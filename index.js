/**
 * Where your business logic should go
 * @param {*} claims
 * @returns boolean
 */
async function externalEvaluation(claims) {
  const currentHour = new Date(new Date().toLocaleString('en-US', {
    timeZone: 'America/New_York',
  })).getHours()

  return currentHour >= 8 && currentHour <= 16
}

// EVERYTHING PAST THIS SHOULD NOT NEED TO CHANGE UNLESS YOU WANT TO
// ==================================================================

addEventListener('fetch', event => {
  if (event.request.url.endsWith('keys')) {
    event.respondWith(handleKeysRequest(event))
  } else {
    event.respondWith(handleExternalEvaluationRequest(event))
  }
})

// the key in KV that holds the generated signing keys
const KV_SIGNING_KEY = 'external_auth_keys'

/*
 * Helpers for converting to and from URL safe Base64 strings. Needed for JWT encoding.
 */
const base64url = {
  stringify: function(a) {
    let base64string = btoa(String.fromCharCode.apply(0, a))
    return base64string
      .replace(/=/g, '')
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
  },
  parse: function(s) {
    s = s
      .replace(/-/g, '+')
      .replace(/_/g, '/')
      .replace(/\s/g, '')
    return new Uint8Array(
      Array.prototype.map.call(atob(s), function(c) {
        return c.charCodeAt(0)
      }),
    )
  },
}

/**
 * Generate a key id for the key set
 * @param {*} publicKey
 * @returns
 */
async function generateKID(publicKey) {
  const msgUint8 = new TextEncoder().encode(publicKey)
  const hashBuffer = await crypto.subtle.digest('SHA-1', msgUint8)
  const hashArray = Array.from(new Uint8Array(hashBuffer))
  const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('')
  return hashHex.substring(0, 64)
}

/*
 * Helper to get from an ascii string to a literal byte array.
 * Necessary to get ascii string prepped for base 64 encoding
 */
function asciiToUint8Array(str) {
  let chars = []
  for (let i = 0; i < str.length; ++i) {
    chars.push(str.charCodeAt(i))
  }
  return new Uint8Array(chars)
}

/**
 * Helper to get the Access public keys from the certs endpoint
 * @param {*} kid - The key id that signed the token
 * @returns
 */
async function fetchAccessPublicKey(kid) {
  const resp = await fetch(`https://${TEAM_DOMAIN}/cdn-cgi/access/certs`)
  const keys = await resp.json()
  const jwk = keys.keys.filter(key => key.kid == kid)[0]
  const key = await crypto.subtle.importKey(
    'jwk',
    jwk,
    {
      name: 'RSASSA-PKCS1-v1_5',
      hash: 'SHA-256',
    },
    false,
    ['verify'],
  )
  return key
}

/**
 * Generate a key pair and stores them into Workers KV for future use
 * @returns
 */
async function generateKeys() {
  console.log('generating a new signing key pair')
  try {
    const keypair = await crypto.subtle.generateKey(
      {
        name: 'RSASSA-PKCS1-v1_5',
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: 'SHA-256',
      },
      true,
      ['sign', 'verify'],
    )
    const publicKey = await crypto.subtle.exportKey('jwk', keypair.publicKey)
    const privateKey = await crypto.subtle.exportKey('jwk', keypair.privateKey)
    const kid = await generateKID(JSON.stringify(publicKey))
    await KV.put(
      KV_SIGNING_KEY,
      JSON.stringify({ public: publicKey, private: privateKey, kid: kid }),
    )
    return { keypair, publicKey, privateKey, kid }
  } catch (e) {
    console.log('failed to generate keyset', e)
    throw 'failed to generate keyset'
  }
}

/**
 * Load the signing key from KV
 * @returns
 */
async function loadSigningKey() {
  const keyset = await KV.get(KV_SIGNING_KEY, 'json')
  if (keyset) {
    const signingKey = await crypto.subtle.importKey(
      'jwk',
      keyset.private,
      {
        name: 'RSASSA-PKCS1-v1_5',
        hash: 'SHA-256',
      },
      false,
      ['sign'],
    )
    return { kid: keyset.kid, privateKey: signingKey }
  }

  console.log('Key set has not been generated. Call /keys first.')
  throw new Error('cannot find signing key')
}

/**
 * Get the public key in JWK format
 * @returns
 */
async function loadPublicKey() {
  // if the JWK values are already in KV then just return that
  const key = await KV.get(KV_SIGNING_KEY, 'json')
  if (key) {
    return { kid: key.kid, ...key.public }
  }

  // otherwise generate keys and store the Keyset in KV
  const { kid, publicKey } = await generateKeys()
  return { kid, ...publicKey }
}

/**
 * Turn a payload into a JWT
 * @param {*} payload
 * @returns
 */
async function signJWT(payload) {
  const { kid, privateKey } = await loadSigningKey()
  const header = {
    alg: 'RS256',
    kid: kid,
  }
  const encHeader = base64url.stringify(
    asciiToUint8Array(JSON.stringify(header)),
  )
  const encPayload = base64url.stringify(
    asciiToUint8Array(JSON.stringify(payload)),
  )
  const encoded = `${encHeader}.${encPayload}`

  const sig = new Uint8Array(
    await crypto.subtle.sign(
      'RSASSA-PKCS1-v1_5',
      privateKey,
      asciiToUint8Array(encoded),
    ),
  )
  return `${encoded}.${base64url.stringify(sig)}`
}

/**
 * Parse a JWT into its respective pieces. Does not do any validation other than form checking.
 * @param {*} token - jwt string
 * @returns
 */
function parseJWT(token) {
  const tokenParts = token.split('.')

  if (tokenParts.length !== 3) {
    throw new Error('token must have 3 parts')
  }

  let enc = new TextDecoder('utf-8')
  return {
    to_be_validated: `${tokenParts[0]}.${tokenParts[1]}`,
    header: JSON.parse(enc.decode(base64url.parse(tokenParts[0]))),
    payload: JSON.parse(enc.decode(base64url.parse(tokenParts[1]))),
    signature: tokenParts[2],
  }
}

/**
 * Validates the provided token using the Access public key set
 *
 * @param token - the token to be validated
 * @returns {object} Returns the payload if valid, or throws an error if not
 */
async function verifyToken(token) {
  if (DEBUG) {
    console.log('incoming JWT', token)
  }
  const jwt = parseJWT(token)
  const key = await fetchAccessPublicKey(jwt.header.kid)

  const verified = await crypto.subtle.verify(
    'RSASSA-PKCS1-v1_5',
    key,
    base64url.parse(jwt.signature),
    asciiToUint8Array(jwt.to_be_validated),
  )

  if (!verified) {
    throw new Error('failed to verify token')
  }

  const claims = jwt.payload
  let now = Math.floor(Date.now() / 1000)
  // Validate expiration
  if (claims.exp < now) {
    throw new Error('expired token')
  }

  return claims
}

/**
 * Top level handler for public jwks endpoint
 * @param {*} event
 * @returns
 */
async function handleKeysRequest(event) {
  const keys = await loadPublicKey()
  return new Response(JSON.stringify({ keys: [keys] }), {
    status: 200,
    headers: { 'content-type': 'application/json' },
  })
}

/**
 * Top level handler for external evaluation requests
 * @param {*} event
 * @returns
 */
async function handleExternalEvaluationRequest(event) {
  const now = Math.round(Date.now() / 1000)
  let result = { success: false, iat: now, exp: now + 60 }
  try {
    const body = await event.request.json()
    const claims = await verifyToken(body.token)

    if (claims) {
      result.nonce = claims.nonce
      if (await externalEvaluation(claims)) {
        result.success = true
      }
    }

    const jwt = await signJWT(result)
    if (DEBUG) {
      console.log('outgoing JWT', jwt)
    }
    return new Response(JSON.stringify({ token: jwt }), {
      headers: { 'content-type': 'application/json' },
    })
  } catch (e) {
    console.log(`error:`, e.toString())
    return new Response(
      JSON.stringify({ success: false, error: e.toString(), stack: e.stack }),
      {
        status: 403,
        headers: { 'content-type': 'application/json' },
      },
    )
  }
}
