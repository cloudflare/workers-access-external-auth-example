/**
 * Will reject and revoke any existing tokens for users who login outside of 8-5 UTC
 *
 * This requires additional configuration.
 *  - Add ACCOUNT_ID as a variable in your wrangler.toml file. This should match the account where the user needs to be revoked.
 *  - Add a Cloudflare API TOKEN
 *      - Go to the Cloudflare Dashboard and create a new API token. Give it a new Account permission. `Access: Organizations, Identity Providers, and Groups` and the `Revoke` for the needed Account.
 *      - Add your new API token as a secret using `wrangler secret put API_TOKEN`.
 * @param {*} claims
 * @returns boolean
 */
async function externalEvaluation(claims) {
  const now = new Date()
  const currentUTCHour = now.getHours()

  // Only allow someone to successfully login between 8-5 UTC
  const allowed = currentUTCHour >= 8 && currentUTCHour <= 17

  if (!allowed) {
    const body = {
      // The email to be revoked. Take it from the identity object on the claims
      email: claims.identity.email,
    }
    // Send an API request to Cloudflare Access to revoke all tokens for this user
    const resp = await fetch(
      `https://api.cloudflare.com/client/v4/accounts/${ACCOUNT_ID}/access/organizations/revoke_user`,
      {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${API_TOKEN}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(body),
      },
    )
    // Debug log so you can tail the worker and see the result of the request
    console.log(`Revoking ${claims.identity.email}: ${resp.status}`)
  }
  return allowed
}
