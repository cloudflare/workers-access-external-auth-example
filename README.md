# Access External Auth Rule Example Worker

This is a worker that allows you to quickly setup an external evalutation rule in Cloudflare Access. Additional information about this feature can be found in the [Cloudflare Developer Docs](https://developers.cloudflare.com/cloudflare-one/policies/access/external-evaluation/).

## Setup

1. Create a new KV Namespace or use an existing one. This worker will automatically generate a signing key pair the first time it is called and it will store those keys in Workers KV.
1. Update `wrangler.toml` with the values for your account. Make sure to use `KV` as the binding name for your KV namespace.
1. Update the `externalEvaluation` function in `index.js` with your business logic.
1. Run `wrangler publish`
1. In the [zero trust dashboard](https://dash.teams.cloudflare.com) update your Access policy and add an `External Evaluation rule`
1. If your worker was deployed on `example.com/*` in workers then fill in the `Evaluate URL` box with `https://example.com` and fill in the `Keys URL` with `https://example.com/keys`

## Debugging

Run `wrangler tail -f pretty` to get basic debug logs for your worker. If you set `DEBUG=true` in wrangler.toml it will also output the incoming and outgoing JWTs. You can plug these into JWT.io to see what Access is sending you and what you are returning to Access.
