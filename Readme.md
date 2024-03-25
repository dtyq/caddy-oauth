# Caddy oidc auth plugin

## Why not authcrunch

I don't want a separate portal for each individual resource.

## Usage

```Caddyfile
oidc [<matcher>] {
    client_id <client_id>
    client_secret <client_secret>
    client_url <client_url>
    [scope <scope>]

    metadata_url <metadata_url>
    # or
    auth_url <auth_url>
    token_url <token_url>
    issuer <issuer>
    [userinfo_url <userinfo_url>]
    [end_session_url <end_session_url>]
}
```

You may want other authz plugins to work with.
