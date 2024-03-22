# caddy oidc auth

## why not authcrunch

I donot want a portal for all resources

## usage

```Caddyfile
oidc [<matcher>] {
    client_id <client_id>
    client_secret <client_secret>
    redirect_url <redirect_url>
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
