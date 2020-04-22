# oidc-filter

`oidc-filter` is a WASM plugin for Envoy/Istio that will redirect users to a given authentication URI if they do not present a JWT token.

## Features

- Automatically redirect users with no active session to an OpenID Connect Authorization Server for authorization
- Stores JWT in cookie and transparently writes it to `Authorization` header for every request

## How do I use this thing?

Check out the [example/](https://github.com/dgn/oidc-filter/tree/master/example/) directory.

## Limitations

- Currently only supports the [Implicit Flow](https://openid.net/specs/openid-connect-implicit-1_0.html#ImplicitFlow)
- tinygo is extremely limited in what it can successfully compile to wasm; I wasn't able to use any json library for example
- oidc-filter doesn't verify the JWTs yet (but Istio does that)
- the cookie has no expiry date and will be refreshed when upstream returns 401 or 403 despite sending token

## Development

- Running `make build` in the root of the repository will build `oidc.wasm`
- See the [example/](https://github.com/dgn/oidc-filter/tree/master/example/] directory for how to test your changes

