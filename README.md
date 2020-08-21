# oidc-filter

`oidc-filter` is a WASM plugin for Envoy/Istio that will redirect users to a given authentication URI if they do not present a JWT token.

## Features

- Automatically redirect users with no active session to an OpenID Connect Authorization Server for authorization
- Stores JWT in cookie and transparently writes it to `Authorization` header for every request

## How do I use this thing?

Check out the [example/](https://github.com/dgn/oidc-filter/tree/master/example/) directory.

## Limitations

- oidc-filter doesn't verify the JWTs yet (but Istio does that)
- If the token has expired, AJAX calls with methods other than GET will fail on first attempt (but then succeed afterwards)
- Not using state or nonce yet (so susceptible to replay attacks)

## Development

- Running `make build` in the root of the repository will build `oidc.wasm`
- See the [example/](https://github.com/dgn/oidc-filter/tree/master/example/) directory for how to test your changes

## TODO
- Add option to replay POST requests after redirects (so that redirected AJAX calls don't fail)
  - Not sure if that's good behaviour
