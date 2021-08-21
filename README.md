# oidc-filter

`oidc-filter` is a Wasm plugin for Envoy/Istio that will redirect users to a given authentication URI if they do not present a JWT token.

## Features

- Automatically redirect users with no active session to an OpenID Connect Authorization Server for authorization
- Stores JWT in cookie and transparently writes it to `Authorization` header for every request

## How do I use this thing?

Check out the [examples/](https://github.com/dgn/oidc-filter/tree/master/examples/) directory.

## Limitations

- oidc-filter doesn't verify the JWTs yet (but Istio does that)
- If the token has expired, AJAX calls with methods other than GET will fail on first attempt (but then succeed afterwards)
- Not using state or nonce yet (so susceptible to replay attacks)

## Development

- Running `make` in the root of the repository will build `plugin.wasm`
- Running `make image` will build a container image compatible with OpenShift Service Mesh 2.0+ and Istio 1.12+
- See the [examples/](https://github.com/dgn/oidc-filter/tree/master/examples/) directory for how to test your changes

## TODO
- Add option to replay POST requests after redirects (so that redirected AJAX calls don't fail)
  - Not sure if that's good behaviour
