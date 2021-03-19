# Envoy Example Deployment

This directory contains an example of how to use oidc-filter together with [Google OAuth](https://developers.google.com/identity/protocols/oauth2) in a barebones Envoy setup.

## Requirements

You will need:

- docker
- Google OAuth Credentials (Client ID and Secret), can be created in the [Google Cloud API Console](https://console.cloud.google.com/apis/credentials)

## How to run the example

First, replace the `<YOUR-GOOGLE-OAUTH2-CLIENT-ID>` and `<YOUR-GOOGLE-OAUTH2-CLIENT-SECRET>` placeholders in `envoy.yaml` with your credentials.

You can then deploy the example by running (in this directory):

```bash
./deploy.sh
```

Now, go to http://localhost:10000/ - it should forward you to Google, where you can login with your account. After logging in, it should show "Example Domain" -- congratulations, you just authenticated against Google OAuth. You can use your browser's developer tools to see the `oidcToken` cookie that is sent with the request.
