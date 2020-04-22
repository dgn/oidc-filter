# Example Deployment

This directory contains a full, working example of how to use oidc-filter together with [Istio](https://istio.io) and [Keycloak](https://keycloak.org).

You can deploy the example by running (in this directory):

```bash
./deploy.sh
```

Then, when everything is up, you need to setup port-forwards for both the ingress-gateway and keycloak:

```bash
kubectl port-forward -n istio-system svc/istio-ingressgateway 8080:80 &
kubectl port-forward svc/keycloak 9090:8080 &
```

Now, go to http://localhost:8080 - it should forward you to keycloak (listening on http://localhost:9090), where you can login using username `admin` and password `admin`. Keycloak will then forward you back to to httpbin, which should show you the headers of your request - check out the cookie `oidcToken`- this is the token that oidc-filter will write into the `Authorization` header.

