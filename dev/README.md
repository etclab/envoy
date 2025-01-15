### Steps to build+test envoy with sandbox example
- Custom cert validator files: `source/extensions/transport_sockets/tls/cert_validator/rbe/rbe_validator.cc` and `source/extensions/transport_sockets/tls/cert_validator/rbe/rbe_validator.h`
    - These files mirror exactly how the [SPIFFE Certificate Validator](https://www.envoyproxy.io/docs/envoy/latest/api-v3/extensions/transport_sockets/tls/v3/tls_spiffe_validator_config.proto) works; right now it adds a custom field to test if the config is working
- After making a change, envoy can be built using `./dev/envoy-dev.sh`. This creates the new binary and creates a docker with the new binary. The binary is named `atosh502/envoy-debug-dev:latest` so that it doesn't pull the image from docker.io and uses the local image instead.
- Once you have the required docker image built, run the [`double-proxy`](https://www.envoyproxy.io/docs/envoy/latest/start/sandboxes/double-proxy.html) repo to test the changes. In order to get the `double-proxy` sandbox to use the docker image you just built in previous step, modify the [`FROM ${ENVOY_IMAGE}:${ENVOY_VARIANT} AS envoy-base`](https://github.com/envoyproxy/examples/blob/a2ad2df50ab23db97fe1046caef3b52b6b0d6a2e/shared/envoy/Dockerfile#L5) line to `FROM atosh502/envoy-debug-dev AS envoy-base` (or the name of the image you created in the previous step)
- Commands for builinding and running `double-proxy` is [here](https://www.envoyproxy.io/docs/envoy/latest/start/sandboxes/double-proxy.html#step-5-start-all-of-our-containers)

### Kube C client
- [list_pod_cpp example](https://github.com/etclab/kube-c-client/tree/dev/examples/list_pod_cpp)

### Sample certificate
- Sampel certificate is in file: `dev/cert.pem`
- Inspect the certificate file with: `openssl x509 -in dev/cert.pem -text -noout`

### Certificate extension
- Admin token is read from [this extension](https://github.com/etclab/istio/blob/68054e7e3f13290282b251ba50e4195b46e470ca/security/pkg/nodeagent/cache/secretcache.go#L459-L462). See [this](https://github.com/etclab/mazu/blob/c25b92c5016021d694d68e9628b9ef4f43194a71/sprint4/go-cert/read-cert.go#L38) for how to read custom extensions in golang.
- The token is checked using the kube c client against the kube api server