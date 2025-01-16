#!/bin/bash

# set -Eeuo pipefail
# set -x

./ci/run_envoy_docker.sh './ci/do_ci.sh release.server_only'

ENVOY_DOCKER_IN_DOCKER=1 ./ci/run_envoy_docker.sh './ci/do_ci.sh docker'