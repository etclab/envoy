#!/bin/bash

# set -Eeuo pipefail
# set -x

./ci/run_envoy_docker.sh './ci/do_ci.sh release.server_only'

ENVOY_DOCKER_IN_DOCKER=1 ENVOY_SHARED_TMP_DIR=/tmp/bazel-shared-atp ./ci/run_envoy_docker.sh './ci/do_ci.sh docker'