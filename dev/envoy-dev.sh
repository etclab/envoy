#!/bin/bash

./ci/run_envoy_docker.sh './ci/do_ci.sh debug.server_only'

ENVOY_DOCKER_IN_DOCKER=1 ./ci/run_envoy_docker.sh './ci/do_ci.sh docker'