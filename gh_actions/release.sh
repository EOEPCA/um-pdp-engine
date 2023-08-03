#!/usr/bin/env bash

# fail fast settings from https://dougrichardson.org/2018/08/03/fail-fast-bash-scripting.html
set -euov pipefail

echo "$DOCKER_PASSWORD" | docker login -u "$DOCKER_USERNAME" --password-stdin

docker push eoepca/$1:$2

# Tag and push as `latest`
docker tag eoepca/$1:$2 eoepca/$1:latest
docker push eoepca/$1:latest
