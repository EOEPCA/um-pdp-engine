#!/usr/bin/env bash

# fail fast settings from https://dougrichardson.org/2018/08/03/fail-fast-bash-scripting.html
set -euov pipefail

docker build -t eoepca/$1 .
docker tag eoepca/$1 eoepca/$1:$2

echo "$DOCKER_PASSWORD" | docker login -u "$DOCKER_USERNAME" --password-stdin

docker push eoepca/$1:$2   # defaults to docker hub EOEPCA repo
