#!/usr/bin/env bash

# fail fast settings from https://dougrichardson.org/2018/08/03/fail-fast-bash-scripting.html
set -euov pipefail

docker run --rm -d -p $2:$3 --name $1 eoepca/$1:$4 # Runs container from EOEPCA repository

sleep 15 # wait until the container is running

# INSERT BELOW THE ACCEPTANCE TEST:
#curl -s http://localhost:$2/search # trivial smoke test
