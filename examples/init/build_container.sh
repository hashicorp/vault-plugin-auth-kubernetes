#!/bin/bash

./build.sh
docker build -t hashicorp/vault-example-init:0.0.1 .
rm vault-init
