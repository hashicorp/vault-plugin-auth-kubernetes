#!/bin/sh

SERVICE_ACCOUNT_TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)

VAULT_TOKEN=$(curl -sb \
    --request POST \
    --data "{\"role\": \"test\", \"jwt\": \"${SERVICE_ACCOUNT_TOKEN}\"}" \
    "${VAULT_ADDR}/v1/auth/kube/login" | jq -r '.auth .client_token')

/bin/consul-template \
    --vault-token=$VAULT_TOKEN \
    --vault-addr=$VAULT_ADDR \
    --vault-renew-token=true \
    -template "/config.ctmpl:/etc/example-app/config.json"
