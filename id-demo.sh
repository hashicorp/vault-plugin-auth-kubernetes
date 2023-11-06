vd-ngrok
VAULT_API_ADDR="$(ngrok-url)" vd -log-level=debug
export VAULT_ADDR="$(ngrok-url)"
vault write identity/oidc/role/default key=default
# Update the config.yaml with the latest ngrok URL
kind delete cluster && kind create cluster --config=config.yaml
kubectl config view --flatten -o json | jq -r '.clusters[0].cluster["certificate-authority-data"]' | base64 -d > local/k8s-ca.pem
kubectl create clusterrolebinding vault-k8s-auth --user vault-oidc:plugin::kubernetes --clusterrole system:auth-delegator

vault auth enable kubernetes
vault write auth/kubernetes/config \
    kubernetes_host="$(kubectl config view --flatten -o json | jq -r '.clusters[0].cluster.server')" \
    kubernetes_ca_cert="$(kubectl config view --flatten -o json | jq -r '.clusters[0].cluster["certificate-authority-data"]' | base64 -d)" \
    identity_token_audience="https://kubernetes.default.svc.cluster.local"
vault write auth/kubernetes/role/default \
    bound_service_account_names=default \
    bound_service_account_namespaces=default
vault write auth/kubernetes/login \
    role=default \
    jwt="$(kubectl create token default)"

# curl \
#     -H "Accept: application/json" \
#     -H "Content-Type: application/json" \
#     -H "Authorization: Bearer $(cat local/vault-jwt)" \
#     --cacert local/k8s-ca.pem \
#   "$(kubectl config view --flatten -o json | jq -r '.clusters[0].cluster.server')/api/v1/namespaces/default/pods"
