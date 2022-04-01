# kind cluster name
KIND_CLUSTER_NAME?=vault-plugin-auth-kubernetes

# kind k8s version
KIND_K8S_VERSION?=v1.23.4

.PHONY: default
default: dev

.PHONY: dev
dev:
	CGO_ENABLED=0 go build -o bin/vault-plugin-auth-kubernetes cmd/vault-plugin-auth-kubernetes/main.go

.PHONY: test
test: fmtcheck
	CGO_ENABLED=0 go test ./... $(TESTARGS) -timeout=20m

.PHONY: integration-test
integration-test:
	INTEGRATION_TESTS=true CGO_ENABLED=0 go test github.com/hashicorp/vault-plugin-auth-kubernetes/integrationtest/... $(TESTARGS) -timeout=20m

.PHONY: fmtcheck
fmtcheck:
	@sh -c "'$(CURDIR)/scripts/gofmtcheck.sh'"

.PHONY: fmt
fmt:
	gofmt -w .

.PHONY: setup-kind
# create a kind cluster for running the acceptance tests locally
setup-kind:
	kind get clusters | grep --silent "^${KIND_CLUSTER_NAME}$$" || \
	kind create cluster \
		--image kindest/node:${KIND_K8S_VERSION} \
		--name ${KIND_CLUSTER_NAME}  \
		--config $(CURDIR)/integrationtest/kind/config.yaml
	kubectl config use-context kind-${KIND_CLUSTER_NAME}

.PHONY: delete-kind
# delete the kind cluster
delete-kind:
	kind delete cluster --name ${KIND_CLUSTER_NAME} || true

.PHONY: vault-image
vault-image:
	GOOS=linux GOARCH=amd64 make dev
	docker build -f integrationtest/vault/Dockerfile bin/ --tag=hashicorp/vault:dev

# Create Vault inside the cluster with a locally-built version of kubernetes auth.
.PHONY: setup-integration-test
setup-integration-test: teardown-integration-test vault-image
	kind --name ${KIND_CLUSTER_NAME} load docker-image hashicorp/vault:dev
	kubectl create namespace test
	kubectl apply --namespace=test -f integrationtest/vault/vault.yaml
	kubectl wait --namespace=test --for=condition=Ready --timeout=5m pod -l app.kubernetes.io/name=vault

.PHONY: teardown-integration-test
teardown-integration-test:
	kubectl delete --ignore-not-found --namespace=test  -f integrationtest/vault/vault.yaml
	kubectl delete --ignore-not-found namespace test