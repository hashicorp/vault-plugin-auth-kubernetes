FROM docker.mirror.hashicorp.services/hashicorp/vault:1.10.0

# Don't use `kubernetes` as plugin name to ensure we don't silently fall back to
# the built-in kubernetes auth plugin if something goes wrong.
COPY --chown=vault:vault vault-plugin-auth-kubernetes /vault/plugin_directory/kubernetes-dev