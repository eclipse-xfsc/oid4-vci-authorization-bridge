#!/bin/sh

export VAULT_ADDR='http://vault:8200'
export VAULT_TOKEN='test'

# Enable the transit secrets engine at path tenant_space/
#vault secrets enable -path=tenant_space transit
echo 'create transit'
curl --header "X-Vault-Token: test" --request POST --data '{"type":"transit"}' http://localhost:8200/v1/sys/mounts/signer


# Enable the transit secrets engine at path tenant_space/
#vault secrets enable -path=tenant_space transit

echo 'check engine'
 # Check if the transit engine was enabled successfully
if curl --header "X-Vault-Token: test" --request GET localhost:8200/v1/sys/mounts | grep -q "signer/"; then
  echo "Transit secrets engine enabled at path tenant_space/"
else
  echo "Failed to enable transit secrets engine at path tenant_space/"
  exit 1
fi

KEY_DATA=$(cat /vault-scripts/signerkey.json)

# Send the payload to Vault using curl
curl --header "X-Vault-Token: test" \
     --request POST \
     --data "$KEY_DATA" \
     http://localhost:8200/v1/signer/restore/signerkey

echo "Vault keys initialized successfully"

curl --header "X-Vault-Token: $VAULT_TOKEN" --request POST --data '{"type":"ecdsa-p256"}' http://localhost:8200/v1/signer/keys/eckey 
