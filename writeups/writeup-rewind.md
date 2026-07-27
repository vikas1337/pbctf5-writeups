---
title: "Rewind"
ctf: "PBCTF 5.0 (Point Blank CTF)"
date: 2026-07-26
category: reverse
difficulty: easy
points: 200
flag_format: "pbctf{...}"
author: "vikas1337"
---

# Rewind

## summary

git repo where main looks clean but the docs name-drop a removed recovery tool. dig through --full-history and you find three deleted stripped ELFs; two are decoys, the real one (checkpoint-sync) only shows up on a merged-away side branch. reverse its token check to get TURNBACK_731, run it to decrypt data/checkpoint.rwd into a tar of C source, then replay generation 731 to xor the flag fragments back together.

## how i solved it

### 1. clone + notice the hint

```bash
git clone https://github.com/saniyafatima07/rewind && cd rewind
cat docs/migration-v1.md   # name-drops a removed tools/legacy/checkpoint-recover
git log --all --oneline
```

```text
main tree is just python metadata tooling. docs mention a 'checkpoint-recover' that isn't there anymore -> git history.
```

### 2. recover the deleted binaries

```bash
# three deleted stripped ELFs across history
git log --all --full-history --diff-filter=D --name-only | grep tools/legacy
git rev-list --all --objects | grep tools/legacy
git cat-file -p 7d6a79f... > sync   # the real one
```

```text
189622e tools/legacy/checkpoint-audit  (decoy, .rwa magic)
bc90412 tools/legacy/checkpoint-index  (decoy, .rwx magic)
7d6a79f tools/legacy/checkpoint-sync   (real, only via --full-history, died on non-first parent of merge 69c77ef)
```

### 3. reverse the token check

```python
# sync <checkpoint.rwd> <token> compares 12-byte transform vs 12 bytes @ .rodata:0x25a0
# expect[i] == rol8( ((token[i]^0x5A) + 7*i)&0xff, 3 )
exp = bytes.fromhex('70b0b049a1f11a12e9657dc5')
ror = lambda v,n: ((v>>n)|(v<<(8-n)))&0xff
tok = bytes(((ror(e,3) - 7*i)&0xff)^0x5A for i,e in enumerate(exp))
print(tok.decode())
```

```text
TURNBACK_731   (the 731 matches 'generation' in every sidecar fixture)
```

### 4. decrypt the checkpoint

```bash
chmod +x sync
./sync data/checkpoint.rwd TURNBACK_731
file restored.tar.gz && tar tzf restored.tar.gz
```

```text
restored.tar.gz: gzip compressed data
rewind-core/   (a C replay engine: restore.c, timeline.c, ...)
```

### 5. replay generation 731

```text
flag is split into 4 xor'd fragments across restore.c (slots 1,3) and timeline.c (slots 0,2), keyed by generation: key(g,slot,i)=((g*(slot+3)+i*11+slot*17)^0xA5)&0xff. rewind_timeline_seed(g)==0x3B50641B gates it, brute confirms g=731 is unique. build and run.
```

```text
$ ./rewind-core --replay 731
PBCTF{d3l3t3d_d03s_n0t_m34n_g0n3}
```

## full solve script

```python
#!/usr/bin/env bash
set -e
git clone https://github.com/saniyafatima07/rewind rewind && cd rewind

# 1. the real recovery tool is a deleted blob only reachable via --full-history
SYNC=$(git rev-list --all --objects | awk '/tools\/legacy\/checkpoint-sync/{print $1}' | head -1)
git cat-file -p "$SYNC" > /tmp/sync && chmod +x /tmp/sync

# 2. recover the token from the 12 rodata bytes @0x25a0
TOKEN=$(python3 - <<'PY'
exp = bytes.fromhex('70b0b049a1f11a12e9657dc5')
ror = lambda v,n: ((v>>n)|(v<<(8-n)))&0xff
print(bytes(((ror(e,3)-7*i)&0xff)^0x5A for i,e in enumerate(exp)).decode())
PY
)
echo "token = $TOKEN"

# 3. decrypt the checkpoint into the C replay engine
/tmp/sync data/checkpoint.rwd "$TOKEN"
tar xzf restored.tar.gz -C /tmp

# 4. build + replay generation 731
cc -O2 -o /tmp/rewind-bin /tmp/rewind-core/*.c
/tmp/rewind-bin --replay 731
```

```text
token = TURNBACK_731
wrote restored.tar.gz (payload CRC32 ok)
PBCTF{d3l3t3d_d03s_n0t_m34n_g0n3}
```

## flag

```
PBCTF{d3l3t3d_d03s_n0t_m34n_g0n3}
```
