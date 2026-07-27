---
title: "Escher - The Gauntlet"
ctf: "PBCTF 5.0 (Point Blank CTF)"
date: 2026-07-26
category: reverse
difficulty: hard
points: 300
flag_format: "pbctf{...}"
author: "vikas1337"
---

# Escher - The Gauntlet

## summary

custom register-vm ('ESVM') behind a netcat gate. no isa doc at all, u reverse the opcodes from the sample traces, then run the right module pipeline on each nonce the gate throws at u. 4 correct hex replies in a row = flag.

## how i solved it

### 1. unzip the handout

```bash
unzip -o escher-the-gauntlet.zip
ls -R
```

```text
modules/diffuse.bin  modules/sift.bin  modules/whirl.bin
sample1.bin sample2.bin sample3.bin sample4.bin sample5.bin
trace.txt manifest.txt README.md

# README: "the flag isn't in the files. it lives behind a network gate.
# the gate's response routine is a pipeline of VM modules, one feeding the next."
# container: magic 'ESVM' | ver(01) | code_len u16 | data_len u16 | code(3 bytes/instr) | data
```

### 2. reverse the opcodes from trace.txt

```text
# every line shows bytes + regs before/after + F + IN/OUT, so each op is deducible.
# sample5 nails the tricky ones:
  pc= 2  08 00 01 | R[03 05..] F=0 -> F=1        # 08: F = (Ra < Rb)   3<5 -> 1
  pc= 3  09 05 00 | F=1 -> did NOT jump          # 09: branch only when F==0
  pc= 4  01 02 aa | R2=aa                         # 01: LDI Ra, imm
  pc= 7  09 09 00 | F=0 -> jumped to pc9          # 09: branch-flag-clear
# and 04 is the gotcha: Ra = Rb - Ra  (REVERSE subtract), not Ra-Rb.
```

```text
opcodes: 01=LDI 02=LOAD[Rb]++ 03=ADD 04=RSUB(Rb-Ra) 05=XOR 06=OUT 07=JNZ(Ra!=0) 08=CMP(Ra<Rb) 09=BRZ(F==0) 0a=INC 0b=HALT 0c=IN
emulator vs all 5 sample traces: sample1..5 OK, step counts + OUT streams match exactly
```

### 3. which pipeline? manifest is lying

```text
# manifest.txt: "response = sift(whirl(nonce))"
#  ...but also: "swapped a front-end module during testing; not 100% sure this
#  note was updated afterwards." <- thats the tell. diffuse is the real front end.
# so candidates: sift(diffuse) vs sift(whirl). let the live gate decide.
```

```text
diffuse is the real front-end module, whirl is scaffolding
```

### 4. knock on the gate + feed nonces

```bash
nc 104.211.98.123 1339
# ticket: 30.1c486fb95302f3f9
```

```text
ticket accepted. the gate feeds a fresh random nonce each round; answer each with the
pipeline's hex response. reach 4 correct in a row.
first nonce: 694ad6ad2c3117f4388a57ae09c9ebea
```

### 5. run the client, 4/4

```bash
python3 gate.py
```

```text
nonce 694ad6ad2c3117f4388a57ae09c9ebea -> 59d38ca1c7dfb4e0728bbde6b4739be3   correct (1/4)
nonce e052486d384bd08a92601349c051789d -> [sift(diffuse)]                      correct (2/4)
nonce 1507b0976b27be0eeb612d13359b6dca -> da95a9ce93d5aafa429193d3d86198ea   correct (3/4)
nonce 03b36b4d77e637398731866cb6e7aae7 -> [sift(diffuse)]                      correct (4/4)
pbctf{3896cef8007de3f3}
```

## full solve script

```python
#!/usr/bin/env python3
# escher - reconstruct the ESVM register machine, run the module pipeline, answer the gate
from pwn import remote
TICKET = "30.1c486fb95302f3f9"

def parse(blob):
    assert blob[:4]==b'ESVM'
    clen=int.from_bytes(blob[5:7],'little'); dlen=int.from_bytes(blob[7:9],'little')
    code=blob[9:9+3*clen]; data=blob[9+3*clen:9+3*clen+dlen]
    return [tuple(code[3*i:3*i+3]) for i in range(clen)], bytearray(data)

def run(blob, inp=b''):
    code,data=parse(blob); R=[0]*8; F=0; pc=0; ip=0; out=bytearray(); inp=bytes(inp)
    while pc < len(code):
        op,a,b=code[pc]; npc=pc+1
        if   op==0x01: R[a]=b                                          # LDI  Ra,imm
        elif op==0x02: R[a]=data[R[b]%len(data)] if data else 0; R[b]=(R[b]+1)&0xff  # LOAD [Rb]++
        elif op==0x03: R[a]=(R[a]+R[b])&0xff                           # ADD
        elif op==0x04: R[a]=(R[b]-R[a])&0xff                           # RSUB Ra=Rb-Ra
        elif op==0x05: R[a]^=R[b]                                      # XOR
        elif op==0x06: out.append(R[a])                                # OUT
        elif op==0x07: npc=b if R[a]!=0 else npc                       # JNZ  Ra,target
        elif op==0x08: F=1 if R[a]<R[b] else 0                         # CMP  F=(Ra<Rb)
        elif op==0x09: npc=a if F==0 else npc                          # JNF  jump a when F==0
        elif op==0x0a: R[a]=(R[a]+1)&0xff                              # INC
        elif op==0x0b: break                                           # HALT
        elif op==0x0c:                                                 # IN   Ra
            if ip>=len(inp): break
            R[a]=inp[ip]; ip+=1
        else: raise RuntimeError('unknown op %02x'%op)
        pc=npc
    return bytes(out)

# gate response routine = sift(diffuse(nonce)) (pipeline named in manifest.txt)
diffuse=open('modules/diffuse.bin','rb').read()
sift=open('modules/sift.bin','rb').read()
respond=lambda nonce: run(sift, run(diffuse, nonce))

io=remote('104.211.98.123',1339)
io.sendlineafter(b'ticket', TICKET.encode())
for _ in range(4):                          # 4 nonces in a row
    line=io.recvline_contains(b'nonce')
    nonce=bytes.fromhex(line.split()[-1].decode())
    io.sendline(respond(nonce).hex().encode())
print(io.recvall(timeout=5).decode())
# -> the gate swings open. pbctf{3896cef8007de3f3}
```

```text
using pipeline sift(diffuse):
nonce 694ad6ad2c3117f4388a57ae09c9ebea -> 59d38ca1c7dfb4e0728bbde6b4739be3   (1/4)
nonce e052486d384bd08a92601349c051789d -> ...                                 (2/4)
nonce 1507b0976b27be0eeb612d13359b6dca -> da95a9ce93d5aafa429193d3d86198ea   (3/4)
nonce 03b36b4d77e637398731866cb6e7aae7 -> ...                                 (4/4)
4/4 correct on the first attempt, gate never shifted dialect
pbctf{3896cef8007de3f3}
```

## flag

```
pbctf{3896cef8007de3f3}
```
