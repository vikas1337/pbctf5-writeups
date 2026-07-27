---
title: "Locked Floor"
ctf: "PBCTF 5.0 (Point Blank CTF)"
date: 2026-07-26
category: pwn
difficulty: medium
points: 200
flag_format: "pbctf{...}"
author: "vikas1337"
---

# Locked Floor

## summary

a virtualbox .ova appliance. no need to actually boot it or crack any login, the .ova is a tarball, so unpack the vmdk and read the flag right off the ext4 filesystem with debugfs. no mount, no root.

## how i solved it

### 1. the .ova is just a tar

```bash
file /mnt/c/Users/USER/Downloads/locked-floor.ova
tar tvf locked-floor.ova
```

```text
locked-floor.ova: POSIX tar archive
-rw-r----- ... locked-floor.ovf
-rw-rw---- ... pbctf-locked-floor-disk001.vmdk
```

### 2. unpack + convert the disk

```bash
tar xf locked-floor.ova
qemu-img convert -O raw pbctf-locked-floor-disk001.vmdk disk.raw
fdisk -l disk.raw | grep -i linux
```

```text
disk.raw1  2048  3145727  ...  Linux filesystem
# single ext4 partition starting at sector 2048
```

### 3. carve the partition, browse it with debugfs (no mount/root)

```bash
dd if=disk.raw of=part.img bs=512 skip=2048 status=none
debugfs -R 'ls -l /' part.img | head
```

```text
debugfs 1.47.2 (1-Jan-2025)
     2  40755  0  0  4096 .   ..
  8195  40755  0  0  4096 home
  8200  40700  0  0  4096 root
  16385 40755  0  0  4096 etc
```

### 4. flag lives in /home/root/flag

```bash
debugfs -R 'ls -l /home' part.img
debugfs -R 'cat /home/root/flag' part.img
```

```text
pbctf{gtfobins_says_hi_install}
```

## full solve script

```python
#!/usr/bin/env bash
# pbctf "Locked Floor" - no need to boot the VM or get root.
# the .ova is just a tar; pull the vmdk, convert to raw, carve the ext4
# partition, and read the flag straight out with debugfs (no mount, no sudo).
set -e
tar xf locked-floor.ova                 # -> pbctf-locked-floor-disk001.vmdk + .ovf
qemu-img convert -O raw pbctf-locked-floor-disk001.vmdk disk.raw

# partition starts at LBA 2048 (1 MiB) - carve it out
dd if=disk.raw of=part.img bs=512 skip=2048 status=none

debugfs -R "ls -l /home/root" part.img          # find the flag
debugfs -R "cat /home/root/flag" part.img       # read it, no root needed
```

```text
  8200   40700 (2)  0  0  4096 21-Jul-2026 15:27 .
  ...    100644 (1)  0  0    32 21-Jul-2026 15:27 flag
debugfs 1.47.2 (1-Jan-2025)
pbctf{gtfobins_says_hi_install}
```

## flag

```
pbctf{gtfobins_says_hi_install}
```
