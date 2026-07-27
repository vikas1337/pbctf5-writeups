---
title: "The Copyist's Secret"
ctf: "PBCTF 5.0 (Point Blank CTF)"
date: 2026-07-26
category: forensics
difficulty: hard
points: 500
flag_format: "pbctf{...}"
author: "vikas1337"
---

# The Copyist's Secret

## summary

13MB, 15-track, ~1.5M-note MIDI. the payload is in the sustained notes - long held notes on the VIOLA track (track 10, program 41). key is D natural minor: each held note maps to a scale-step index, pairs of steps are base-12 digits -> ascii. cello track is a decoy phrase.

## how i solved it

### 1. load the giant midi

```python
import mido
mid=mido.MidiFile('copyist.mid')
print(len(mid.tracks),'tracks, division', mid.ticks_per_beat)
for i,t in enumerate(mid.tracks):
    print(i, t.name, sum(1 for m in t if m.type=='note_on'))
```

```text
15 tracks, ticks_per_beat 480
10 Viola  ~ big note count (program 41)
11 Cello  (decoy)
# ~1.5M note_on events total -> the melody is noise, look at note LENGTHS
```

### 2. grab the held notes

```text
ticks_per_beat is 480 (a beat = 480 ticks); most notes are short passing notes.
filter for the sustained ones: duration == 960 ticks (a clean HALF note = 2 beats). held notes recur on a wide ~23040-tick grid.
do it on the viola track (track 10).
```

```text
held viola notes give a clean sequence of pitches, all inside a D natural-minor scale.
```

### 3. D-minor scale-step -> base-12 digits

```text
map each held pitch to its scale-step index within D natural minor (7 steps per octave, keep climbing octaves).
take steps in pairs (d1,d2) -> base-12 value d1*12+d2 -> ascii char.
```

```text
viola decodes to: tw3lv3_t0n3s_b3n34th_th3_l3v14th4n
cello decodes to the decoy: tw3lv3_t0n3s_ab0v3
```

### 4. submit phrase to the judge

```bash
nc 104.211.98.123 1340   # ticket 30.01b4cbc93e533efc
# send: tw3lv3_t0n3s_b3n34th_th3_l3v14th4n
```

```text
correct -> pbctf{f11b436873896eb2}
```

## full solve script

```python
import mido
mid=mido.MidiFile('copyist.mid')
viola=mid.tracks[10]  # program 41, viola

# collect (pitch, duration) with absolute ticks
held=[]; on={}; t=0
for m in viola:
    t+=m.time
    if m.type=='note_on' and m.velocity>0:
        on[m.note]=t
    elif m.type=='note_off' or (m.type=='note_on' and m.velocity==0):
        if m.note in on:
            dur=t-on.pop(m.note)
            if dur==960:            # the sustained notes
                held.append((t,m.note))
held.sort()
pitches=[p for _,p in held]

# D natural minor scale-step index: D E F G A Bb C  (semitone offsets from D)
SCALE=[0,2,3,5,7,8,10]
def step(pitch):
    rel=(pitch-2)                 # 2 == D (mod 12 root); D2=38 etc
    octv, semi = divmod(rel,12)
    return octv*7 + SCALE.index(semi)

steps=[step(p) for p in pitches]
base=min(steps)
steps=[s-base for s in steps]
chars=[]
for i in range(0,len(steps)-1,2):
    v=steps[i]*12+steps[i+1]
    chars.append(chr(v))
phrase=''.join(chars)
print('phrase:',phrase)
# -> submit to nc 104.211.98.123 1340 (ticket 30.01b4cbc93e533efc)

```

```text
15 tracks, ticks_per_beat 480
held viola notes: 68
phrase: tw3lv3_t0n3s_b3n34th_th3_l3v14th4n
[cello track decoy: tw3lv3_t0n3s_ab0v3]
# submitted to nc 104.211.98.123 1340
pbctf{f11b436873896eb2}
```

## flag

```
pbctf{f11b436873896eb2}
```
