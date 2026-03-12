---
title: Restricted Shellcode
tags:
    - [Linux]
    - [Userland]
lang: en
permalink: /en/linux-userland/shellcode/restricted.html
pagination: true
bk: how2write.html
fd: seccomp.html
---
Real shellcode often comes with constraints. The payload may have to fit a tiny size, avoid bad bytes, or run in a partially unknown state.

## Length-restricted shellcode
### Choosing short instructions
Instruction selection matters. Small encodings and register reuse become critical.

### Building a stager
When the payload is too large, a short first-stage loader can fetch or decode a larger second stage.

## Character-restricted shellcode
### NUL and newline restrictions
Many input channels forbid bytes that terminate strings or break parsing.

### ASCII / UTF-8 restrictions
Sometimes the payload must remain printable or valid in a higher-level text encoding.

### Floating-point / IEEE 754 restrictions
Weird data channels can impose even stranger byte constraints.

## State-restricted shellcode
### Unknown address
If the shellcode location is unknown, self-discovery techniques such as `call`/`pop` or egg hunting become important.

### Non-writable shellcode region
If the region is execute-only or not writable, self-modifying or staged strategies change accordingly.
