---
title: How to Write Shellcode
tags:
    - [Linux]
    - [Userland]
lang: en
permalink: /en/linux-userland/shellcode/how2write.html
pagination: true
bk: ../introduction/environment.html
fd: restricted.html
---
Shellcode is no longer the universal answer it once was, but it still matters whenever executable attacker-controlled memory exists.

## Did NX kill shellcode?
NX made classic injected code execution harder, but shellcode still appears in JIT environments, sandbox escapes, staged payloads, and restricted challenge settings.

### Shellcode in sandboxes
Sometimes code reuse is not enough and a small custom payload is still the easiest route.

### JIT and shellcode
JIT engines often create executable pages, which can reopen the door to shellcode-style attacks.

## Writing shellcode
The basics are:
- know your syscall ABI
- avoid unnecessary bytes
- keep register state under control
- decide whether the payload should be staged or self-contained
