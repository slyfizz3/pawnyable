---
title: Security Mechanisms
tags:
    - [Linux]
    - [Userland]
lang: en
permalink: /en/linux-userland/introduction/security.html
pagination: true
fd: primitive.html
---
This chapter summarizes the main mitigations that shape userland exploitation.

## OS- and CPU-level mitigations
### ASLR
ASLR randomizes important regions such as libraries, the stack, and heap mappings, making direct jumps and hardcoded addresses unreliable.

### Non-randomized regions and PIE
Not everything is randomized equally. Whether the main binary is PIE or not changes how much of the process layout stays fixed.

### NX
NX marks data pages as non-executable, which is why modern exploitation relies heavily on code reuse or JIT-generated code.

### CET
CET adds hardware-backed control-flow integrity features such as shadow stacks and indirect branch tracking.

## Compiler- and program-level mitigations
### Stack Canary (SSP)
Canaries detect simple stack-smashing attempts before the function returns.

### `FORTIFY_SOURCE`
This adds extra bounds checks around common library functions when the compiler can infer object sizes.

### CFI
Control-flow integrity restricts indirect calls or jumps to expected targets.

## Library hardening
Shared libraries may add their own protections or interact with OS mitigations in ways that matter during exploitation.
