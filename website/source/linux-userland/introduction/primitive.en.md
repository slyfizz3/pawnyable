---
title: About Primitives
tags:
    - [Linux]
    - [Userland]
lang: en
permalink: /en/linux-userland/introduction/primitive.html
pagination: true
bk: security.html
fd: environment.html
---
In exploitation, a primitive is a useful capability gained from a bug. Thinking in primitives makes it easier to reason about exploit chains.

## What is a primitive?
A primitive is not the final exploit. It is an intermediate capability such as:
- RIP control
- information leak
- arbitrary read
- arbitrary write

## Common primitives
### RIP control
Direct control of instruction pointer execution.

### Address leak
A way to recover randomized addresses and defeat ASLR-like protections.

### `addrof`
The ability to learn the address of an object.

### `fakeobj`
The ability to make the target treat attacker-controlled memory as a valid object.

### AAR
Arbitrary address read.

### AAW
Arbitrary address write.
