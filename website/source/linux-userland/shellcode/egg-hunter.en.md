---
title: Egg Hunter
tags:
    - [Linux]
    - [Userland]
lang: en
permalink: /en/linux-userland/shellcode/egg-hunter.html
pagination: true
bk: seccomp.html
fd: byog.html
---
An egg hunter is a tiny first-stage payload that searches memory for a larger second-stage shellcode marked by a known signature.

## Egg Hunter
The technique is useful when:
- the initial injection space is too small
- the final payload exists somewhere else in memory
- the exact address is unknown

## Searching for shellcode
The hunter scans memory until it finds the marker, then jumps to the real payload.

## Searching for addresses
### Using safe syscalls
Some hunters rely on syscalls that safely reveal whether an address is mapped.

### Using TSX
On some systems, transactional memory can be used as another way to probe whether memory is accessible.
