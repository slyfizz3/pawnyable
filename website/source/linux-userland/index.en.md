---
title: Linux Userland Exploitation
lang: en
permalink: /en/linux-userland/
hide_toc: true
---

In this chapter, the chick instructor walks through Linux userland exploitation. Plenty of public material already covers common userland exploitation, so this section focuses on the ideas that matter most in practice.

- Prerequisites
  - [Security mechanisms](introduction/security.html)
  - [About primitives](introduction/primitive.html)
  - [Setting up the environment](introduction/environment.html)
- Shellcode
  - [How to write shellcode](shellcode/how2write.html)
  - [Restricted shellcode](shellcode/restricted.html)
  - [Bypassing seccomp](shellcode/seccomp.html)
  - [Egg Hunter](shellcode/egg-hunter.html)
  - [Bring Your Own Gadget (WIP)](shellcode/byog.html)
- Stack
  - [Stack Buffer Overflow](stack/bof.html)
  - [Return Oriented Programming](stack/rop.html)
  - [fork and canaries](stack/fork.html)
  - [Threads and canaries](stack/thread.html)
- Heap
  - [Call/Jump Oriented Programming](heap/call-chain.html)
  - [Heap Buffer Overflow](heap/bof.html)
  - [Use-after-Free](heap/uaf.html)
  - [Heap Spray 1: placing data at a chosen address](heap/spray1.html)
  - [Heap Spray 2: placing two objects next to each other](heap/spray2.html)
  - [Heap Spray 3: fixing the initial heap state](heap/spray3.html)
- Other bug classes
  - [Format String Bug](others/fsb.html)
  - [Integer Overflow](others/integer.html)
  - [Type Confusion](others/confusion.html)
  - [NULL pointer dereference](others/nullpo.html)

<div class="column" title="Chick instructor">
  TBD :)
</div>
