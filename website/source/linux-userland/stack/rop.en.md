---
title: Return Oriented Programming
tags:
    - [Linux]
    - [Userland]
    - [Stack]
    - [ROP]
lang: en
permalink: /en/linux-userland/stack/rop.html
---
Return Oriented Programming is the standard answer when code injection is blocked but control-flow hijack is still possible.

## What is Return Oriented Programming?
ROP chains together short instruction sequences ending in `ret` to perform arbitrary computation.

## ROP gadgets
The quality of a ROP environment depends on what gadgets exist in the main binary and loaded libraries.

## Stack pivot
When the original stack is too small or unstable, a stack pivot moves execution onto a larger attacker-controlled region.
