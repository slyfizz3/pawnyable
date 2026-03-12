---
title: Stack Buffer Overflow
tags:
    - [Linux]
    - [Userland]
    - [Stack]
    - [Buffer Overflow]
lang: en
permalink: /en/linux-userland/stack/bof.html
---
Buffer overflow is one of the oldest and most fundamental bug classes in binary exploitation.

## What is Stack Buffer Overflow?
It happens when attacker-controlled data overwrites a stack buffer and continues into adjacent stack state such as saved frame pointers or return addresses.

The important questions are:
- how far can you overwrite?
- what control data is nearby?
- which mitigations are enabled?
