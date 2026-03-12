---
title: Practice Answers - How to Write Shellcode
lang: en
permalink: /en/linux-userland/shellcode/how2write-answer.html
---
## Exercise 1
The goal is to write a minimal syscall-oriented payload. Focus on the required registers first and remove every unnecessary instruction.

## Exercise 2
This exercise usually introduces string construction or argument setup. Reuse registers instead of loading new constants repeatedly.

## Exercise 3
Here the point is not just "make it work" but "make it small and robust." Compare multiple encodings and keep the shortest safe option.
