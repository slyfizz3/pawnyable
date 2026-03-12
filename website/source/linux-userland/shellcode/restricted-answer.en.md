---
title: Practice Answers - Restricted Shellcode
lang: en
permalink: /en/linux-userland/shellcode/restricted-answer.html
---
## Exercise 1
The shortest answer is usually not the most readable one. Work backward from the final syscall and choose encodings that satisfy the byte constraints.

## Exercise 2
When a direct payload is impossible, split it into a small loader and a richer second stage. That is often the cleanest solution under severe restrictions.
