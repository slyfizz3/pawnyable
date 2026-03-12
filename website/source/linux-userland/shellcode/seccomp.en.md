---
title: Bypassing seccomp
tags:
    - [Linux]
    - [Userland]
lang: en
permalink: /en/linux-userland/shellcode/seccomp.html
pagination: true
bk: restricted.html
fd: egg-hunter.html
---
`seccomp` is one of the most common userland sandboxing mechanisms. Exploitation under seccomp is often about finding what the filter forgot to block.

## seccomp
### What is seccomp?
It is a syscall filtering mechanism.

### How seccomp is used
Programs install a filter that decides which syscalls are allowed.

### `seccomp-tools`
This is a convenient way to inspect BPF-based seccomp filters.

### Syscalls that should be blocked
A weak sandbox often forgets dangerous alternatives to the obvious syscalls.

## Problems in blacklist filters
### `openat` and `execveat`
Blocking `open` or `execve` alone is usually not enough.

### `creat` and procfs
Alternate filesystem paths or helper syscalls may still expose powerful behavior.

### `ptrace`, `process_vm_readv`, `process_vm_writev`
Cross-process interfaces can become sandbox escape routes.

### Container escape
In containerized environments, the seccomp story may combine with namespace and filesystem issues.

## Problems in whitelist filters
### Incomplete argument validation
Even an allowed syscall can be abused if its arguments are not constrained carefully.

## Side channels
### Observing errors
Different return codes can leak policy details.

### Measuring timing
Timing differences can reveal whether a path was filtered or executed.

## Bad architecture and syscall-number checks
### Architecture mismatch
Incorrect architecture validation can break assumptions.

### Using x32 ABI
Alternate ABIs sometimes expose filter blind spots.

## Other bypass ideas
### Kernel or library flaws
If the kernel or a library is buggy, seccomp may no longer matter.

### Abusing another process
A less restricted peer process can sometimes be used as a capability proxy.
