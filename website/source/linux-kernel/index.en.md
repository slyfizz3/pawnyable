---
title: Linux Kernel Exploitation
lang: en
permalink: /en/linux-kernel/
hide_toc: true
---

<div class="balloon_l">
  <div class="faceicon"><img src="img/wolf_normal.png" alt="Wolf" ></div>
  <p class="says">
  This chapter studies Linux kernel exploitation, especially local privilege escalation. Many hardware security features and escalation patterns also appear in Windows kernel exploitation, so the material carries over well.
  </p>
</div>

- Runtime setup and debugging
  - [Introduction to kernel exploitation](introduction/introduction.html)
  - [Debugging the kernel with gdb](introduction/debugging.html)
  - [Security mechanisms](introduction/security.html)
  - [Compiling and transferring exploits](introduction/compile-and-transfer.html)
- Core kernel exploitation (LK01: Holstein)
  - [Understanding the Holstein module and triggering the bugs](LK01/welcome-to-holstein.html)
  - [Holstein v1: Exploiting Stack Overflow](LK01/stack_overflow.html)
  - [Holstein v2: Exploiting Heap Overflow](LK01/heap_overflow.html)
  - [Holstein v3: Exploiting Use-after-Free](LK01/use_after_free.html)
  - [Holstein v4: Exploiting Race Condition](LK01/race_condition.html)
- Kernel-specific attack surfaces
  - [NULL Pointer Dereference (LK02: Angus)](LK02/null_ptr_deref.html)
  - [Double Fetch (LK03: Dexter)](LK03/double_fetch.html)
  - [Using userfaultfd (LK04: Fleckvieh)](LK04/uffd.html)
  - [Using FUSE (LK04: Fleckvieh)](LK04/fuse.html)
  - [Exploiting a buggy mmap implementation (LK05: Highland) (WIP)](#)
- eBPF and the JIT compiler (LK06: Brahman)
  - [Introduction to BPF](LK06/ebpf.html)
  - [Verifier and JIT compiler](LK06/verifier.html)
  - [Exploiting eBPF bugs](LK06/exploit.html)

<div class="column" title="Instructor profile">
  <div style="overflow: hidden">
    <div style="float: left; margin-right: 1em;" class="faceicon">
      <img src="img/wolf_suyasuya.png" alt="Wolf" >
    </div>
    <div style="float: left;">
      <b>Wolf</b><br>
      A legendary wolf who became leader through privilege escalation.<br>
      A leading OS expert in the animal world. Usually sleeping.<br>
      Likes: cows / Linux<br>
      Dislikes: hyenas / Windows
    </div>
  </div>
</div>
