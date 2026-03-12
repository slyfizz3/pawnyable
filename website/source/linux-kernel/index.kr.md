---
title: Linux Kernel Exploitation
lang: kr
permalink: /kr/linux-kernel/
hide_toc: true
---

<div class="balloon_l">
  <div class="faceicon"><img src="img/wolf_normal.png" alt="늑대" ></div>
  <p class="says">
  이 장에서는 리눅스 커널 공간에서의 exploit, 즉 권한 상승 기법을 공부합니다. 여기서 배우는 하드웨어 보안 기능과 권한 상승 방식은 Windows 커널 exploit에도 자주 등장합니다.
  </p>
</div>

- 실행 환경과 디버깅
  - [커널 exploit 입문](introduction/introduction.html)
  - [gdb로 커널 디버깅하기](introduction/debugging.html)
  - [보안 기법](introduction/security.html)
  - [컴파일과 exploit 전송](introduction/compile-and-transfer.html)
- 커널 exploit 기초 (LK01: Holstein)
  - [Holstein 모듈 분석과 취약점 발화](LK01/welcome-to-holstein.html)
  - [Holstein v1: Stack Overflow 악용](LK01/stack_overflow.html)
  - [Holstein v2: Heap Overflow 악용](LK01/heap_overflow.html)
  - [Holstein v3: Use-after-Free 악용](LK01/use_after_free.html)
  - [Holstein v4: Race Condition 악용](LK01/race_condition.html)
- 커널 특화 공격 기법
  - [NULL Pointer Dereference (LK02: Angus)](LK02/null_ptr_deref.html)
  - [Double Fetch (LK03: Dexter)](LK03/double_fetch.html)
  - [userfaultfd 활용 (LK04: Fleckvieh)](LK04/uffd.html)
  - [FUSE 활용 (LK04: Fleckvieh)](LK04/fuse.html)
  - [취약한 mmap 구현 악용 (LK05: Highland) (준비 중)](#)
- eBPF와 JIT 컴파일러 (LK06: Brahman)
  - [BPF 입문](LK06/ebpf.html)
  - [검증기와 JIT 컴파일러](LK06/verifier.html)
  - [eBPF 버그 악용](LK06/exploit.html)

<div class="column" title="강사 소개">
  <div style="overflow: hidden">
    <div style="float: left; margin-right: 1em;" class="faceicon">
      <img src="img/wolf_suyasuya.png" alt="늑대" >
    </div>
    <div style="float: left;">
      <b>늑대 선생님</b><br>
      권한 상승으로 무리의 리더가 되었다는 전설이 있는 늑대.<br>
      동물계 최고의 OS 전문가. 기본적으로 늘 잠들어 있다.<br>
      좋아하는 것: 소 / Linux<br>
      싫어하는 것: 하이에나 / Windows
    </div>
  </div>
</div>
