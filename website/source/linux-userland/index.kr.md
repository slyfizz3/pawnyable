---
title: Linux Userland Exploitation
lang: kr
permalink: /kr/linux-userland/
hide_toc: true
---

이 장에서는 병아리 선생님과 함께 Linux 사용자 공간에서의 exploit 기법을 공부합니다. 사용자 공간 exploitation 자료는 이미 많기 때문에, 여기서는 실제로 중요한 개념 위주로 정리합니다.

- 선수 지식
  - [보안 기법](introduction/security.html)
  - [Primitive란 무엇인가](introduction/primitive.html)
  - [환경 준비](introduction/environment.html)
- 셸코드
  - [셸코드 작성법](shellcode/how2write.html)
  - [제약이 있는 셸코드](shellcode/restricted.html)
  - [seccomp 우회](shellcode/seccomp.html)
  - [Egg Hunter](shellcode/egg-hunter.html)
  - [Bring Your Own Gadget (준비 중)](shellcode/byog.html)
- 스택
  - [Stack Buffer Overflow](stack/bof.html)
  - [Return Oriented Programming](stack/rop.html)
  - [fork와 canary](stack/fork.html)
  - [스레드와 canary](stack/thread.html)
- 힙
  - [Call/Jump Oriented Programming](heap/call-chain.html)
  - [Heap Buffer Overflow](heap/bof.html)
  - [Use-after-Free](heap/uaf.html)
  - [Heap Spray 1: 원하는 주소에 데이터 배치](heap/spray1.html)
  - [Heap Spray 2: 두 객체를 인접하게 배치](heap/spray2.html)
  - [Heap Spray 3: 초기 힙 상태 고정](heap/spray3.html)
- 기타 취약점
  - [Format String Bug](others/fsb.html)
  - [Integer Overflow](others/integer.html)
  - [Type Confusion](others/confusion.html)
  - [NULL pointer dereference](others/nullpo.html)

<div class="column" title="병아리 선생님">
  TBD :)
</div>
