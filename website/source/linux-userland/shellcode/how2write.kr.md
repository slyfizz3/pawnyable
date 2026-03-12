---
title: 셸코드 작성법
tags:
    - [Linux]
    - [Userland]
lang: kr
permalink: /kr/linux-userland/shellcode/how2write.html
pagination: true
bk: ../introduction/environment.html
fd: restricted.html
---
셸코드는 예전처럼 모든 상황의 정답은 아니지만, 공격자 제어 실행 가능 메모리가 존재하는 환경에서는 여전히 중요합니다.

## NX가 셸코드를 끝냈을까?
NX는 고전적인 주입 코드 실행을 어렵게 만들었지만, JIT 환경, sandbox escape, staged payload, 제한된 CTF 문제 등에서는 여전히 셸코드가 중요합니다.

### 샌드박스 아래의 셸코드
코드 재사용만으로 충분하지 않을 때는 작은 커스텀 payload가 오히려 가장 쉬운 경로일 수 있습니다.

### JIT와 셸코드
JIT 엔진은 실행 가능한 페이지를 만들기 때문에, 다시 셸코드형 공격이 가능해지기도 합니다.

## 셸코드 써 보기
핵심은 다음과 같습니다.
- syscall ABI 이해
- 불필요한 바이트 줄이기
- 레지스터 상태 통제
- staged payload로 할지 단일 payload로 할지 결정
