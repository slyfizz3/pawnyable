---
title: Primitive란 무엇인가
tags:
    - [Linux]
    - [Userland]
lang: kr
permalink: /kr/linux-userland/introduction/primitive.html
pagination: true
bk: security.html
fd: environment.html
---
exploit에서 primitive는 버그로부터 얻은 유용한 능력입니다. primitive 관점으로 생각하면 exploit chain을 훨씬 체계적으로 설계할 수 있습니다.

## Primitive란?
primitive는 최종 exploit 자체가 아니라 중간 능력입니다. 예를 들면:
- RIP 제어
- 정보 누출
- arbitrary read
- arbitrary write

## 일반적인 primitive
### RIP 제어
명령어 포인터 실행 흐름을 직접 제어하는 능력입니다.

### 주소 누출
랜덤화된 주소를 복구해 ASLR류 보호를 깨는 능력입니다.

### `addrof`
객체의 실제 주소를 알아내는 능력입니다.

### `fakeobj`
공격자 제어 메모리를 유효한 객체처럼 다루게 만드는 능력입니다.

### AAR
Arbitrary address read.

### AAW
Arbitrary address write.
