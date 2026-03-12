---
title: 보안 기법
tags:
    - [Linux]
    - [Userland]
lang: kr
permalink: /kr/linux-userland/introduction/security.html
pagination: true
fd: primitive.html
---
이 장은 사용자 공간 exploit에 영향을 주는 주요 완화 기법들을 요약합니다.

## OS 및 CPU 수준 완화 기법
### ASLR
ASLR은 라이브러리, 스택, 힙 같은 중요한 영역을 무작위화하여 하드코딩된 주소나 직접 점프를 불안정하게 만듭니다.

### 무작위화되지 않는 영역과 PIE
모든 영역이 동일하게 랜덤화되지는 않습니다. 메인 바이너리가 PIE인지 여부가 고정 레이아웃 범위를 크게 바꿉니다.

### NX
NX는 데이터 페이지 실행을 막습니다. 그래서 현대 exploit는 코드 재사용이나 JIT 생성 코드를 많이 이용합니다.

### CET
CET는 shadow stack, indirect branch tracking 같은 하드웨어 기반 제어 흐름 보호를 제공합니다.

## 컴파일러 및 프로그램 수준 완화 기법
### Stack Canary (SSP)
canary는 함수 리턴 전에 단순한 스택 오염을 감지합니다.

### `FORTIFY_SOURCE`
컴파일러가 객체 크기를 추론할 수 있을 때, 자주 쓰이는 라이브러리 함수 주위에 추가 경계 검사를 넣습니다.

### CFI
간접 호출이나 점프가 허용된 목표로만 향하도록 제한합니다.

## 라이브러리 완화 기법
공유 라이브러리 자체에도 보호가 들어갈 수 있으며, OS 완화 기법과 결합되면서 exploit 난이도에 영향을 줍니다.
