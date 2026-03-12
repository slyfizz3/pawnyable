---
title: 제약이 있는 셸코드
tags:
    - [Linux]
    - [Userland]
lang: kr
permalink: /kr/linux-userland/shellcode/restricted.html
pagination: true
bk: how2write.html
fd: seccomp.html
---
실전 셸코드에는 제약이 붙는 경우가 많습니다. payload 길이가 매우 짧아야 하거나, bad byte를 피해야 하거나, 일부 실행 상태를 모른 채 동작해야 할 수 있습니다.

## 길이 제약 셸코드
### 짧은 명령어 선택
명령어 선택이 매우 중요합니다. 작은 인코딩과 레지스터 재사용이 핵심이 됩니다.

### Stager 구축
payload가 너무 크다면, 짧은 1단계 로더가 더 큰 2단계 payload를 읽어오거나 복호화하는 구조를 사용합니다.

## 문자 제약 셸코드
### NUL, 개행 제약
많은 입력 경로는 문자열 종료나 파싱 문제를 일으키는 바이트를 금지합니다.

### ASCII / UTF-8 제약
payload가 출력 가능한 문자 집합이나 상위 텍스트 인코딩을 유지해야 하는 경우도 있습니다.

### 부동소수점 / IEEE 754 제약
이상한 데이터 채널은 더 기묘한 바이트 제약을 만들기도 합니다.

## 상태 제약 셸코드
### 주소를 모르는 경우
셸코드 위치를 모르면 `call`/`pop`, egg hunter 같은 자기 위치 탐색 기법이 중요해집니다.

### 셸코드 영역이 쓰기 불가능한 경우
실행 전용 혹은 비쓰기 영역이라면 self-modifying 전략이나 staged 접근도 달라집니다.
