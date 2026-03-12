---
title: seccomp 우회
tags:
    - [Linux]
    - [Userland]
lang: kr
permalink: /kr/linux-userland/shellcode/seccomp.html
pagination: true
bk: restricted.html
fd: egg-hunter.html
---
`seccomp`는 사용자 공간에서 가장 흔한 샌드박싱 기법 중 하나입니다. seccomp 아래의 exploit는 대개 필터가 무엇을 막지 못했는지 찾는 과정입니다.

## seccomp
### seccomp란?
syscall 필터링 메커니즘입니다.

### seccomp 사용 방식
프로그램이 어떤 syscall을 허용할지 결정하는 필터를 설치합니다.

### `seccomp-tools`
BPF 기반 seccomp 필터를 분석할 때 매우 편리한 도구입니다.

### 차단해야 할 syscall
약한 샌드박스는 눈에 띄는 syscall만 막고 대체 경로를 놓치는 경우가 많습니다.

## 블랙리스트 필터의 문제점
### `openat`과 `execveat`
`open`이나 `execve`만 막는 것으로는 충분하지 않은 경우가 많습니다.

### `creat`과 procfs
대체 파일시스템 경로 또는 보조 syscall이 여전히 강력한 기능을 열어 줄 수 있습니다.

### `ptrace`, `process_vm_readv`, `process_vm_writev`
프로세스 간 인터페이스가 샌드박스 탈출 경로가 될 수 있습니다.

### 컨테이너 탈출
컨테이너 환경에서는 seccomp 문제가 namespace, 파일시스템 문제와 결합되기도 합니다.

## 화이트리스트 필터의 문제점
### 불완전한 인자 검증
허용된 syscall이라도 인자 제약이 부실하면 충분히 악용될 수 있습니다.

## 사이드채널 공격
### 에러 관측
반환 코드 차이만으로도 정책 정보를 누출할 수 있습니다.

### 처리 시간 측정
타이밍 차이는 필터링되었는지 실제 실행되었는지를 알려 줄 수 있습니다.

## 아키텍처와 syscall 번호 검증 문제
### 아키텍처 검증 부실
아키텍처 검사가 틀리면 필터 가정 전체가 무너질 수 있습니다.

### x32 ABI 사용
대체 ABI가 필터의 사각지대를 제공하기도 합니다.

## 기타 우회 아이디어
### 커널 또는 라이브러리 결함 이용
커널이나 라이브러리에 버그가 있으면 seccomp 자체가 무의미해질 수 있습니다.

### 다른 프로세스 악용
덜 제한된 다른 프로세스를 capability proxy처럼 이용하는 경우도 있습니다.
