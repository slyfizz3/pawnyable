---
title: Stack Buffer Overflow
tags:
    - [Linux]
    - [Userland]
    - [Stack]
    - [Buffer Overflow]
lang: kr
permalink: /kr/linux-userland/stack/bof.html
---
Buffer overflow는 binary exploitation에서 가장 오래되고 가장 기본적인 취약점 종류 중 하나입니다.

## Stack Buffer Overflow란?
공격자 제어 데이터가 스택 버퍼를 넘어서 저장된 프레임 포인터나 리턴 주소 같은 인접 스택 상태까지 덮어쓰는 상황을 말합니다.

중요한 질문은 다음입니다.
- 어디까지 덮을 수 있는가
- 근처에 어떤 제어 데이터가 있는가
- 어떤 완화 기법이 켜져 있는가
