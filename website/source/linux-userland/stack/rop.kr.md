---
title: Return Oriented Programming
tags:
    - [Linux]
    - [Userland]
    - [Stack]
    - [ROP]
lang: kr
permalink: /kr/linux-userland/stack/rop.html
---
Return Oriented Programming은 코드 주입이 막혀 있지만 제어 흐름 탈취는 가능한 상황에서 쓰이는 대표적인 해법입니다.

## Return Oriented Programming이란?
`ret`으로 끝나는 짧은 명령어 조각들을 이어 붙여 임의 계산을 수행하는 기법입니다.

## ROP gadget
좋은 ROP 환경인지 여부는 메인 바이너리와 로드된 라이브러리에 어떤 gadget가 존재하는지에 크게 좌우됩니다.

## Stack Pivot
원래 스택이 너무 작거나 불안정하면, stack pivot를 이용해 더 큰 공격자 제어 영역으로 실행을 옮깁니다.
