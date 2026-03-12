---
title: 예제 정답 - 제약이 있는 셸코드
lang: kr
permalink: /kr/linux-userland/shellcode/restricted-answer.html
---
## 예제 1
가장 짧은 정답이 항상 가장 읽기 쉬운 정답은 아닙니다. 최종 syscall에서 거꾸로 생각하고, 바이트 제약을 만족하는 인코딩을 골라야 합니다.

## 예제 2
직접 payload가 불가능할 때는 작은 로더와 더 풍부한 2단계 payload로 나누는 것이 가장 깔끔한 해법인 경우가 많습니다.
