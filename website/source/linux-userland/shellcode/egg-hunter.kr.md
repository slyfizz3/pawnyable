---
title: Egg Hunter
tags:
    - [Linux]
    - [Userland]
lang: kr
permalink: /kr/linux-userland/shellcode/egg-hunter.html
pagination: true
bk: seccomp.html
fd: byog.html
---
Egg hunter는 더 큰 2단계 셸코드를 메모리에서 찾아가는 아주 작은 1단계 payload입니다. 보통 미리 알려진 마커(signature)를 기준으로 검색합니다.

## Egg Hunter
이 기법은 다음 상황에서 유용합니다.
- 처음 주입 가능한 공간이 너무 작을 때
- 최종 payload가 다른 메모리 영역에 있을 때
- 정확한 주소를 모를 때

## 셸코드 탐색
hunter는 메모리를 스캔해 마커를 찾고, 마커를 발견하면 실제 payload로 점프합니다.

## 주소 탐색
### 안전한 syscall 사용
일부 hunter는 주소가 매핑돼 있는지 안전하게 알려 주는 syscall을 이용합니다.

### TSX 활용
일부 시스템에서는 transactional memory를 이용해 메모리 접근 가능 여부를 탐지할 수도 있습니다.
