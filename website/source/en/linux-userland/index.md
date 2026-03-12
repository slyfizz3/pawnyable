---
title: Linux Userland Exploitation
hide_toc: true
lang: en
---
この章ではひよこ先生🐤と一緒にLinuxのユーザー空間におけるExploit手法について学びます。Linuxのユーザー空間におけるExploit手法を解説した資料は人間社会にも多数出回っているため、ここではより重要な知識のみを説明します。

- 前提知識
  - [セキュリティ機構](introduction/security.html)
  - [Primitiveについて](introduction/primitive.html)
  - [環境の用意](introduction/environment.html)
- シェルコード
  - [シェルコードの書き方](shellcode/how2write.html)
  - [制約付きシェルコード](shellcode/restricted.html)
  - [seccompの回避](shellcode/seccomp.html)
  - [Egg Hunter](shellcode/egg-hunter.html)
  - [Bring Your Own Gadget（工事中）](shellcode/byog.html)
- スタック
  - [Stack Buffer Overflow](stack/bof.html)
  - [Return Oriented Programming](stack/rop.html)
  - [forkとcanary](stack/fork.html)
  - [スレッドとcanary](stack/thread.html)
- ヒープ
  - [Call/Jump Oriented Programming](heap/call-chain.html)
  - [Heap Buffer Overflow](heap/bof.html)
  - [Use-after-Free](heap/uaf.html)
  - [Heap Sprayその１：特定のアドレスにデータを置く手法](heap/spray1.html)
  - [Heap Sprayその２：2つのオブジェクトを隣接させる手法](heap/spray2.html)
  - [Heap Sprayその３：ヒープの初期状態を固定する手法](heap/spray3.html)
- その他の脆弱性
  - [Format String Bug](others/fsb.html)
  - [Integer Overflow](others/integer.html)
  - [Type Confusion](others/confusion.html)
  - [NULL pointer dereference](others/nullpo.html)

<div class="column" title="ひよこ先生">
　TBD :)
</div>
