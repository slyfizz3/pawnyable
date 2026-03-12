---
title: Linux Userland Exploitation
hide_toc: true
---
<div class="i18n" data-ja="この章ではひよこ先生🐤と一緒にLinuxのユーザー空間におけるExploit手法について学びます。Linuxのユーザー空間におけるExploit手法を解説した資料は人間社会にも多数出回っているため、ここではより重要な知識のみを説明します。" data-ko="이 장에서는 병아리 선생님🐤과 함께 Linux 사용자 영역의 Exploit 기법을 배웁니다. 관련 자료는 이미 많이 존재하므로, 여기서는 더 중요한 핵심 지식만 설명합니다." data-en="In this chapter, you'll learn Linux userland exploitation techniques with Professor Chick 🐤. Since many resources already explain userland exploits, this chapter focuses on the most important concepts.">この章ではひよこ先生🐤と一緒にLinuxのユーザー空間におけるExploit手法について学びます。Linuxのユーザー空間におけるExploit手法を解説した資料は人間社会にも多数出回っているため、ここではより重要な知識のみを説明します。</div>

<ul>
  <li><span class="i18n" data-ja="前提知識" data-ko="사전 지식" data-en="Prerequisites">前提知識</span>
    <ul>
      <li><span class="i18n" data-ja="<a href='introduction/security.html'>セキュリティ機構</a>" data-ko="<a href='introduction/security.html'>보안 기법</a>" data-en="<a href='introduction/security.html'>Security mechanisms</a>"><a href='introduction/security.html'>セキュリティ機構</a></span></li>
      <li><span class="i18n" data-ja="<a href='introduction/primitive.html'>Primitiveについて</a>" data-ko="<a href='introduction/primitive.html'>Primitive에 대하여</a>" data-en="<a href='introduction/primitive.html'>About primitives</a>"><a href='introduction/primitive.html'>Primitiveについて</a></span></li>
      <li><span class="i18n" data-ja="<a href='introduction/environment.html'>環境の用意</a>" data-ko="<a href='introduction/environment.html'>환경 준비</a>" data-en="<a href='introduction/environment.html'>Environment setup</a>"><a href='introduction/environment.html'>環境の用意</a></span></li>
    </ul>
  </li>
  <li><span class="i18n" data-ja="シェルコード" data-ko="셸코드" data-en="Shellcode">シェルコード</span>
    <ul>
      <li><span class="i18n" data-ja="<a href='shellcode/how2write.html'>シェルコードの書き方</a>" data-ko="<a href='shellcode/how2write.html'>셸코드 작성법</a>" data-en="<a href='shellcode/how2write.html'>How to write shellcode</a>"><a href='shellcode/how2write.html'>シェルコードの書き方</a></span></li>
      <li><span class="i18n" data-ja="<a href='shellcode/restricted.html'>制約付きシェルコード</a>" data-ko="<a href='shellcode/restricted.html'>제약이 있는 셸코드</a>" data-en="<a href='shellcode/restricted.html'>Restricted shellcode</a>"><a href='shellcode/restricted.html'>制約付きシェルコード</a></span></li>
      <li><span class="i18n" data-ja="<a href='shellcode/seccomp.html'>seccompの回避</a>" data-ko="<a href='shellcode/seccomp.html'>seccomp 우회</a>" data-en="<a href='shellcode/seccomp.html'>Bypassing seccomp</a>"><a href='shellcode/seccomp.html'>seccompの回避</a></span></li>
      <li><a href='shellcode/egg-hunter.html'>Egg Hunter</a></li>
      <li><span class="i18n" data-ja="<a href='shellcode/byog.html'>Bring Your Own Gadget（工事中）</a>" data-ko="<a href='shellcode/byog.html'>Bring Your Own Gadget (준비 중)</a>" data-en="<a href='shellcode/byog.html'>Bring Your Own Gadget (WIP)</a>"><a href='shellcode/byog.html'>Bring Your Own Gadget（工事中）</a></span></li>
    </ul>
  </li>
</ul>


<ul>
  <li><span class="i18n" data-ja="スタック" data-ko="스택" data-en="Stack">スタック</span>
    <ul>
      <li><a href='stack/bof.html'>Stack Buffer Overflow</a></li>
      <li><a href='stack/rop.html'>Return Oriented Programming</a></li>
      <li><span class="i18n" data-ja="<a href='stack/fork.html'>forkとcanary</a>" data-ko="<a href='stack/fork.html'>fork와 canary</a>" data-en="<a href='stack/fork.html'>fork and canary</a>"><a href='stack/fork.html'>forkとcanary</a></span></li>
      <li><span class="i18n" data-ja="<a href='stack/thread.html'>スレッドとcanary</a>" data-ko="<a href='stack/thread.html'>스레드와 canary</a>" data-en="<a href='stack/thread.html'>threads and canary</a>"><a href='stack/thread.html'>スレッドとcanary</a></span></li>
    </ul>
  </li>
  <li><span class="i18n" data-ja="ヒープ" data-ko="힙" data-en="Heap">ヒープ</span>
    <ul>
      <li><a href='heap/call-chain.html'>Call/Jump Oriented Programming</a></li>
      <li><a href='heap/bof.html'>Heap Buffer Overflow</a></li>
      <li><a href='heap/uaf.html'>Use-after-Free</a></li>
      <li><span class="i18n" data-ja="<a href='heap/spray1.html'>Heap Sprayその１：特定のアドレスにデータを置く手法</a>" data-ko="<a href='heap/spray1.html'>Heap Spray 1: 특정 주소에 데이터를 배치하는 기법</a>" data-en="<a href='heap/spray1.html'>Heap Spray #1: placing data at a specific address</a>"><a href='heap/spray1.html'>Heap Sprayその１：特定のアドレスにデータを置く手法</a></span></li>
      <li><span class="i18n" data-ja="<a href='heap/spray2.html'>Heap Sprayその２：2つのオブジェクトを隣接させる手法</a>" data-ko="<a href='heap/spray2.html'>Heap Spray 2: 두 오브젝트를 인접 배치하는 기법</a>" data-en="<a href='heap/spray2.html'>Heap Spray #2: placing two objects adjacently</a>"><a href='heap/spray2.html'>Heap Sprayその２：2つのオブジェクトを隣接させる手法</a></span></li>
      <li><span class="i18n" data-ja="<a href='heap/spray3.html'>Heap Sprayその３：ヒープの初期状態を固定する手法</a>" data-ko="<a href='heap/spray3.html'>Heap Spray 3: 힙 초기 상태를 고정하는 기법</a>" data-en="<a href='heap/spray3.html'>Heap Spray #3: stabilizing the initial heap state</a>"><a href='heap/spray3.html'>Heap Sprayその３：ヒープの初期状態を固定する手法</a></span></li>
    </ul>
  </li>
  <li><span class="i18n" data-ja="その他の脆弱性" data-ko="기타 취약점" data-en="Other vulnerabilities">その他の脆弱性</span>
    <ul>
      <li><a href='others/fsb.html'>Format String Bug</a></li>
      <li><a href='others/integer.html'>Integer Overflow</a></li>
      <li><a href='others/confusion.html'>Type Confusion</a></li>
      <li><a href='others/nullpo.html'>NULL pointer dereference</a></li>
    </ul>
  </li>
</ul>

<div class="column" title="ひよこ先生">
　TBD :)
</div>
