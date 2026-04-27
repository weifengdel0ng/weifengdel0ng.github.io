+++
title = "wp"
date = "2026-04-15"
type = "post"
categories = ['BUU']
tags = ['BUU']
draft = false
+++
![Pasted image 20260304191505.png](Pasted%20image%2020260304191505.png)
主函数中以下部分会导致无法进行反汇编但也同时是其漏洞。这个部分会导致程序将栈上的部分当作程序执行。
```
lea     rax, [rbp+buf]
call    rax
mov     eax, 0
```
只要写入一个shellcode就结束了
shellcode见前一道wp
最后的exp：exp
