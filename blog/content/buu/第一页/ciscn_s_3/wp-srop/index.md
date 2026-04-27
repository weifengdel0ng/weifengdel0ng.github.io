+++
title = "wp--srop"
date = "2026-03-04"
type = "post"
categories = ['BUU']
tags = ['BUU']
draft = false
+++
![Pasted image 20260123102243.png](Pasted%20image%2020260123102243.png)vuln函数中使用了两个syscall指令，根据rax即可知道该指令调用的是哪个系统调用

第一个syscall：与自己进行异或操作（对应xor指令），得到的结果就是0，系统调用号为0的系统调用是read
第二个syscall：给rax赋值为1（对应代码mov rax 1），系统调用号为1的系统调用是write
1. read存在栈溢出
2. write能泄露数据

1 | rax = 59//对应59号系统调用-> exceve  
2 | rdi = ‘/bin/sh’  
3 | rsi = 0  
4 | rdx = 0
