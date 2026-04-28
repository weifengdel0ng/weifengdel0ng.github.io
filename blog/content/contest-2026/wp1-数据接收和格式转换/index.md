+++
title = "wp1-数据接收和格式转换"
date = "2026-03-29"
type = "post"
categories = ["比赛"]
tags = ["2026校赛"]
draft = false
+++
给出的回显格式是:５４ ＋ ９９ ＝

00000000  0a ef bc 97  ef bc 91 20  08 20 ef bc  8b 20 08 20  │····│··· │· ··│· · │
00000010  ef bc 94 ef  bc 92 20 08  20 ef bc 9d  20           │····│·· ·│ ···│ │
0000001d
７１ ＋ ４２ ＝ 
字符是全角的
ef bc 97是一串，代表7
ef bc  8b是+
ef bc 9d 是=
20 08  20是空格



口算20个就可以了
难道没有ai我啥也不是🐎
要提取算式
```python
from pwn import *  
from LibcSearcher import LibcSearcher  
import unicodedata  
import time  
#程序是几位的  
con=64  
if con == 32:  
    print('当前程序是32位的:')  
    context(log_level='debug', arch='i386', os='linux')  
elif con == 64:  
    print("当前程序是64位的")  
    context(log_level='debug', arch='amd64', os='linux')  
context.terminal = ['tmux', 'splitw', '-h']  
#_______________________________________________________  
#local_file = ('./pwn')  
#elf = ELF(local_file)  
debug=0  
if debug:  
    print('开始打本地:')  
    io=process(local_file)  
else:  
    print("开始打远程")  
    io = remote("nc1.ctfplus.cn", 30953)  
#_______________需要用到的地址区包括offset_____________________  
#main = elf.symbols["main"]  
  
#main地址--------------------  
def zh(data):  
    fullwidth_utf8 = {  
        b'\xef\xbc\x90': '0',  
        b'\xef\xbc\x91': '1',  
        b'\xef\xbc\x92': '2',  
        b'\xef\xbc\x93': '3',  
        b'\xef\xbc\x94': '4',  
        b'\xef\xbc\x95': '5',  
        b'\xef\xbc\x96': '6',  
        b'\xef\xbc\x97': '7',  
        b'\xef\xbc\x98': '8',  
        b'\xef\xbc\x99': '9',  
    }  
  
    i = 0  
    digits = []  
    while i < len(data):  
        if data[i:i+3] in fullwidth_utf8:  
            digits.append(fullwidth_utf8[data[i:i+3]])  
            i += 3  
        else:  
            i += 1  
  
    result = ''.join(digits)  
    return result  
  
  
io.recvuntil(b"solve all the questions to get the shell!")  
  
for i in range(100):  
    string1 = io.recv()  
    print(string1)  
  
    s = string1  
    sep = b" \x08 \xef\xbc\x8b "    before, found, after = s.partition(sep)  
    if found:  
        result1 =  before  
        result2 = after  
    else:  
        result = 0  
  
    num1 = int(zh(before))  
    num2 = int(zh(after))  
  
    sum = num1 + num2  
    io.sendline(str(sum))  
    sleep(0.3)  
  
  
  
#————————————————————payload2——————————————————————————  
io.interactive()
```
