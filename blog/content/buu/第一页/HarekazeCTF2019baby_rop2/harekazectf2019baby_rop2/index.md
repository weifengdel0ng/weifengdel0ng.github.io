+++
title = "HarekazeCTF2019baby_rop2"
date = "2026-03-04"
type = "post"
categories = ['BUU']
tags = ['第一页', 'HarekazeCTF2019baby_rop2']
draft = false
+++
![Pasted image 20260111103752.png](%E9%99%84%E4%BB%B6/Pasted%20image%2020260111103752.png)main函数有一个read两个printf
之前都是自己调用自己，这次是将自己的地址作为参数借用别的函数输出。


本题的主要思路是
“用printf函数读取 read_got 这个地址里存储的值，并按照格式字符串的要求输出”。
所以我们需要几个参数
main_addr:作为发送第一个payload后返回的地址，再次执行main函数
pop_rdi:给 printf 传递第一个参数
format_str:格式化字符串的地址
pop_rsi:给 printf 传递第二个参数
read_got：read_got作为第二个参数
printf_plt:调用printf函数
main_addr：返回地址

也就是正常的ret2libc

exp在下
exp
flag为
```plaintext
flag{75bf2aa7-6f7d-402d-b957-56c8c69a6304}
```
