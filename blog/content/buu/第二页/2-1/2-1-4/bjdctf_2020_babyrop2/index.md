+++
title = "bjdctf_2020_babyrop2"
date = "2026-04-15"
type = "post"
categories = ['BUU']
tags = ['BUU']
draft = false
+++
![Pasted image 20260305191622.png](%E9%99%84%E4%BB%B6/Pasted%20image%2020260305191622.png)
存在一个栈溢出，但要绕过一个canary。
![Pasted image 20260305192514.png](%E9%99%84%E4%BB%B6/Pasted%20image%2020260305192514.png)“gift”：在printf处存在一个格式化字符串漏洞。能输入的限定是%6s。只能传6个字符，其中已经固定了四个“%x$p”(x是一个个位数的数字)一个个数字尝试，当x=6的时候，输出的是我们输入的部分
```python
r.recvuntil("I'll give u some gift to help u!")  
payload = b'A%6$pA'  
r.send(payload)
```
![Pasted image 20260306152843.png](%E9%99%84%E4%BB%B6/Pasted%20image%2020260306152843.png)
所以我们的输入部分偏移是6
接下来看canary的位置：
canary
输入aaaaaa![Pasted image 20260306153746.png](%E9%99%84%E4%BB%B6/Pasted%20image%2020260306153746.png)可以看到aaaaaa存在了rsp的位置，canary在rsp下面8个字节，所以canary的偏移应该是7 。也就是%7$p
![Pasted image 20260306153933.png](%E9%99%84%E4%BB%B6/Pasted%20image%2020260306153933.png)同时也注意到rax的值跟canary是一样的（虽然不知道有什么用）
