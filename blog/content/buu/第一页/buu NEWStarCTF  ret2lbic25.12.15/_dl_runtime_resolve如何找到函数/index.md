+++
title = "_dl_runtime_resolve如何找到函数"
date = "2026-03-04"
type = "post"
categories = ['BUU']
tags = ['第一页', 'buu NEWStarCTF  ret2lbic25.12.15']
draft = false
+++
在想要调用的函数没有被调用过，想要调用他的时候，是按照这个过程来调用的

xxx@plt -> xxx@got -> xxx@plt -> 公共 @plt -> _dl_runtime_resolve

到这里我们还需要知道

> _dl_runtime_resolve 是怎么知道要查找 printf 函数的
> 
> _dl_runtime_resolve 找到 printf 函数地址之后，它怎么知道回填到哪个 GOT 表项

  

第一个问题，在 xxx@plt 中，我们在 jmp 之前 push 了一个参数，每个 xxx@plt 的 push 的操作数都不一样，那个参数就相当于函数的 id，告诉了 _dl_runtime_resolve 要去找哪一个函数的地址
第一次调用时需要改地址
![640.webp](ret2libc25.12.11%E9%99%84%E4%BB%B6/640.webp)
第二次可以直接调用
![640 2.webp](ret2libc25.12.11%E9%99%84%E4%BB%B6/640%202.webp)
