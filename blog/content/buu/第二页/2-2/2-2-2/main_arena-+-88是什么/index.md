+++
title = "main_arena + 88是什么"
date = "2026-04-01"
type = "post"
categories = ['BUU']
tags = ['BUU']
draft = false
+++
这是一个非常经典的 **堆利用（Heap Exploitation）** 场景，你正在利用 **unsorted bin 泄露 libc 地址**。我们来详细解释为什么 `dump(2)` 会泄露 `main_arena + 88`（即 `main_arena88`）。

---

### 🔍 背景：unsorted bin 与 main_arena 的关系

在 glibc 的 malloc 实现中：

- 当你 `free` 一个 **不是 fastbin 大小**（通常 ≥ 0x90 字节，含 chunk header）的 chunk 时，它会被放入 **unsorted bin**。
- **unsorted bin 是一个双向循环链表**，其头节点（`fd` 和 `bk` 指针）就位于 `main_arena` 结构体内部。
- 具体来说，`main_arena.unsorted_bins[0]` 的地址就是 `&main_arena + 0x58`（在 64 位系统上）。
- 当 unsorted bin 中只有一个 chunk 时：
    - 该 chunk 的 `bk` 指针会指向 `main_arena + 0x58`（即 unsorted bin 的头部）。
    - 而 `main_arena + 0x58` 距离 `main_arena` 起始地址偏移为 **0x58 = 88** 字节。

> ✅ 所以：**被 free 到 unsorted bin 的 chunk 的 `bk` 字段 = `main_arena + 88`**

---

### 🧩 你的利用步骤解析

我们一步步看你的代码如何构造出这个泄露：

```python
alloc(0x10)  # chunk0
alloc(0x10)  # chunk1
alloc(0x10)  # chunk2
alloc(0x10)  # chunk3
alloc(0x80)  # chunk4 （实际 size=0x90，含 header）
```

> 注意：`alloc(0x80)` 分配的是 **0x80 字节用户数据**，对应 chunk size 为 `0x80 + 0x10 = 0x90`（因为有 0x10 字节 header）。

```python
free(1)  # free chunk1 (size=0x20 → fastbin)
free(2)  # free chunk2 (size=0x20 → fastbin)
```

→ chunk1 和 chunk2 进入 fastbin（不会进 unsorted bin）。

---

#### ⚠️ 关键：堆块重叠（overlap）构造 fake chunk

```python
payload = p64(0)*3 + p64(0x21) + p64(0)*3 + p64(0x21) + p8(0x80)
fill(0, len(payload), payload)
```

- 你在 **chunk0** 中伪造了两个 fake chunk：
    - 第一个 fake chunk：size=0x21（对应 0x10 用户数据）
    - 第二个 fake chunk：size=0x21
    - 最后一个字节 `p8(0x80)` 是为了后面 overflow 用（其实是写到 chunk1 的 prev_size）

然后：

```python
payload = p64(0)*3 + p64(0x21)
fill(3, len(payload), payload)
```

- 修改 chunk3 的内容，可能是为了清理或防止合并。

---

#### 🎯 触发 overlap，让 chunk4 被“提前”释放

```python
alloc(0x10)  # alloc chunk1 back (from fastbin)
alloc(0x10)  # alloc chunk2 back
```

→ 现在 chunk1 和 chunk2 被重新分配，但它们的内容已被你控制。

接着：

```python
payload = p64(0)*3 + p64(0x91)
fill(3, len(payload), payload)
```

- 你在 **chunk3** 中伪造了一个 size=0x91 的 chunk header。
- 此时，如果你 `free(chunk4)`，glibc 会检查前一个 chunk 是否空闲（通过 `PREV_INUSE` 位）。
- 但更重要的是：**你可能通过某种方式让 chunk4 被当作一个更大的 chunk 的一部分被释放**。

不过更关键的是下一步：

```python
alloc(0x80)  # 再次分配一个 0x80 的 chunk（可能是 chunk5？）
free(4)      # free 原来的 chunk4（size=0x90）
```

→ **`free(4)` 释放了一个 0x90 大小的 chunk**，这 **大于 fastbin 范围**（fastbin 最大 0x80 用户数据，即 size=0x90 含 header 通常是 smallbin/unsorted bin 范围，具体看版本）。

> 在大多数 glibc 版本中，**size ≥ 0x90（含 header）的 chunk 被 free 时会进入 unsorted bin**。

所以：**chunk4 被放入 unsorted bin**，它的 `fd` 和 `bk` 被写入 `main_arena + 88`。

---

#### 💥 为什么 dump(2) 能读到 main_arena + 88？

关键在于：**你通过堆布局，让 chunk2 和 chunk4 发生了重叠（overlap）！**

回顾：

- 你之前 `free(1)` 和 `free(2)`，然后通过 `fill(0, ...)` 在 chunk0 中伪造了 fake chunk。
- 接着 `alloc(0x10)` 两次，把 chunk1 和 chunk2 重新拿回来。
- 但你可能通过溢出（比如在 chunk3 写 0x91）让后续的 `free(4)` 导致 **内存布局错乱**，使得 **chunk2 的内存区域现在正好覆盖了 chunk4 的 chunk header 或 data 区域**。

更可能的情况是：

- 你构造了一个 **fake chunk 起始于 chunk2 的位置**，并且这个 fake chunk 被当作 unsorted bin 中的 chunk。
- 或者：**chunk2 的数据区现在正好是 chunk4 被 free 后的 unsorted bin chunk 的 `bk` 字段所在位置**。

于是：

```python
dump(2)  # 读取 chunk2 的内容
```

→ 返回的数据中包含了 **unsorted bin chunk 的 `bk` 指针**，即 `main_arena + 88`。

你通过：

```python
mainarena88 = u64(p.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00'))
```

成功提取出这个地址（因为 libc 地址高字节是 `0x7f...`，所以用 `\x7f` 定位）。

---

### ✅ 总结：为什么 dump(2) = main_arena + 88？

|原因|说明|
|---|---|
|**1. chunk4 被 free 到 unsorted bin**|因为其 size=0x90，进入 unsorted bin|
|**2. unsorted bin 的 bk 指向 main_arena + 88**|这是 glibc 的固定结构（偏移 0x58 = 88）|
|**3. 堆布局导致 chunk2 与 chunk4 重叠**|通过 fake chunk 和溢出，使 chunk2 的数据区覆盖了 chunk4 的 metadata 或 data|
|**4. dump(2) 读取了 chunk2 的内容**|实际读到了 chunk4 的 `bk` 字段 → `main_arena + 88`|

---

### 🔒 补充：main_arena + 88 是什么？

在 glibc 源码中（64 位）：

```c
struct malloc_state {
  /* ... */
  malloc_chunk* top;
  malloc_chunk* last_remainder;
  mchunkptr bins[NBINS * 2 - 2];  // unsorted bin 是 bins[0] 和 bins[1]
  ...
};
```

- `bins[0]`（即 unsorted bin 的 fd）位于 `&main_arena + 0x58`
- `bins[1]`（即 unsorted bin 的 bk）也从同一位置开始（因为是双向链表）
- 所以：**unsorted bin 中 chunk 的 `bk` = `&main_arena + 0x58 = main_arena + 88**

---

### ✅ 后续利用逻辑正确吗？

你的后续步骤：

```python
malloc_hook = mainarena - 0x10
```

→ 这是基于 **旧版 glibc（如 2.23）** 的偏移。在 glibc 2.23 中：

- `main_arena` 距离 `__malloc_hook` 通常是 **+0x10**，所以 `__malloc_hook = main_arena - 0x10` 是对的。

然后你用 `LibcSearcher` 自动找 libc 版本，再写 `__malloc_hook - 35`（one_gadget 常见偏移），最后触发 `alloc(1)` 调用 malloc，执行 system。

✅ 整体思路是标准的 **unsorted bin leak + malloc_hook hijack**。

---

如果你有具体的 libc 版本或题目名称，我可以进一步验证偏移是否准确。希望这个解释帮你彻底理解了 `dump(2)` 为何能泄露 `main_arena + 88`！
