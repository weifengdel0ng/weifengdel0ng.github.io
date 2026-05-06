+++
title = "Dual Protection"
date = "2026-05-04"
type = "post"
categories = ["ISCC2026"]
tags = ["ISCC2026"]
draft = false
+++
# Dual Protection WP

  

## 题目信息

  

- 题目文件：`Dual Protection.exe`

- flag 格式：`ISCC{}`

  

## 一、程序基本行为

  

程序运行后会提示输入：

  

```text

Input Flag:

```

  

输入后只会输出两种结果：

  

```text

Correct.

Wrong.

```

  

通过字符串可以直接看到：

  

- `Input Flag:`

- `%36s`

- `Correct.`

- `Wrong.`

  

其中 `%36s` 已经暗示输入长度和 `36` 很相关。

  

---

  

## 二、主逻辑分析

  

主逻辑位于 `0x401100` 附近，核心流程可以还原为：

  

```c

memset(buf, 0, 0x63);

printf("Input Flag: ");

scanf("%36s", buf);

  

if (strlen(buf) != 0x24) {

    return fail;

}

  

for (i = 0; i < 0x24; i++) {

    sub_401000(buf, i);

    sub_401050(buf, i);

    sub_4010D0(buf, i);

}

  

seed = 0xdeadbeef;

if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &debugged) && debugged) {

    seed = 0x0badf00d;

}

  

code = VirtualAlloc(0, 0x118, 0x3000, 0x40);

memcpy(code, enc_blob, 0x118);

  

for (i = 0; i < 0x118; i++) {

    seed = seed * 0x19660d + 0x3c6ef35f;

    code[i] ^= (seed >> 24) & 0xff;

}

  

ok = code(buf);

  

puts(ok ? "Correct." : "Wrong.");

system("pause");

```

  

可以看出程序有两层保护：

  

1. 先对输入做三轮逐字节变换。

2. 再动态解密一段真正的校验代码。

  

---

  

## 三、长度检查

  

程序手动计算输入长度，随后比较：

  

```c

if (strlen(buf) != 0x24)

```

  

因此输入长度必须为：

  

```text

0x24 = 36

```

  

---

  

## 四、第一层保护：三轮逐字节变换

  

### 1. `sub_401000`

  

位于 `0x401000`，逻辑如下：

  

```c

b = buf[i];

b ^= 0x55;

b = rol8(b, 2);

b = (b + i) & 0xff;

buf[i] = b;

```

  

---

  

### 2. `sub_401050`

  

位于 `0x401050`，函数内部构造了一个 8 字节数组：

  

```c

key = [0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF];

```

  

逻辑如下：

  

```c

b = buf[i];

b ^= key[i % 8];

b = (b + 0x7f) & 0xff;

buf[i] = b;

```

  

---

  

### 3. `sub_4010D0`

  

位于 `0x4010D0`，逻辑如下：

  

```c

b = buf[i];

b ^= ((i + 0x20) & 0xff);

buf[i] = b;

```

  

---

  

### 4. 合并后的正向变换

  

对每个字符 `buf[i]`，整体变换为：

  

```c

b = buf[i];

b = rol8(b ^ 0x55, 2);

b = (b + i) & 0xff;

b = b ^ key[i % 8];

b = (b + 0x7f) & 0xff;

b = b ^ ((i + 0x20) & 0xff);

buf[i] = b;

```

  

---

  

## 五、第二层保护：动态解密 + 双重反调试

  

程序把数据区中的 `0x118` 字节拷贝到新申请的可执行内存，然后进行解密：

  

```c

seed = 0xdeadbeef;

for (i = 0; i < 0x118; i++) {

    seed = (seed * 0x19660d + 0x3c6ef35f) & 0xffffffff;

    code[i] ^= (seed >> 24) & 0xff;

}

```

  

但是在此之前程序调用了：

  

```c

CheckRemoteDebuggerPresent(GetCurrentProcess(), &debugged)

```

  

如果检测到调试器，则把种子改成：

  

```c

0x0badf00d

```

  

这样解密结果就会完全不同。

  

此外，解密出的代码内部还会读取：

  

```c

fs:[0x30]

```

  

也就是 PEB，再检查 `BeingDebugged` 标志。  

因此这题存在双重反调试：

  

1. `CheckRemoteDebuggerPresent`

2. `PEB->BeingDebugged`

  

如果直接挂调试器分析，解密出的校验逻辑会被故意破坏。

  

---

  

## 六、解密后真实校验逻辑

  

把动态解密出来的 `0x118` 字节代码反汇编后，可以发现它本质上只是逐字节比较输入缓冲区和一个固定常量数组。

  

常量数组为：

  

```python

const = [

    0xC1, 0x8D, 0xA9, 0x81, 0x8F, 0x88, 0xFB, 0xE5,

    0x4A, 0xF1, 0xB5, 0x38, 0x80, 0xDD, 0x67, 0x89,

    0x3E, 0xC9, 0xC9, 0x89, 0x3B, 0x80, 0x2C, 0xF5,

    0x6E, 0xFD, 0x7D, 0x21, 0x5F, 0x80, 0xFC, 0xA9,

    0x72, 0xFC, 0x82, 0x79

]

```

  

等价伪代码如下：

  

```c

ok = 1;

for (i = 0; i < 36; i++) {

    if (buf[i] != const[i]) {

        ok = 0;

    }

}

return ok;

```

  

因此题目本质上就是：

  

1. 输入必须长度为 36。

2. 输入经过三轮变换后必须等于 `const` 数组。

  

---

  

## 七、逆向还原输入

  

正向变换为：

  

```c

b = rol8(b ^ 0x55, 2);

b = (b + i) & 0xff;

b = b ^ key[i % 8];

b = (b + 0x7f) & 0xff;

b = b ^ ((i + 0x20) & 0xff);

```

  

那么逆向时按相反顺序恢复：

  

```c

b = b ^ ((i + 0x20) & 0xff);

b = (b - 0x7f) & 0xff;

b = b ^ key[i % 8];

b = (b - i) & 0xff;

b = ror8(b, 2) ^ 0x55;

```

  

---

  

## 八、解题脚本

  

```python

const = [

    0xC1, 0x8D, 0xA9, 0x81, 0x8F, 0x88, 0xFB, 0xE5,

    0x4A, 0xF1, 0xB5, 0x38, 0x80, 0xDD, 0x67, 0x89,

    0x3E, 0xC9, 0xC9, 0x89, 0x3B, 0x80, 0x2C, 0xF5,

    0x6E, 0xFD, 0x7D, 0x21, 0x5F, 0x80, 0xFC, 0xA9,

    0x72, 0xFC, 0x82, 0x79

]

  

key = [0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF]

  

def ror8(x, n):

    return ((x >> n) | ((x << (8 - n)) & 0xff)) & 0xff

  

flag = []

for i, c in enumerate(const):

    x = c ^ ((i + 0x20) & 0xff)

    x = (x - 0x7f) & 0xff

    x ^= key[i % 8]

    x = (x - i) & 0xff

    x = ror8(x, 2) ^ 0x55

    flag.append(chr(x))

  

print(''.join(flag))

```

  

运行结果：

  

```text

ISCC{u6</LN-9&+;6ZSYnwE0>CtgCKI#5/(}

```

  

---

  

## 九、验证

  

将结果输入程序，输出：

  

```text

Correct.

```

  

说明恢复出的输入正确。

  

---

  

## 十、最终 flag

  

```text

ISCC{u6</LN-9&+;6ZSYnwE0>CtgCKI#5/(}

```

  

---

  

## 十一、简要总结

  

这题的关键点有三个：

  

1. 输入长度固定为 `36`。

2. 输入先经过三轮字节级变换。

3. 真正的校验逻辑被动态解密，并且夹带双重反调试。

  

虽然外层看起来比较复杂，但本质上最终仍然只是“变换后与常量比较”。  

因此只要把动态解密出的比较逻辑提出来，再逆变换恢复原始输入，即可拿到 flag。
## 附件下载

- [Dual Protection.zip](dual-protection.zip)

