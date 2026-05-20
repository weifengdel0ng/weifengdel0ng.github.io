+++
title = "密码验证"
date = "2026-05-14"
type = "post"
categories = ["ISCC2026"]
tags = ["ISCC2026"]
draft = false
+++

Mobile + 密码验证

解题思路：

题目给了一个 APK，Java 层会先检查 flag 的基础格式，然后调用 NativeBridge.verifyFlag(AssetManager, String) 进入 JNI 做真正校验。先从 Java 层入手，确认输入必须满足三个条件：总长度为 36，以 ISCC{ 开头，以 } 结尾。这样可以把中间 payload 固定为 30 字节，并继续拆成三段：A = flag[5:13]，长度 8；B = flag[13:25]，长度 12；C = flag[25:35]，长度 10。后续 native 逻辑就是围绕这三段分别做约束。

继续逆向 so，可以提取出 assets 中参与校验的四个文件：cipher1.bin、cipher2.bin、cipher3.bin 和 puzzle.bin。它们的内容分别为：cipher1.bin = EF559B79F2FD3744，cipher2.bin = BB6D440A8FD96CECE488F805，cipher3.bin = 919895338D222586BFAA，puzzle.bin = 1AB3A449DEF0FA4E083909404B44553DC024F74E。native 中还存在一张字符表：0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz{}_-!@\#\$%\^&*()[]&lt;&gt;?.,:;+\\/。另外有三组经过 ((b - 0x13) & 0xff) \^ 0x5a 还原后的常量：r1 = 1a2b3c4d5e6f708192a3b4c5d6e7f809，r2 = 01000000000100000000010000000001，r3 = aabbccdd11223344556677889900feed。

分析 helper 函数后，可以把 JNI 里的核心流程概括出来。2a3d0 会先把前 16 字节和第二个向量异或，再整体左旋 3 字节；2a5f0 是 4x4 GF(256) 矩阵乘，再做行重排 [2,3,0,1]；2a890 的逻辑是 dst[i] = sbox[a[i] \^ b[i] \^ c[i]]，然后做前缀异或；2aa20 是 16 轮 TEA 加密；2ab10 是把 12 字节按 3 组分别做 GF(256) 线性变换；2ad90 是一个 LCG 伪随机字节流；2b080 则会对输入向量聚合成 (xor_all, sum_all mod 256)。其中 GF(256) 乘法使用的就是 AES 常见的 0x1b 模多项式乘法。

先根据前置常量计算中间状态。对 r1 和 r3 做异或并经过 2a3d0 后，可得 v128 = rotl3(r1 \^ r3) = 904f4d43c5c7c5c34d4fe706e4b090f0。然后执行 2a5f0(v128, r2)，得到 v140 = 4d4fe706e4b090f0904f4d43c5c7c5c3。再执行 2a890(v128, v140, r3)，得到 v158 = f51f2c6a6e92a15490a362dfb3462439。后面三段的求解都依赖这三个中间量。

第一段 A 的逻辑是：先将 A 与 v158[1:9] 异或，再按大端形式送入 TEA，加密结果需要等于 cipher1.bin。逆向求解时直接对 cipher1.bin 做 TEA 解密，密钥为 v128，可得 TEA\^-1(cipher1, key=v128) = 78750d07e4e57bbb。于是 A = 78750d07e4e57bbb \^ v158[1:9] = 6759676976442f2b，转成字符串就是 gYgivD/+。除此之外，puzzle.bin 还提供了一层线性约束：puzzle[0:16] 可视作一个 4x4 GF(256) 矩阵，puzzle[16:20] 是目标值，要求 GF_MAT(puzzle[0:16], A[0:4]) == puzzle[16:20]。带入前四字节验证后完全成立，因此 A 可以确认无误。

第二段 B 会被拆成 3 个 4 字节分组。2ab10 的逻辑是对每组 4 字节都乘同一个 4x4 GF(256) 矩阵，矩阵来自 v140，最终 12 字节输出需要等于 cipher2.bin。因此只需要对这个矩阵求逆，再对 cipher2.bin 按组逆变换即可。由 v140 写出的矩阵为 M = [[77,79,231,6],[228,176,144,240],[144,79,77,67],[197,199,197,195]]。逐组逆解后得到 B = mTM}ExODAs&gt;b。native 中还额外检查了 B[0]，这个字符不是独立加密出来的，而是由 A 的聚合值得到：先算 xor_all(A) = 0x06，再做 8 位左旋 3 位得到 0x30，最后取字符表第 0x30 % 88 项，恰好是字符 m，与上面的结果一致。

第三段 C 是最容易看错的部分。这里 PRNG 的 seed 并不是来自 A，而是直接来自 v158 的前 8 字节，也就是 seed = 0xf51f2c6a6e92a154。将这个值送入 2ad90 生成 10 字节伪随机流，可得 prng = fbb1a36abe6746c4e3f0。native 里对 C 的主校验关系其实非常直接：C = cipher3 \^ prng。代入计算后得到 C = 6a293659334563425c5a，对应字符串 j)6Y3EcB\\Z。也就是说，第三段本身就应当是 j)6Y3EcB\\Z，其中第 9 个字符是字面量反斜杠。前 8 个字节来自异或恢复，而最后 2 个字节还能被附加聚合校验再次验证：对 A+B 计算 xor_all 得 0x57，sum_all & 0xff 得 0xd3，再映射字符表分别得到 '\\' 和 'Z'，正好对应 C[8] 和 C[9]。

到这里三段已经全部恢复完成：A = gYgivD/+，B = mTM}ExODAs&gt;b，C = j)6Y3EcB\\Z。将三段顺序拼接，得到 payload = gYgivD/+mTM}ExODAs&gt;bj)6Y3EcB\\Z，最终 flag 为 ISCC{gYgivD/+mTM}ExODAs&gt;bj)6Y3EcB\\Z}。

实际测试时如果直接用 adb input text 往模拟器里灌字符串，可能会出现“格式错误”的提示，这并不能说明 native 校验失败。原因是这题的 flag 中包含两个容易影响输入的特殊字符：一个是 }，另一个是反斜杠 \\。在一些模拟器环境中，这两个字符会被 adb input text 吞掉、错误转义，或者导致整段文本被拆坏。这样 Java 层看到的字符串长度就已经不等于 36，于是会在进入 JNI 前直接报“格式错误”。因此这题判断 flag 是否正确，不能依赖模拟器输入框现象，必须以 native 校验逻辑本身为准。

综上，这题的校验链可以概括为：A 段通过 TEA 与 v158 掩码恢复，并受 puzzle.bin 的 GF(256) 线性约束验证；B 段通过 4x4 GF(256) 线性变换逆求；C 段通过以 v158[:8] 为种子的 PRNG 与 cipher3 异或恢复，同时再由 A+B 的聚合值验证尾部两个字符。最终正确 flag 为：

ISCC{gYgivD/+mTM}ExODAs&gt;bj)6Y3EcB\\Z}

总结一下：

1\. 提取并还原常量 r1、r2、r3。

2\. 计算 v128 = rotl3(r1 \^ r3)。

3\. 计算 v140 = 2a5f0(v128, r2)。

4\. 计算 v158 = 2a890(v128, v140, r3)。

5\. 用 key = v128 对 cipher1.bin 做 TEA 解密，再与 v158[1:9] 异或，得到 A = gYgivD/+。

6\. 用 v140 对应的 GF(256) 4x4 矩阵求逆，逐组逆推出 B = mTM}ExODAs&gt;b。

7\. 以 seed = v158[:8] 初始化 2ad90，生成 10 字节伪随机流，与 cipher3.bin 异或，得到 C = j)6Y3EcB\\Z。

8\. 拼接 flag：ISCC{gYgivD/+mTM}ExODAs&gt;bj)6Y3EcB\\Z}。

Exp：
