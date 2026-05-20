+++
title = "毛毛虫的逆袭"
date = "2026-05-14"
type = "post"
categories = ["ISCC2026"]
tags = ["ISCC2026"]
draft = false
+++

### Reverse + 毛毛虫的逆袭

解题思路：

题目给出的是一个 64 位 Windows 可执行文件，初步分析可以看到其节表中存在 \`UPX0\`、\`UPX1\`、\`UPX2\` 等特征，导入函数也非常少，只有 \`LoadLibraryA\`、\`ExitProcess\`、\`GetProcAddress\`、\`VirtualProtect\` 等典型壳程序接口，因此可以判断该程序使用了 UPX 进行加壳。首先使用 \`upx -d\` 对样本进行脱壳，脱壳后文件体积明显增大，导入表恢复正常，便于后续静态分析。

在脱壳后的程序中，可以从字符串区直接看到输入提示和校验失败提示，确定 flag 格式为 \`ISCC{}\`，其中花括号内部长度为 20 个字符。继续分析主逻辑后发现，程序先检查总长度、前缀和后缀，然后提取中间 20 个字符做进一步校验。这里存在两条分支路径，程序会尝试使用 \`stod\` 将中间字符串转换为 \`double\`，若结果大于 \`5.0\` 则进入 SHA-256 分支，否则进入 LCG 变换分支。由于正常 flag 一般以字母或符号开头，\`stod\` 返回值通常为 \`0.0\`，因此实际利用时会进入 LCG 路径。

LCG 分支中，程序以种子 \`12\` 初始化，随后使用线性同余生成器不断更新状态。每轮从高位取一个字节，再对 \`95\` 取模，得到一个用于可打印字符偏移的密钥字节。然后对输入字符执行变换：先减去 \`0x20\` 映射到可打印字符区间起点，再加上密钥字节取模 \`95\`，最后再加回 \`0x20\`。程序将变换结果与硬编码在 \`.data\` 段中的字符串 \`qwbD/&gt;X|1F2QI.u-fCMm\` 做比较，因此只需要逆向执行这个过程即可恢复原始输入。

根据同余生成器参数逐位算出 20 个密钥字节后，对目标字符串逆向减去偏移并取模恢复，即可得到花括号内部内容，最终拼接出完整 flag。需要注意的是本题结果中包含反斜杠和空格，这些字符本身就是合法内容，不是输入错误。

Exp：

\`\`\`python

seed = 12

multiplier = 0x41c64e6d

increment = 0x3039

expected = 'qwbD/&gt;X|1F2QI.u-fCMm'

keys = \[\]

state = seed

for \_ in range(20):

state = (state \* multiplier + increment) & 0xFFFFFFFF

high\_byte = (state &gt;&gt; 24) & 0xFF

keys.append(high\_byte % 95)

flag\_inner = ''

for ch, key in zip(expected, keys):

val\_out = ord(ch) - 0x20

val\_in = (val\_out - key) % 95

flag\_inner += chr(val\_in + 0x20)

print(f'ISCC{{{flag\_inner}}}')

\`\`\`

Flag：

\`ISCC{\\BtcuL2P!O\]CrZxl=g t}\`
