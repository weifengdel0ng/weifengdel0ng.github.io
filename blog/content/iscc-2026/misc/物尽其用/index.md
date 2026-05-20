+++
title = "物尽其用"
date = "2026-05-17"
type = "post"
categories = ["ISCC2026"]
tags = ["ISCC2026"]
draft = false
+++

Misc-物尽其用

# 解题思路

## 1. 附件结构与初步观察

题目附件 `TrainModel.zip` 解压后包含四个文件：

```
config.json
Input.png
model_state.npz
train.exe
```

先检查 `config.json`，内容为训练参数与两个回调开关：

```json
{
  "training": {
    "epochs": 10,
    "batch_size": 1,
    "lr": 0.001
  },
  "callbacks": {
    "aux_log_enabled": false,
    "recovery_enabled": false
  }
}
```

配置文件本身没有直接藏 flag，但暴露了程序内部存在"训练+回调"机制，且 `aux_log_enabled` 与 `recovery_enabled` 两个布尔开关可控制运行时行为。

## 2. 从 model_state.npz 获取核心提示

`model_state.npz` 是一个 NumPy 存档，加载后发现其中包含若干关键数组：

| 字段名 | 形状 | 说明 |
|--------|------|------|
| base_hint_bytes | (56,) uint8 | 编码后的提示文本 |
| base_aux_meta | (6,) uint8 | 解码方式标识 |
| base_conv1_weight | (8,1,3,3) float32 | 卷积层权重 |
| base_fc1_weight | (16,72) float32 | 全连接层权重 |
| obs_raw | (128,) uint8 | 原始观测数据 |
| obs_trans | (128,) uint8 | 变换后观测数据 |
| stat_vec | (6,) float32 | 统计向量 |

其中 `base_aux_meta` 的原始字节为 `[98, 54, 52, 43, 103, 122]`，解码后得到字符串 `b64+gz`，这是一个编码提示——先 Base64 解码，再 gzip 解压。

按照此提示处理 `base_hint_bytes`，得到核心提示：

```
ISCC{MD5(flag1R||flag2G)}
```

这直接指明了最终目标：不是从附件直接提取完整 flag，而是先还原 `flag1R` 和 `flag2G` 两段文本，拼接后计算 MD5 哈希，再套上 `ISCC{}` 外壳。其中 `||` 是拼接符号，不参与哈希计算。

## 3. 提取 Input.png 各通道 LSB 隐写数据

`Input.png` 为 512×512 的 RGB 彩色图像。对三个颜色通道分别提取最低有效位（LSB），前 128 比特（16 字节）解码结果如下：

| 通道 | LSB 前 16 字节 | 
|------|---------------|
| R | `ISCC{xBuIbYdngo}` |
| G | `ISCC{nMYykQqnLP}` |
| B | `ISCC{UbRjaKrRIK}` |

三个通道均呈现 `ISCC{...}` 的格式，但提示中只要求 `flag1R` 和 `flag2G` 两段。这意味着不能简单地将三个通道都当作有效载荷：

- `flag1R` 直接取自 R 通道花括号内文本：`xBuIbYdngo`
- G 通道虽然形似答案（`nMYykQqnLP`），但直接使用无法得出正确 MD5——此处是题目的第一个陷阱

## 4. 运行 train.exe 获取行为线索

直接执行 `train.exe`，程序会在当前目录生成 `train.log` 和 `Output.png`。

将 `config.json` 中两个回调开关均设为 `true` 后重新运行，日志出现关键信息：

```
Callbacks config: aux_log_enabled=True, recovery_enabled=True
[AuxMonitor] marker emitted: token{debug_marker_only}
[Monitor] recovery skipped at E05 (cfg_incomplete, code=R05-K37)
Recovery pipeline never applied. Model stays in current state.
[Payload] extracted bytes: R=16 G=16 B=16 (total=128).
```

日志透露出三层关键信息：
1. `token{debug_marker_only}` 仅为调试标记，非有效载荷
2. 程序内部存在 `recovery pipeline`（恢复流水线），但默认未实际执行
3. 当前提取的通道数据处于"未恢复"状态

结合提示要求的 `flag2G` 与日志所述的"恢复未应用"，可以推断：原始图片中的 G 通道数据并非最终参与计算的 `G`，还需经过恢复流程。

## 5. 逆向分析通道映射与扰动逻辑

对 `train.exe` 进行逆向分析后，整理出两条核心恢复规则：

### 5.1 通道重排列

程序恢复后的正常状态会对通道进行重排列，映射关系为：

```
(R, G, B) → (G, B, R)
```

这意味着最终落到 G 位置的，实际上是原始 B 通道的数据。这也是为什么直接取原始 G 通道的 `nMYykQqnLP` 无法计算出正确 flag——它根本不在最终 G 的位置上。

### 5.2 固定种子正文重排

程序仅对花括号内的正文部分进行重排，且使用固定随机种子。各通道种子如下：

| 通道 | 种子值 |
|------|--------|
| R | 863148490 |
| G | 72199925 |
| B | 2239801264 |

对应到 B 通道（即最终 G），使用种子 `2239801264` 对其正文进行 shuffle 恢复：

```
原始 B 正文: U b R j a K r R I K
             ↓ (seed=2239801264 shuffle)
恢复后正文: K R I R j K a b r U
```

验证如下：

- 原始 B 通道 LSB：`ISCC{UbRjaKrRIK}`
- 重排后：`ISCC{KRIRjKabrU}`

## 6. 组合计算最终 Flag

现在两段正文均已还原：

```
flag1R = xBuIbYdngo      （R 通道正文）
flag2G = KRIRjKabrU      （B 通道经恢复后落在 G 位置）
```

按提示拼接并计算 MD5：

```
MD5("xBuIbYdngo" + "KRIRjKabrU")
  = MD5("xBuIbYdngoKRIRjKabrU")
  = fc67aebf3033e144c6e81893dc814e35
```

最终 flag：

```
ISCC{fc67aebf3033e144c6e81893dc814e35}
```

---

# Exp

```python
import base64
import gzip
import hashlib
import zipfile
from io import BytesIO

import numpy as np
from PIL import Image


# 三个通道对应的固定随机种子（从 train.exe 逆向得出）
CH_SEEDS = {"R": 863148490, "G": 72199925, "B": 2239801264}
CH_IDX = {"R": 0, "G": 1, "B": 2}


def lsb_extract(img: Image.Image, ch: int, n_bytes: int = 16) -> bytes:
    """从指定通道提取 LSB 隐写数据"""
    arr = np.array(img.convert("RGB"))
    bits = (arr[:, :, ch] & 1).ravel()[: n_bytes * 8]
    return np.packbits(bits, bitorder="big").tobytes()


def shuffle_body(payload: bytes, seed: int) -> bytes:
    """对 ISCC{...} 花括号内正文做固定种子 shuffle"""
    start = payload.find(b"ISCC{")
    end = payload.find(b"}", start)
    if start < 0 or end < 0:
        return payload

    head = payload[: start + 5]          # ISCC{
    body = np.frombuffer(payload[start + 5 : end], dtype=np.uint8).copy()
    tail = payload[end:]

    order = np.arange(len(body), dtype=np.int64)
    np.random.RandomState(seed).shuffle(order)
    return head + bytes(body[order].tolist()) + tail


def inner(payload: bytes) -> str:
    """提取花括号内正文"""
    s = payload.decode()
    return s[s.index("{") + 1 : s.rindex("}")]


def solve(zip_path: str) -> str:
    with zipfile.ZipFile(zip_path) as zf:
        img = Image.open(BytesIO(zf.read("Input.png")))
        state = np.load(BytesIO(zf.read("model_state.npz")))

    # 解码提示
    hint_raw = bytes(state["base_hint_bytes"])
    hint = gzip.decompress(base64.b64decode(hint_raw)).decode()
    print(f"[Hint] {hint}")

    # 提取三个通道 LSB
    payloads = {ch: lsb_extract(img, CH_IDX[ch]) for ch in ("R", "G", "B")}
    for ch, p in payloads.items():
        print(f"[LSB-{ch}] {p.decode()}")

    # 通道重映射: (R,G,B) -> (G,B,R)，最终 G 来自原始 B
    final_g = shuffle_body(payloads["B"], seed=CH_SEEDS["B"])
    print(f"[Final G] {final_g.decode()}")

    # 取正文并拼接做 MD5
    p1 = inner(payloads["R"])
    p2 = inner(final_g)
    flag = f"ISCC{{{hashlib.md5((p1 + p2).encode()).hexdigest()}}}"

    print(f"flag1R = {p1}")
    print(f"flag2G = {p2}")
    print(f"Flag  = {flag}")
    return flag


if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "TrainModel.zip"
    solve(target)
```

运行结果：

```
[Hint] ISCC{MD5(flag1R||flag2G)}
[LSB-R] ISCC{xBuIbYdngo}
[LSB-G] ISCC{nMYykQqnLP}
[LSB-B] ISCC{UbRjaKrRIK}
[Final G] ISCC{KRIRjKabrU}
flag1R = xBuIbYdngo
flag2G = KRIRjKabrU
Flag  = ISCC{fc67aebf3033e144c6e81893dc814e35}
```

# Flag

```
ISCC{fc67aebf3033e144c6e81893dc814e35}
```
