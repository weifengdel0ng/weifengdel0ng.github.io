+++
title = "双校区来信"
date = "2026-05-06"
type = "post"
categories = ["ISCC2026"]
tags = ["ISCC2026"]
draft = false
+++
**完整 WP**

这题按你给的思路，核心链路是：

`ZIP 伪加密 -> 修标志位 -> 解出 task.mp4 -> 提取 audio.wav -> Echo Hiding 解码 -> Morse -> Atbash -> ISCC{...}`

这份新附件最终跑出的结果是：

```text
ISCC{GNU6+/W0KKF2(B/}
```

---

**1. 识别 ZIP 伪加密**

附件是 [attachment-4 (1).zip](</C:/Users/ericgao/Desktop/test/attachment-4 (1).zip>)。  
它不是“真加密”，而是 ZIP 头里的加密标志位被置了。

我检查到：

- 本地文件头 `PK\x03\x04` 的加密位是正常的
- 中央目录头 `PK\x01\x02` 的加密位被置成了 `1`

这会导致很多解压工具误以为它需要密码。

修法就是把这两个位置的最低位清零：

- 本地文件头：偏移 `+6`
- 中央目录头：偏移 `+8`

可用代码：

```python
from pathlib import Path

def clear_zip_fake_encrypt(src: Path, dst: Path) -> None:
    data = bytearray(src.read_bytes())

    i = 0
    while True:
        j = data.find(b'PK\x03\x04', i)
        if j < 0:
            break
        data[j + 6] &= 0xFE
        i = j + 4

    i = 0
    while True:
        j = data.find(b'PK\x01\x02', i)
        if j < 0:
            break
        data[j + 8] &= 0xFE
        i = j + 4

    dst.write_bytes(data)
```

修完后就能正常解压，里面只有一个 `task.mp4`。

---

**2. 从 MP4 提取音频**

直接用 `ffmpeg` 抽出 PCM：

```bash
ffmpeg -y -i task.mp4 -vn -acodec pcm_s16le audio.wav
```

我实际提取到的是：

- 采样率：`44100 Hz`
- 双声道
- `int16`
- 长度约 `1764352` 个采样点

---

**3. Echo Hiding 解码**

题目真正的信息不在画面，而在音频回声隐写里。

按你给的 wp 参数：

- 段长 `ws = 2205`
- `d0 = 100`
- `d1 = 130`

处理方式：

- 左右声道取平均
- 每 `2205` 个采样切一段
- 对每段做倒谱
- 比较 `100` 附近和 `130` 附近哪个峰更高
- 高者对应 `0/1`

代码如下：

```python
import numpy as np
import scipy.io.wavfile as wav
from pathlib import Path

def echo_decode(audio: Path, ws: int = 2205, d0: int = 100, d1: int = 130):
    sr, x = wav.read(audio)

    if x.ndim == 2 and x.shape[1] == 2:
        sig = (x[:, 0].astype(np.float64) + x[:, 1].astype(np.float64)) / 2.0
    else:
        sig = x.astype(np.float64)

    bits = []
    for off in range(0, len(sig) - ws + 1, ws):
        seg = sig[off:off + ws]
        seg = seg - seg.mean()

        cep = np.fft.irfft(np.log(np.abs(np.fft.rfft(seg)) ** 2 + 1e-10))
        p0 = float(np.max(cep[max(1, d0 - 2):d0 + 3]))
        p1 = float(np.max(cep[max(1, d1 - 2):d1 + 3]))

        bits.append(0 if p0 > p1 else 1)

    return bits
```

这份附件跑出来：

- 比特数：`800`

---

**4. 比特流转 ASCII / Morse**

把比特按 8 位一组还原成字节：

```python
def bits_to_raw(bits):
    return bytes(
        int(''.join(map(str, bits[i:i + 8])), 2)
        for i in range(0, len(bits) - 7, 8)
    )
```

题目里前面一段是纯 Morse 字符集，只包含：

- `.`
- `-`
- 空格
- `/`

所以直接截到第一个非法字符前：

```python
def extract_morse_prefix(raw: bytes) -> str:
    end = 0
    while end < len(raw) and raw[end] in b'.- /':
        end += 1
    return raw[:end].decode('ascii')
```

这份附件得到的 Morse 串是：

```text
- -- ..-. -.... .-.-. -..-. -.. ----- .--. .--. ..- ..--- -.--. -.-- -..-.
```

---

**5. Morse 解码**

需要完整 Morse 表，尤其注意 `.-... -> &` 这一项有时会坑人。  
不过这份附件实际没用到 `&`，但字典还是建议补全。

```python
MORSE = {
    '.-':'A','-...':'B','-.-.':'C','-..':'D','.':'E','..-.':'F','--.':'G',
    '....':'H','..':'I','.---':'J','-.-':'K','.-..':'L','--':'M','-.':'N',
    '---':'O','.--.':'P','--.-':'Q','.-.':'R','...':'S','-':'T','..-':'U',
    '...-':'V','.--':'W','-..-':'X','-.--':'Y','--..':'Z',
    '-----':'0','.----':'1','..---':'2','...--':'3','....-':'4','.....':'5',
    '-....':'6','--...':'7','---..':'8','----.':'9',
    '.-.-.-':'.','--..--':',','..--..':'?','-.-.--':'!','-....-':'-',
    '-..-.':'/','-.--.':'(','-.--.-':')','.----.':"'",'---...':':',
    '-.-.-.':';','.-.-.':'+','-...-':'=','..--.-':'_','.-..-.':'"',
    '...-..-':'$','.--.-.':'@','.-...':'&',
}

def morse_decode(morse: str) -> str:
    return ''.join(MORSE[tok] for tok in morse.split() if tok in MORSE)
```

解出来是：

```text
TMF6+/D0PPU2(Y/
```

---

**6. Atbash**

按 wp 的方式，只对字母做 Atbash，其它字符原样保留：

```python
def atbash_letters_only(s: str) -> str:
    out = []
    for c in s:
        if 'A' <= c <= 'Z':
            out.append(chr(ord('Z') - (ord(c) - ord('A'))))
        elif 'a' <= c <= 'z':
            out.append(chr(ord('z') - (ord(c) - ord('a'))))
        else:
            out.append(c)
    return ''.join(out)
```

对

```text
TMF6+/D0PPU2(Y/
```

做 Atbash 得到：

```text
GNU6+/W0KKF2(B/
```

最后套壳：

```text
ISCC{GNU6+/W0KKF2(B/}
```

---

**7. 一把梭脚本**

```python
from __future__ import annotations
from pathlib import Path
import shutil
import zipfile
import tempfile
import subprocess
import numpy as np
import scipy.io.wavfile as wav

MORSE = {
    '.-':'A','-...':'B','-.-.':'C','-..':'D','.':'E','..-.':'F','--.':'G',
    '....':'H','..':'I','.---':'J','-.-':'K','.-..':'L','--':'M','-.':'N',
    '---':'O','.--.':'P','--.-':'Q','.-.':'R','...':'S','-':'T','..-':'U',
    '...-':'V','.--':'W','-..-':'X','-.--':'Y','--..':'Z',
    '-----':'0','.----':'1','..---':'2','...--':'3','....-':'4','.....':'5',
    '-....':'6','--...':'7','---..':'8','----.':'9',
    '.-.-.-':'.','--..--':',','..--..':'?','-.-.--':'!','-....-':'-',
    '-..-.':'/','-.--.':'(','-.--.-':')','.----.':"'",'---...':':',
    '-.-.-.':';','.-.-.':'+','-...-':'=','..--.-':'_','.-..-.':'"',
    '...-..-':'$','.--.-.':'@','.-...':'&',
}

FFMPEG = r"C:\Users\ericgao\AppData\Local\Programs\Python\Python313\Lib\site-packages\imageio_ffmpeg\binaries\ffmpeg-win-x86_64-v7.1.exe"

def clear_zip_fake_encrypt(src: Path, dst: Path) -> None:
    data = bytearray(src.read_bytes())

    i = 0
    while True:
        j = data.find(b'PK\x03\x04', i)
        if j < 0:
            break
        data[j + 6] &= 0xFE
        i = j + 4

    i = 0
    while True:
        j = data.find(b'PK\x01\x02', i)
        if j < 0:
            break
        data[j + 8] &= 0xFE
        i = j + 4

    dst.write_bytes(data)

def extract_audio(zip_path: Path, outdir: Path) -> Path:
    fixed_zip = outdir / "fixed.zip"
    mp4 = outdir / "task.mp4"
    audio = outdir / "audio.wav"

    clear_zip_fake_encrypt(zip_path, fixed_zip)

    with zipfile.ZipFile(fixed_zip) as zf:
        with zf.open("task.mp4") as src, open(mp4, "wb") as dst:
            shutil.copyfileobj(src, dst)

    subprocess.run(
        [FFMPEG, "-y", "-v", "error", "-i", str(mp4), "-vn", "-acodec", "pcm_s16le", str(audio)],
        check=True,
    )
    return audio

def echo_decode(audio: Path, ws: int = 2205, d0: int = 100, d1: int = 130):
    sr, x = wav.read(audio)

    if x.ndim == 2 and x.shape[1] == 2:
        sig = (x[:, 0].astype(np.float64) + x[:, 1].astype(np.float64)) / 2.0
    else:
        sig = x.astype(np.float64)

    bits = []
    for off in range(0, len(sig) - ws + 1, ws):
        seg = sig[off:off + ws]
        seg = seg - seg.mean()

        cep = np.fft.irfft(np.log(np.abs(np.fft.rfft(seg)) ** 2 + 1e-10))
        p0 = float(np.max(cep[max(1, d0 - 2):d0 + 3]))
        p1 = float(np.max(cep[max(1, d1 - 2):d1 + 3]))

        bits.append(0 if p0 > p1 else 1)

    return bits

def bits_to_morse(bits):
    raw = bytes(
        int(''.join(map(str, bits[i:i + 8])), 2)
        for i in range(0, len(bits) - 7, 8)
    )

    end = 0
    while end < len(raw) and raw[end] in b'.- /':
        end += 1

    return raw[:end].decode("ascii")

def morse_decode(morse: str) -> str:
    return ''.join(MORSE[tok] for tok in morse.split() if tok in MORSE)

def atbash_letters_only(s: str) -> str:
    out = []
    for c in s:
        if 'A' <= c <= 'Z':
            out.append(chr(ord('Z') - (ord(c) - ord('A'))))
        elif 'a' <= c <= 'z':
            out.append(chr(ord('z') - (ord(c) - ord('a'))))
        else:
            out.append(c)
    return ''.join(out)

def solve_one(zip_path: Path) -> str:
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        audio = extract_audio(zip_path, td)
        bits = echo_decode(audio)
        morse = bits_to_morse(bits)
        decoded = morse_decode(morse)
        body = atbash_letters_only(decoded)
        return f"ISCC{{{body}}}"

if __name__ == "__main__":
    zip_path = Path(r"C:\Users\ericgao\Desktop\test\attachment-4 (1).zip")
    print(solve_one(zip_path))
```

---

**8. 最终答案**

```text
ISCC{GNU6+/W0KKF2(B/}
```
