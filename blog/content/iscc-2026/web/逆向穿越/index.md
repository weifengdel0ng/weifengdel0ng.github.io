+++
title = "逆向穿越"
date = "2026-05-14"
type = "post"
categories = ["ISCC2026"]
tags = ["ISCC2026"]
draft = false
+++

### Web + 逆向穿越

解题思路：

题目是一个基于 Spring Boot 和 Spring Cloud Config Server 的配置服务。首先访问 \`/config/app/dev/master\`，返回了一份 mock 配置，其中明确提示真实敏感信息位于系统根目录下的 \`/app/application.yml\`。结合题目环境可以判断，核心突破点在 Config Server 的路径解析逻辑。

进一步分析发现，题目环境中的 Tomcat 开启了 \`ALLOW\_ENCODED\_SLASH=true\` 和 \`ALLOW\_BACKSLASH=true\` 等危险配置，使得 URL 中的 \`%2f\` 不会在 Tomcat 层被提前标准化。与此同时，Spring Cloud Config 2.2.x 存在 CVE-2020-5410，补丁主要拦截的是 \`..\` 目录穿越形式，但没有禁止以 \`/\` 开头的绝对路径。因此可以构造 \`%2fapp%2fapplication.yml\`，在经过 Spring 的路径变量解码后变成 \`/app/application.yml\`，从而绕过原有 search location 限制，成功读取任意文件。

读取 \`/app/application.yml\` 后，发现管理端点的真实路径是 \`/internal-monitor-xyz123/env\`。访问该接口后可以看到环境变量信息，虽然 \`FLAG\` 被脱敏为 \`\*\*\*\*\*\*\`，但同时泄露了一个关键路径变量 \`SYSTEM\_DIAGNOSTIC\_BACKUP\_DOWNLOAD\_PATH\`，其值指向一个诊断快照下载地址。另外配置中还存在 \`auto-dump: true\`，说明系统开启了自动诊断转储功能。

随后访问该诊断快照下载接口，获得一份 JVM 堆转储文件。由于环境变量中的 FLAG 会以字符串对象形式保存在 Java 堆中，而接口脱敏只发生在 HTTP 响应层，因此堆文件中仍保留了原始 FLAG。最后对下载到的转储文件执行字符串提取，即可直接搜索出目标 FLAG。

本题核心漏洞链为：Config Server 路径穿越 → \`%2f\` 双重解码绕过 → 任意文件读取 → Actuator 信息泄露 → 堆转储提取 FLAG。

Exp：

\`\`\`bash

curl http://39.105.213.28:12602/config/app/dev/%2fapp%2fapplication.yml

curl http://39.105.213.28:12602/internal-monitor-xyz123/env

curl http://39.105.213.28:12602/api/v3/internal/dev/diagnostics/snapshot/8e2f1a4b.dat -o diag.dat

strings diag.dat | grep "ISCC"

\`\`\`

Flag：

\`ISCC{Double\_Decode\_Spring\_Bingo\_2026}\`
