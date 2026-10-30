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
# 1. 一次输出 10 节报告：9 类线索 + 统一时间线 + IOC 清单
python scripts/log_triage.py /var/log --year 2022 --tz 8

# 2. 只看攻击窗口（大日志先切窗口，噪音立刻少一半）
python scripts/log_triage.py /var/log --year 2022 \
       --since "2022-12-14 01:50" --until "2022-12-14 02:10"

# 3. 从远程靶机/服务器取证（只读，不落地脚本）
/tmp/ir_task/r.sh 'cd / && tar czf /tmp/ev.tgz var/log var/www/html 2>/dev/null'
scp -P <PORT> root@<HOST>:/tmp/ev.tgz /tmp/ir_task/ && cd /tmp/ir_task && tar xzf ev.tgz

# 4. 对拉回的日志分诊
python scripts/log_triage.py /tmp/ir_task/var/log --year 2022
```

参数：

| 参数 | 作用 |
|---|---|
| `--year 2022` | 补齐 syslog / cron.log 缺失的年份（这两个文件只有 `Dec 14 02:10:05`，没有年）。脚本会用 wtmp/btmp 的绝对时间反查是否补错并告警 |
| `--tz 8` | 输出北京时间，默认 UTC。报告里给两个时区能避免阅读方误判 |
| `--since` / `--until` | 只看该时间窗内的事件，如 `--since "2022-12-14 01:00"` |
| `--brute-threshold 50` | 判定"暴力破解"的失败次数阈值 |

## 输出示例

对一台真实被入侵的 Ubuntu 18.04 靶机跑出来的结果（节选）：

```
已解析: access=1569, auth=251, error=26, mysql=6538, mysql_err=921, phpfpm=16, syslog=16598, utmp=55
[警告] btmp 中有记录的月日时分与 auth.log 完全一致、但年份为 [2021]（auth.log 按 2022 补全）
       ——年份可能错了一年，建议用 --year 2021 复核（btmp 为绝对时间，可信）

【1】Web 访问来源 TOP
IP                      请求数  首次访问                末次访问                 状态码 / 主要 UA
192.168.226.24         1088  2022-12-14 01:52:39 2022-12-14 02:01:51  200:685,302:398,404:5  Mozilla/5.0 (Windows NT 10
192.168.216.16          466  2022-12-14 00:44:58 2022-12-14 02:22:44  200:357,304:91,302:16,404:1  Mozilla/5.0 (Windows NT 10

【2】口令爆破 / 暴力登录
  [Web]  192.168.226.24     登录接口 POST 1008 次  2022-12-14 01:52:49 ~ 2022-12-14 01:56:48  <<< 疑似暴力破解
  [SSH]  192.168.131.1      认证失败 6 次  2022-10-08 04:33:14 ~ 2022-10-08 04:37:23
  [btmp] 192.168.131.1      失败登录 5 次  2021-10-08 04:33:15 ~ 2021-10-08 04:37:23  尝试用户 root

【3】登录成功记录
  --- wtmp 登录会话（绕过 syslog 删除也能看到）---
  2021-10-08 04:41:37  [wtmp]  root         pts/0    <- 192.168.131.1
  2022-12-14 01:59:34  [wtmp]  root         tty1     <- local
  --- 重启记录（判断环境快照恢复/时钟异常）---
  2022-12-14 00:40:12  [boot]  系统启动
  2022-12-14 00:49:55  [boot]  系统启动
  2022-12-14 08:36:18  [boot]  系统启动

【6】WebShell / 恶意脚本访问线索
  /data/themes/lndex.php
      来源 192.168.226.24   命中 4 次   状态码 404:4
      判定 常见木马命名/混淆命名
      时间 2022-12-14 01:59:23 ~ 2022-12-14 01:59:27（4 次）
      备注 全部 404 —— 攻击者在试探路径，文件未落地
  /data/modules/lndex.php
      来源 192.168.226.24   命中 3 次   状态码 200:3
      判定 常见木马命名/混淆命名
      时间 2022-12-14 01:59:55 ~ 2022-12-14 02:01:51（3 次）
      备注 存在 200 响应 —— 文件已落地并可访问，需立即上机确认
  --- error.log 中的脚本执行痕迹（最强落地证据）---
  [!!] client=192.168.226.24  2022-12-14 01:59:55
       PHP Notice:  Undefined offset: 1 in /var/www/html/data/modules/lndex.php on line 1

【9】IOC 快速清单（可直接用于封禁与全盘排查）
  -- 攻击者 IP --
    192.168.226.24     Web 登录爆破 1008 次; WebShell 访问 /data/modules/lndex.php; 错误日志记录的脚本执行
  -- 同期其他 Web 来源（无爆破/上传行为，倾向运维，需人工确认）--
    192.168.216.16, ::1
  -- 可疑文件路径 --
    /data/modules/lndex.php  [已落地(200)]
    /data/themes/lndex.php  [仅试探(无 200)]
    /data/themes/lndex/lndex.php  [仅试探(无 200)]
  -- 外联地址（后门载荷中提取，含 base64 解码）--
    192.168.226.24:22496
  -- 新建/变更账户 --
    ubuntu18 @ 2022-10-08 03:05:55
    mysql @ 2022-12-14 00:42:08
    lee @ 2022-12-14 01:31:26
```

几个值得注意的处理：

- **第 6 节区分了 404 与 200**：同一文件名 4 次全是 404（试探）、3 次是 200（落地）。只按文件名报警会把这个差别抹掉。
- **error.log 那一行是木马真正确认执行的证据**：`Undefined offset: 1 in .../lndex.php` 说明 PHP 解析并运行了它，时间 01:59:55 与 200 请求吻合。
- **年份告警不是噪音**：auth.log 只能按 `--year` 猜年份，btmp 存的是绝对时间，两者一对就发现差了一年。
- **外联地址必须解码才拿得到**：后门写成 `echo <base64> | base64 -d | bash`，明文里根本没有 IP。
  脚本会把载荷解码后再提取 C2，否则 IOC 清单里这一段永远是空的。

## 能查什么

| # | 线索类别 | 具体能力 |
|---|---|---|
| 1 | Web 来源画像 | 按 IP 聚合请求数、首末访问时间、状态码分布、主要 UA，一眼区分攻击者与运维 |
| 2 | 口令爆破 | Web 登录接口 POST 频次 + SSH `Failed password`（含 pam 的 `rhost=`）+ **btmp 失败登录**三路统计 |
| 3 | 登录成功 | SSH `Accepted`、`su`、`sudo`、auditd `USER_LOGIN`、**wtmp 会话**多源交叉；`su` 会标注执行者 uid |
| 4 | 账户变更 / 提权 | `useradd`、`chpasswd`、pkexec 的 `GCONV_PATH` 指纹（CVE-2021-4034）；auditd 还原 `execve` 完整命令行 |
| 5 | 计划任务后门 | crontab `REPLACE` 事件、Base64 管道执行、反弹 shell 特征，**按命令行聚合去重** |
| 6 | WebShell 线索 | 混淆命名、双扩展名、可写目录落地；**error.log / PHP-FPM 中的执行痕迹**（`eval()'d code`、木马文件报错）；200 与 404 分离判定 |
| 7 | 数据库访问 | MySQL `Connect` / `Access denied` 按 tid 与消息双重去重（general 与 error 会双写），高危 SQL 特征 |
| 8 | 统一时间线 | 跨所有日志源合并排序，账户组操作自动降噪 |
| 9 | IOC 清单 | 自动汇总攻击者 IP（含判定依据）、已落地/仅试探的可疑文件、外联地址、新建账户 |
| 10 | 日志完整性 | 跨年月检测、**用 wtmp/btmp 反查 syslog 年份补错**、未识别文件提示、日志轮转与缺失 |

## 判据陷阱

`references/attack-patterns.md` 里整理了 12 个，下面是代价最高的八个：

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
5. **环境可能被重置过多次。** 多个 MySQL `started with:`、反复 `changed for root`、
   wtmp 里密集的 boot 记录 = 快照恢复。不锚定时间窗，会把上一轮的痕迹算到这一轮头上。
6. **syslog 没年份，跨年必错一半。** 同一份 auth.log 可能同时有去年装机、今年被攻击的事件，
   一个 `--year` 只能对一半。用 wtmp/btmp 的绝对时间反查——两边"月-日-时-分"完全重合而年份不同，
   就是补错了。脚本会直接告警。
7. **btmp 的失败登录是 `type=6`（LOGIN_PROCESS），不是 7。** 按 7 过滤会一条都读不到，
   误判成"没有 SSH 爆破"。反过来 wtmp 的 `type=6` 是 getty 提示符，不是真实登录。
8. **Apache error.log 的方括号顺序不固定。** `[php7:notice]` 常排在 `[pid]` 之前，
   写成固定顺序的正则会取不到 `[client IP]`——而 client IP 正是把 PHP 报错关联到
   "某个 IP 执行了木马"的唯一纽带。

## 输出报告

`assets/report-template.html` 是可打印的 A4 报告模板，包含结论速览表、攻击者身份判定（含**被排除的正常 IP**）、
完整时间线、七问逐条取证（附原始日志行）、IOC、攻击链、处置建议、取证局限说明。

## 文件结构

```
SKILL.md                         主流程：三条铁律、五阶段工作流、常用命令
scripts/log_triage.py            日志快速分诊器（10 节报告 + IOC 清单）
references/log-sources.md        日志清单、字段含义、轮转、时区、auditd 字段、utmp 二进制结构
references/attack-patterns.md    各阶段手法指纹 + 12 个判据陷阱 + 七要素建模模板
assets/report-template.html      可打印取证报告模板
```

支持的日志源：Apache/Nginx access（combined·common·HTTP2·IPv6）、Apache 原生 error.log、
Nginx error.log、PHP-FPM、auth.log/secure、syslog/messages/daemon/user/kern/mail、
auditd（USER_LOGIN·USER_CMD·EXECVE·AVC）、wtmp/btmp、MySQL general log + error log，
以及 `.1` `.2.gz` `secure-20221214` 等轮转命名。

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
