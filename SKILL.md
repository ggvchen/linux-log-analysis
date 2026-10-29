---
name: linux-log-analysis
description: 对 Linux 主机做日志分析、入侵排查与应急响应取证。当用户提出"日志分析""入侵排查""溯源""主机是不是被黑了""攻击者 IP 是多少""怎么 getshell 的""什么时候提权的""查后门"，或提供 auth.log / secure / access.log / error.log / mysql.log / cron.log / wtmp 等日志文件，或给出靶机/服务器的 SSH 地址与凭证要求分析日志时使用。可还原从 Web 爆破、GetShell、横向、提权到持久化的完整攻击时间线，并产出可打印的取证报告。
agent_created: true
---

# Linux 日志分析（应急响应取证）

## 适用场景

两类输入，走两条路径：

| 输入形态 | 路径 |
|---|---|
| 给了 SSH 地址+端口+账号口令（靶机、云主机） | 远程取证 → 拉回本地分析 |
| 给了日志文件/目录（压缩包、/var/log 拷贝） | 直接本地分析 |

典型问法：定位攻击者 IP、首次登录时间、getshell 方式、提权方法与时间、数据库访问、持久化后门及执行情况。

## 三条铁律

1. **先固定证据，再分析。** 优先把日志拉回本地分析，避免在目标机上反复操作污染证据。远程只做只读操作（`ls`/`cat`/`tar`），不改文件、不重启服务。
2. **时间必须交叉印证。** 同一事件至少两个独立来源对得上（如 access.log 的 POST 时间 + 文件 ctime + cron.log 记录）。单一来源得出的时间只能标注为"疑似"。
3. **结论必须挂在原始日志行上。** 每条结论后面附原始日志片段。没有日志支撑的部分，写明"需上机确认"，不要用推测填空。

## 工作流

### 阶段 0：界定范围

确认授权性质（CTF 靶机 / 客户委托 / 自有资产），记录目标 IP、端口、账号、系统版本。向用户确认是否有已知的"事件大概时间段"——有则用它收窄分析范围，能省掉大量噪音。

### 阶段 1：取证

**远程连接（无 sshpass 时的可靠做法）：**

```bash
mkdir -p /tmp/ir_task
printf '#!/bin/sh\necho "<PASSWORD>"\n' > /tmp/ir_task/askpass.sh && chmod 700 /tmp/ir_task/askpass.sh

cat > /tmp/ir_task/r.sh <<'EOF'
#!/bin/sh
DISPLAY=:0 SSH_ASKPASS=/tmp/ir_task/askpass.sh SSH_ASKPASS_REQUIRE=force \
ssh -F /dev/null -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -o ConnectTimeout=20 -o LogLevel=ERROR -p <PORT> <USER>@<HOST> "$@"
EOF
chmod 700 /tmp/ir_task/r.sh

/tmp/ir_task/r.sh 'id; hostname; uname -a; date; ls -la /var/log/'
```

关键点：
- `-F /dev/null` 必须加，否则 ssh 会读本机 `~/.ssh/config`，在受管环境里常被安全策略拦截。
- `SSH_ASKPASS_REQUIRE=force` 让 OpenSSH 8.4+ 无需 tty 也能走 askpass。
- 非 Debian 系注意 `auth.log` 实际叫 `secure`。

**打包取证（只读）：**

```bash
/tmp/ir_task/r.sh 'cd / && tar czf /tmp/ev.tgz \
  var/log/auth.log* var/log/secure* var/log/wtmp var/log/btmp var/log/lastlog \
  var/log/cron* var/log/syslog* var/log/messages* var/log/kern.log* \
  var/log/apache2 var/log/nginx var/log/httpd var/log/mysql var/log/audit \
  var/www/html 2>/dev/null; ls -la /tmp/ev.tgz'

DISPLAY=:0 SSH_ASKPASS=/tmp/ir_task/askpass.sh SSH_ASKPASS_REQUIRE=force \
scp -F /dev/null -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -P <PORT> <USER>@<HOST>:/tmp/ev.tgz /tmp/ir_task/ && \
cd /tmp/ir_task && tar xzf ev.tgz
```

**不要打包** `/etc/shadow`、`~/.bash_history`、数据库配置文件等凭据类文件——既涉合规，也常被安全策略直接拦截。若 crontab 原文读不到，用 `cron.log` 中的 `CMD (...)` 字段还原命令行（多数情况下足够）。

### 阶段 2：快速分诊

```bash
python3 scripts/log_triage.py <日志目录> --year <事件年份> --tz 8
```

脚本自动完成：识别日志类型（含 `.1`、`.2.gz` 轮转与 gzip）、跨文件去重（auth.log 与 syslog 会重复记录）、按 IP 统计 Web 来源、爆破检测、su/sudo/pkexec 提权指纹、crontab 变更与后门聚合、WebShell 候选路径、数据库连接与高危 SQL、统一时间线。

`--year` 用于补齐 syslog 缺失的年份；`--tz 8` 输出北京时间（默认 UTC）。

分诊结果只是线索，**必须回到原始日志逐条核对**再下结论。

### 阶段 3：攻击链建模（七要素）

按顺序填空，每项都要"时间 + 证据行"：

1. **攻击者身份** — 源 IP、UA、内网还是外网、是否有多个来源
2. **入口点** — 爆破/漏洞/弱口令，首次成功时间
3. **权限落地** — GetShell 方式、落地文件路径、首次执行时间
4. **横向** — 从服务账户到系统账户的过程与时间
5. **提权** — 方法（CVE 编号或配置缺陷）、时间、指纹
6. **数据访问** — 数据库/文件访问时间与范围
7. **持久化** — 后门位置、植入时间、载荷内容、**是否真正生效**

第 7 项最容易做浅。"存在后门"和"后门能用"是两回事，必须验证载荷是否成功回连（`ss -antp` 查外连 + cron 日志中的报错输出）。

### 阶段 4：交叉印证

动手写结论前，对照 `references/attack-patterns.md` 的「判据陷阱」逐条自检。最容易踩的五个：

- **302 ≠ 登录成功**：失败也跳转。必须以"登录后页面返回 200"判定。
- **mtime 可伪造**：`touch -t` 能改 Modify，但 ctime 改不了。木马落地时间一律用 `stat` 的 **Change** 字段。
- **运维 ≠ 攻击者**：管理员也会大量访问后台、SSH 登 root。区分靠"有无爆破、有无上传可执行文件、有无提权/建号/改 cron"。
- **用户级 crontab 多写 user 字段会失效**：`* * * * * root echo ...` 会让 `sh` 把 `root` 当命令名，报错但不回连。日志中 `(root) CMD (root echo ...)` 的 CMD 内含 `root` 即为证据。
- **环境可能被重置多次**：MySQL 多个 `started with:` 头、auth.log 多次 `chpasswd ... password changed for root` = 快照恢复过。必须锚定真正的攻击窗口。

### 阶段 5：输出报告

复制 `assets/report-template.html` 为交付文件，替换占位符后输出。报告必须包含：结论速览表、攻击者身份判定（含被排除的正常 IP）、完整时间线、七问逐条取证（附原始日志）、IOC、攻击链图、处置建议、取证局限说明。

时间同时给 UTC 与本地时区（国内 +8）并明确标注，避免阅读方误判。

## 常用命令补充

```bash
# 文件落地排查（按时间窗口）
find / -xdev -type f -newermt "2022-12-14 01:00" ! -path "/proc/*" ! -path "/sys/*" 2>/dev/null

# 时间戳真相（mtime 可能被伪造，以 ctime 为准）
stat /path/to/suspect

# 当前外连（验证后门是否活着）
ss -antp

# 登录历史
last -Fai | head -40; lastb -Fai | head -40; lastlog

# 重启次数（判断环境重置）
utmpdump /var/log/wtmp 2>/dev/null | grep -i reboot

# SUID 基线比对
find / -xdev -perm -4000 -type f 2>/dev/null

# 隐藏账户 / 空口令
awk -F: '$3==0 {print}' /etc/passwd
awk -F: '($2==""){print $1}' /etc/shadow 2>/dev/null
```

## 资源

| 文件 | 用途 |
|---|---|
| `scripts/log_triage.py` | 日志快速分诊器，一次输出 9 类线索 + 统一时间线 |
| `references/log-sources.md` | 日志文件清单、字段含义、轮转、时区、日志被清除的识别 |
| `references/attack-patterns.md` | 各攻击阶段的手法指纹 + **9 个判据陷阱** + 七要素模板 |
| `assets/report-template.html` | 可打印的应急响应报告模板（浅色主题，A4 友好） |

## 报告与沟通

- 不要在任何输出中回显目标的明文口令、密码哈希。
- 用户是备考/演练场景时，除结论外简要说明"证据链如何闭合"，比只给答案更有价值。
- 发现后门但载荷失效时，明确写"已植入、可触发、未成功回连"，并说明若攻击者修正即可获得稳定通道——这决定处置优先级。
