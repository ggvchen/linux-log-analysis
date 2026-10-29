# Linux 日志源清单与字段速查

## 一、核心日志位置

| 文件 | 发行版 | 记录内容 | 关键价值 |
|---|---|---|---|
| `/var/log/auth.log` | Debian/Ubuntu | 认证、sudo、su、sshd、useradd、cron 的 PAM 会话 | **最强证据源**，登录/提权几乎全在此 |
| `/var/log/secure` | RHEL/CentOS | 同 auth.log | 同上 |
| `/var/log/apache2/access.log` | Debian | Web 访问（combined 格式） | 攻击者 IP、爆破、getshell 路径 |
| `/var/log/httpd/access_log` | RHEL | 同上 | 同上 |
| `/var/log/apache2/error.log` | Debian | PHP 错误、脚本不存在、Fatal error | **证明 webshell 被解析执行**（Undefined offset 等） |
| `/var/log/nginx/access.log` | - | 格式同 Apache combined | 同上 |
| `/var/log/mysql/mysql.log` | - | MySQL general log（连接+查询） | 数据库登录时间、高危 SQL |
| `/var/log/mysql/error.log` | - | MySQL 启动/错误 | 环境重置次数、崩溃 |
| `/var/log/cron.log` | Ubuntu | cron 执行、crontab 变更 | **后门植入与执行** |
| `/var/log/syslog` | Debian | 全量 syslog（含 auth 副本） | 交叉印证、systemd 事件 |
| `/var/log/messages` | RHEL | 同 syslog | 同上 |
| `/var/log/kern.log` | Debian | 内核消息 | 驱动加载、OOM、键盘异常 |
| `/var/log/wtmp` | - | 二进制，登录/登出/重启 | `last` 命令读取 |
| `/var/log/btmp` | - | 二进制，失败登录 | `lastb` 命令读取 |
| `/var/log/lastlog` | - | 二进制，每用户最后登录 | `lastlog` 命令读取 |
| `/var/log/faillog` | - | 二进制，失败计数 | `faillog -a` |

**必查但常被忽略：**
- `/var/log/journal/` 或 `journalctl -xe`（systemd 环境，日志可能只在 journald 里）
- `/var/log/audit/audit.log`（若 auditd 开启，有 execve 命令级记录，价值极高）
- 应用日志：`/var/www/*/logs/`、Tomcat `catalina.out`、`/opt/*/logs/`

## 二、日志轮转：必须一起分析

只读 `auth.log` 会漏掉攻击早期行为。必须收集全部轮转文件：

```bash
ls -la /var/log/ | grep -E "auth|secure|access|error|syslog|mysql|cron"
# auth.log  auth.log.1  auth.log.2.gz  auth.log.3.gz ...
```

`log_triage.py` 会自动识别 `access.log.1`、`auth.log.2.gz` 等命名并解压读取。

## 三、apache/nginx access.log 字段

```
192.168.226.24 - - [14/Dec/2022:01:52:39 +0000] "POST /login.php HTTP/1.1" 302 300 "http://10.2.4.11/login.php" "Mozilla/5.0 ..."
└──── 第1列 ───┘        └─────── 第4列 ───────┘ └─ 第6列:方法+路径 ─┘ └7┘ └8┘ └──── 第10列 referer ────┘ └── 第11列 UA ──┘
```

| 字段 | awk 列 | 用途 |
|---|---|---|
| 来源 IP | `$1` | 攻击者归属、爆破统计 |
| 时间戳 | `$4` | 含时区（`+0000`），需归一到 UTC |
| 方法+路径 | `$6 $7` | 爆破路径、webshell 路径 |
| 状态码 | `$9` | 200 成功 / 302 跳转 / 404 试探 |
| 响应大小 | `$10` | **同接口大小突变 = 内容变化**（如登录失败 1083 → 成功 300） |
| Referer | `$11` | 判断操作来源页面，还原点击流 |
| User-Agent | `$12` | 识别扫描器、区分正常浏览器 |

**响应大小的价值**：爆破时失败与成功的响应体大小不同（如 1083 vs 300），可直接看出哪一次突破。

## 四、auth.log / syslog 常见行格式

```
Dec 14 02:03:52 ubuntu18 su[23612]: Successful su for lee by www-data
└── 时间(无年份) ──┘ └主机┘ └进程[pid]┘ └──────── 消息 ────────┘
```

**关键消息模式：**

| 模式 | 含义 |
|---|---|
| `Accepted password for X from IP port N ssh2` | SSH 口令登录成功 |
| `Accepted publickey for X from IP` | 公钥登录（查 authorized_keys 是否被植入） |
| `Failed password for X from IP` | 口令失败（爆破计数） |
| `authentication failure; ... rhost=IP user=X` | PAM 层认证失败 |
| `pam_unix(sshd:session): session opened for user X` | 会话建立 |
| `Successful su for X by Y` | **su 切换成功（横向关键）** |
| `pam_unix(su:session): session opened for user X by (uid=N)` | su 会话，**括号内 uid 是执行者** |
| `pam_unix(sudo:session): session opened for user root by X(uid=N)` | sudo 提权 |
| `useradd[...]: new user: name=X, UID=N, GID=N` | 新建账户 |
| `passwd[..]: password changed for X` | 口令修改 |
| `pkexec[..]: X: ... [USER=root] [COMMAND=...]` | **pkexec 提权（PwnKit 指纹在这里）** |
| `CRON[..]: (user) CMD (命令)` | **cron 实际执行的完整命令** |
| `crontab[..]: (user) REPLACE (user)` | **crontab 被写入/修改** |
| `crontab[..]: (user) LIST (user)` | crontab 被查看 |

## 五、wtmp / btmp / lastlog 解析

二进制格式，用系统工具：

```bash
last -Fai | head -50          # 登录历史（-F 完整时间 -a 显示 IP -i IP 数字）
lastb -Fai | head -50         # 失败登录
lastlog                       # 每用户最后登录（空值=从未登录，异常账户易暴露）
who -a; w                     # 当前在线
utmpdump /var/log/wtmp 2>/dev/null | tail -50   # 原始记录，含 reboot/shutdown 标记
```

`utmpdump` 的输出能精确看到 `reboot`、`runlevel` 记录，用于**确定环境重置次数与时间点**，这是识别"日志跨多个环境"的关键。

## 六、时间与时区

- syslog 系（auth/syslog/cron）时间戳**不含年份**，跨年日志会误判，必要时用 `--year` 指定。
- access.log 含时区偏移（`+0000`），`log_triage.py` 会归一到 UTC。
- 报告必须**标注时区**，并同时给出 UTC 与本地时间（国内 +8）。
- 检测时钟异常：`journalctl --list-boots`、`last reboot` 与日志时间线是否自洽；若日志某段出现时间倒退，多半是快照恢复或 NTP 纠偏。

## 七、日志被清除的识别

攻击者常执行 `rm -rf /var/log/*`、`echo > auth.log`、`history -c`。检查：

```bash
ls -la /var/log/                       # 文件大小为 0、mtime 异常新
stat /var/log/auth.log                 # ctime 与 mtime 差异
find /var/log -name "*.log" -size 0    # 空日志文件
ls -la /var/log/*.gz                   # 轮转链是否断裂（缺 .1 只有 .2）
cat /var/log/syslog | grep -i "deleted\|truncat"
```

**日志缺口分析**：正常系统每分钟都有 cron/系统心跳。若某时间段完全无记录，说明日志被截断。

## 八、快速收集清单（上机或远程执行）

```bash
# 一次性打包（排除凭据类文件，避免合规问题）
tar czf /tmp/ir_$(date +%s).tar.gz \
  var/log/auth.log* var/log/secure* var/log/wtmp var/log/btmp var/log/lastlog \
  var/log/cron* var/log/syslog* var/log/messages* var/log/kern.log* \
  var/log/apache2 var/log/nginx var/log/httpd var/log/mysql \
  var/log/audit 2>/dev/null

# 文件系统侧（不入包，直接看）
stat /var/www/html/<可疑文件>
find / -xdev -type f -newermt "<入侵起始时间>" 2>/dev/null | head -50
```
