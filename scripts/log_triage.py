#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Linux 日志快速分诊器 / Linux log triage for incident response.

扫描一个日志目录（可含轮转文件、gz 压缩、二进制 wtmp/btmp），
自动提取入侵线索并输出统一时间线与 IOC 清单。

用法:
    python3 log_triage.py <log_dir> [--year 2022] [--tz 8]
                          [--since "2022-12-14 01:00"] [--until "2022-12-14 03:00"]
                          [--brute-threshold 50]

示例:
    python3 log_triage.py ./var/log --year 2022
    python3 log_triage.py /var/log --tz 8 --since "2022-12-14 01:00"

支持:
    Web      apache/nginx access（combined / common / HTTP2 / IPv6）、原生 error.log、nginx error.log
    认证     auth.log / secure / sshd、syslog / messages / daemon / user / kern / mail / cron
    审计     auditd audit.log（USER_LOGIN / USER_CMD / EXECVE / AVC）
    二进制   wtmp（登录会话与重启）、btmp（失败登录）
    数据库   MySQL general log、MySQL error log
    轮转     .1 .2 .gz / secure-20221214 / access.log-20221214

设计原则:
  - 只读，不修改任何日志
  - 容错：空文件、非 UTF-8、gzip、二进制、格式混杂都不应中断分析
  - auth.log 与 syslog 常重复记录同一事件，需按 (时间, 原文) 去重
  - 时间统一归一到 UTC 内部计算，输出时按 --tz 偏移
  - 输出到 stdout，便于重定向或二次处理
"""

import argparse
import base64
import gzip
import os
import re
import struct
import sys
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone

# ---------------------------------------------------------------- 正则

# Apache / Nginx combined / common / HTTP2 / IPv6：
# 1.2.3.4 - - [14/Dec/2022:01:52:39 +0000] "GET /x HTTP/1.1" 200 1234 "ref" "ua"
RE_ACCESS = re.compile(
    r'^(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"([A-Z]+)\s+(\S+?)(?:\s+\S+)?"\s+(\d{3})\s+(\S+)'
    r'(?:\s+"([^"]*)"\s+"([^"]*)")?'
)

# syslog 系：Dec 14 01:56:48 [host] proc[pid]: msg
# host 可选——容器、journald 导出、精简系统常见无 hostname 的形态
RE_SYSLOG = re.compile(
    r'^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+'
    r'(?:(\S+)\s+)?'
    r'([\w./@\-]+?)(?:\[(\d+)\])?:\s(.*)$'
)

# rsyslog 高精度时间戳：2022-12-14T02:07:13.892649+08:00 host proc[pid]: msg
RE_SYSLOG_ISO = re.compile(
    r'^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\s+'
    r'(?:(\S+)\s+)?([\w./@\-]+?)(?:\[(\d+)\])?:\s(.*)$'
)

# MySQL general log: 2022-12-14T02:07:13.892649Z  10 Connect  lee@localhost on  using Socket
RE_MYSQL = re.compile(
    r'^(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2}:\d{2})(?:\.\d+)?Z?\s+(\d+)\s+'
    r'(Connect|Query|Quit|Init DB|Field|Prepare|Execute|Close stmt|Statistics|Shutdown)\s*(.*)$'
)

# MySQL error log: 2022-12-14T02:07:04.123456Z 9 [Note] ... / 2022-12-14 02:07:04 9 [Note] ...
RE_MYSQL_ERR = re.compile(
    r'^(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}:\d{2})(?:\.\d+)?Z?\s+(?:\d+\s+)?\[(\w+)\]\s*(.*)$'
)

# Apache 原生 error.log: [Wed Dec 14 02:00:00.123456 2022] [php7:error] [pid 1] [client 1.2.3.4:5] msg
# 注意：[模块:级别]、[pid]、[client] 三段的排列顺序随版本/模块而变（常见 [php7:notice] 在 [pid] 之前），
#       所以只锚定时间戳，剩余部分用 apache_err_parts() 逐个方括号剥离，不能写成固定顺序的正则。
RE_APACHE_TIME = re.compile(r'^\[(\w{3}\s+\w{3}\s+\d{1,2}\s+[\d:.]+\s+\d{4})\]\s*(.*)$')
RE_BRACKET = re.compile(r'^\[([^\]]+)\]\s*')

# nginx error.log: 2022/12/14 02:00:00 [error] 123#123: *1 open() "..."
RE_NGINX_ERR = re.compile(
    r'^(\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})\s+\[(\w+)\]\s+(?:\d+#\d+:\s*)?(?:\*\d+\s*)?(.*)$'
)

# auditd：type=USER_LOGIN msg=audit(1670976200.000:461): pid=... acct="lee" ... res=success
RE_AUDIT = re.compile(r'^type=(\w+)\s+msg=audit\((\d+(?:\.\d+)?):(\d+)\):\s*(.*)$')
RE_AUDIT_ARGV = re.compile(r'\ba(\d+)=("(?:[^"\\]|\\.)*"|\S+)')

# PHP-FPM: [14-Dec-2022 01:59:55] WARNING: [pool www] child 1 said into stderr: "NOTICE: PHP message: ..."
RE_FPM = re.compile(
    r'^\[(\d{2})-(\w{3})-(\d{4})\s+(\d{2}:\d{2}:\d{2})\]\s+(\w+):\s*'
    r'(?:\[pool [^\]]+\]\s*child \d+ said into stderr:\s*")?'
    r'(?:NOTICE: PHP message:\s*)?(.*?)"?\s*$'
)

# ---------------------------------------------------------------- 指纹

# 后门 / 反弹 shell 特征
BACKDOOR_PATTERNS = [
    (r'base64\s*-d.*\|\s*(?:ba)?sh', 'Base64 编码管道执行（无文件落地）'),
    (r'/dev/tcp/', 'bash /dev/tcp 反弹 Shell'),
    (r'\bnc\b[^|]*\s-e\s', 'netcat -e 反弹 Shell'),
    (r'ncat[^|]*\s-e\s', 'ncat -e 反弹 Shell'),
    (r'curl[^|]*\|\s*(?:ba)?sh', 'curl 管道执行'),
    (r'wget[^|]*\|\s*(?:ba)?sh', 'wget 管道执行'),
    (r'python[0-9.]*\s+-c[^|]*socket', 'Python 反弹 Shell'),
    (r'perl\s+-e[^|]*socket', 'Perl 反弹 Shell'),
    (r'chmod\s+\+x[^|]*(?:/tmp|/dev/shm|/var/tmp)', '临时目录植入可执行文件'),
    (r'/etc/(?:rc\.local|cron\.d/|cron\.hourly/)', '写入自启动/计划任务'),
    (r'(?:useradd|adduser)[^|]*-o[^|]*-u\s*0', '创建 UID=0 隐藏账户'),
    (r'echo\s+\S+\s*>>?\s*~?/?\.?ssh/authorized_keys', '写入 SSH 公钥'),
]

# 提权利用特征
PRIVESC_PATTERNS = [
    (r'GCONV_PATH', 'PwnKit CVE-2021-4034（pkexec 环境变量劫持）'),
    (r'CHARSET=pkexec', 'PwnKit CVE-2021-4034 指纹'),
    (r'sudo.*EDITOR=', 'sudoedit 提权'),
    (r'dirtypipe|CVE-2022-0847', 'DirtyPipe 提权'),
    (r'overlayfs.*CVE-2021-3493|CVE-2021-3493', 'OverlayFS 提权'),
    (r'pkexec', 'pkexec 调用（需确认是否被利用）'),
]

# WebShell 可疑路径特征
WEBSHELL_HINTS = [
    (r'\.(?:php|asp|aspx|jsp)\.(?:jpg|png|gif|txt|zip|bak)\b', '双扩展名伪装'),
    (r'/\S*(?:shell|cmd|c99|r57|b374k|wso|bypass|1|123|lndex|indx)\S*\.php\b', '常见木马命名/混淆命名'),
    (r'/(?:eval|assert|system|pass|cmd|exec)\S*\.php\b', '高危函数命名文件'),
    (r'/(?:upload|uploads|upfile|files|tmp|temp|images?|data|modules?|themes?|cache|logs?)/\S*\.(?:php|jsp|asp|aspx|phtml)\b',
     '可写目录下的脚本文件'),
]

# PHP 木马在 error.log 中留下的执行痕迹
PHP_WS_EXEC = re.compile(
    r"eval\(\)'d code|assert\(\)'d code|preg_replace\(\)'d code", re.I)

# 报错信息里指向的文件名是否像木马。注意不要用"可写目录"这类宽泛规则——
# 正常业务模块也常放在 data/modules 下，会立刻变成噪音。
PHP_SUSPICIOUS_FILE = re.compile(
    r'/(?:[^/\s]*(?:shell|cmd|c99|r57|b374k|wso|bypass|lndex|indx)[^/\s]*\.(?:php|jsp|asp|aspx)\b'
    r'|(?:1|123|2|test|tmp)\.(?:php|jsp|asp|aspx)\b'
    r'|[^/\s]+\.(?:php|asp|aspx|jsp)\.(?:jpg|png|gif|txt|zip|bak)\b)', re.I)


def extract_c2(cmd):
    """从命令里提取外联 IP:PORT。

    后门的真实 C2 往往不在明文里——`echo <base64> | base64 -d | bash` 这种写法，
    地址编码在载荷内，必须先解码才提得到。
    """
    texts = [cmd]
    for blob in re.findall(r'[A-Za-z0-9+/]{16,}={0,2}', cmd):
        try:
            dec = base64.b64decode(blob + '=' * (-len(blob) % 4)).decode('utf-8', 'replace')
        except (ValueError, TypeError):
            continue
        if dec and dec.isprintable():
            texts.append(dec)
    out = set()
    for t in texts:
        for m in re.finditer(r'(\d{1,3}(?:\.\d{1,3}){3})[:/](\d{1,5})', t):
            out.add(f'{m.group(1)}:{m.group(2)}')
    return out


def is_suspicious_php_error(text):
    """PHP 报错是否可作为木马执行的证据：eval/assert 强指纹，或报错文件本身像木马。"""
    if not text:
        return False
    if PHP_WS_EXEC.search(text):
        return True
    return bool(PHP_SUSPICIOUS_FILE.search(text))

# 登录入口路径（爆破检测）
LOGIN_HINTS = re.compile(r'(?:login|signin|logon|wp-login)', re.I)
# 后台入口：仅当带登录类 action 参数时才算登录请求，避免把后台操作误判为爆破
ADMIN_ENTRY = re.compile(r'(?:admin|administrator|manage|console)', re.I)
ADMIN_LOGIN_ACTION = re.compile(r'action=(?:login|logon|signin|dologin)', re.I)

# 站点自带入口，其 POST 属正常业务，不应作为 WebShell 线索
BENIGN_ENTRY = re.compile(
    r'/(?:admin|login|logout|install|setup|update|index|search|comment|feed|rss|'
    r'register|upload_file|editor)\.php$', re.I)


def is_login_endpoint(clean, raw):
    """判断一个请求是否命中登录接口。"""
    if LOGIN_HINTS.search(clean):
        return True
    if ADMIN_ENTRY.search(clean):
        return bool(ADMIN_LOGIN_ACTION.search(raw))
    return False


# MySQL 高危语句
MYSQL_RISKY = [
    (r'into\s+outfile', 'INTO OUTFILE 写文件'),
    (r'into\s+dumpfile', 'INTO DUMPFILE 写文件'),
    (r'load_file\s*\(', 'LOAD_FILE 读文件'),
    (r'create\s+(?:aggregate\s+)?function', 'CREATE FUNCTION（UDF 提权）'),
    (r'sys_exec|sys_eval', 'UDF 命令执行'),
    (r'from\s+mysql\.user', '读取 mysql.user 表'),
    (r'grant\s+all', 'GRANT ALL 授权'),
    (r'(?:drop|truncate)\s+(?:table|database)', '破坏性语句'),
]

MONTHS = {m: i for i, m in enumerate(
    ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'], 1)}

DEFAULT_UID = {0: 'root', 33: 'www-data', 1000: 'ubuntu', 111: 'mysql', 1001: 'lee'}

# utmp 二进制结构（Linux x86_64 / glibc，定长 384 字节，小端）
UTMP_FMT = '<h2xi32s4s32s256shhiii4i20s'
UT_USER_PROCESS = 7
UT_LOGIN_PROCESS = 6   # btmp 里失败登录写的是 6，不是 7（真实环境踩过的坑）
UT_BOOT_TIME = 2
UT_RUN_LVL = 1
UT_DEAD_PROCESS = 8


# ---------------------------------------------------------------- 基础工具

def open_text(path):
    """按需 gunzip，容错读取。"""
    try:
        if path.endswith('.gz'):
            with gzip.open(path, 'rt', encoding='utf-8', errors='replace') as f:
                return f.read()
        with open(path, 'r', encoding='utf-8', errors='replace') as f:
            return f.read()
    except Exception as e:  # noqa: BLE001
        print(f'[warn] 跳过 {path}: {e}', file=sys.stderr)
        return ''


def parse_apache_time(s):
    """14/Dec/2022:01:52:39 +0000 -> naive datetime（统一归一到 UTC）"""
    m = re.match(r'(\d{2})/(\w{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2})(?:\s*([+-]\d{4}))?', s)
    if not m:
        return None
    d, mon, y, H, M, S, tz = m.groups()
    try:
        dt = datetime(int(y), MONTHS[mon], int(d), int(H), int(M), int(S))
    except (KeyError, ValueError):
        return None
    if tz:
        try:
            sign = 1 if tz[0] == '+' else -1
            dt -= timedelta(minutes=sign * (int(tz[1:3]) * 60 + int(tz[3:5])))
        except ValueError:
            pass
    return dt


def parse_syslog_time(s, year):
    m = re.match(r'([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})', s)
    if not m:
        return None
    mon, d, H, M, S = m.groups()
    try:
        return datetime(year, MONTHS[mon], int(d), int(H), int(M), int(S))
    except (KeyError, ValueError):
        return None


def parse_epoch(ts):
    """audit / utmp 的 epoch 秒 -> naive UTC datetime"""
    try:
        return datetime.fromtimestamp(float(ts), tz=timezone.utc).replace(tzinfo=None)
    except (ValueError, OSError, OverflowError):
        return None


def decode_hex(s):
    """audit USER_CMD 的 cmd= 是十六进制编码的命令行。"""
    try:
        return bytes.fromhex(s).decode('utf-8', 'replace')
    except ValueError:
        return None


def parse_apache_err_time(s):
    """Wed Dec 14 02:00:00.123456 2022 -> datetime（error.log 的时间格式）"""
    s = s.strip()
    for f in ('%a %b %d %H:%M:%S.%f %Y', '%a %b %d %H:%M:%S %Y'):
        try:
            return datetime.strptime(s, f)
        except ValueError:
            continue
    try:
        return datetime.strptime(re.sub(r'\.\d+', '', s), '%a %b %d %H:%M:%S %Y')
    except ValueError:
        return None


def apache_err_parts(tail):
    """从 error.log 剩余部分剥离 [pid] [client IP:port] [模块:级别]，返回 (client_ip, level, msg)。

    方括号段的顺序随 Apache 版本与模块变化（[php7:notice] 常在 [pid] 之前），
    因此逐段剥离而不是写死顺序。
    """
    cip, lvl = None, None
    rest = tail
    while True:
        m = RE_BRACKET.match(rest)
        if not m:
            break
        inner = m.group(1)
        rest = rest[m.end():]
        cm = re.match(r'client\s+([0-9a-fA-F.:]+?)(?::\d+)?$', inner)
        if cm:
            cip = cm.group(1)
            continue
        if inner.startswith('pid '):
            continue
        lvl = inner
    return cip, lvl, rest


def compress_runs(times, fmt):
    """把一串时间点压缩成 '首次 ~ 末次（N 次）'，避免刷屏。"""
    if not times:
        return '-'
    times = sorted(times)
    if len(times) == 1:
        return fmt(times[0])
    return f'{fmt(times[0])} ~ {fmt(times[-1])}（{len(times)} 次）'


def classify(path):
    """按路径与文件名判断日志类型。先看目录，再看文件名——避免 mysql/error.log 被当成 apache error。"""
    p = path.replace('\\', '/').lower()
    base = os.path.basename(p)
    parent = os.path.basename(os.path.dirname(p))

    # 二进制 utmp 记录（无文本可读，需 struct 解析）
    if base in ('wtmp', 'btmp') or re.match(r'^(?:w|b)tmp\.', base):
        return 'utmp'

    # auditd
    if base.startswith('audit.log') or (parent == 'audit' and base.startswith('audit')):
        return 'audit'

    # MySQL：先按目录判定，避免 mysql/error.log 落到 apache error 分支
    if parent.startswith('mysql') or parent.startswith('mariadb'):
        return 'mysql_err' if base.startswith('error') else 'mysql'
    if 'mysql' in base or 'general' in base or base.startswith('slow'):
        return 'mysql_err' if base.startswith('error') else 'mysql'

    if 'access' in base:
        return 'access'
    if 'fpm' in base or base.startswith('php'):
        return 'phpfpm'
    if base.startswith('error') or base.endswith('-error.log') or 'error_log' in base:
        return 'apache_err'
    if base.startswith(('auth', 'secure', 'sshd')):
        return 'auth'
    if base.startswith(('cron', 'syslog', 'messages', 'daemon', 'user', 'kern', 'mail',
                        'maillog', 'boot', 'ufw', 'iptables', 'haproxy', 'samba')):
        return 'syslog'
    if base.startswith(('xferlog', 'vsftpd', 'pure-ftpd', 'proftpd')):
        return 'syslog'
    if base in ('dpkg.log', 'history.log', 'alternatives.log') or parent == 'apt':
        return 'syslog'
    return None


def iter_utmp(path):
    """解析 wtmp/btmp 定长记录，产出 (type, user, line, host, pid, epoch)。"""
    data = b''
    try:
        if path.endswith('.gz'):
            with gzip.open(path, 'rb') as f:
                data = f.read()
        else:
            with open(path, 'rb') as f:
                data = f.read()
    except Exception as e:  # noqa: BLE001
        print(f'[warn] 跳过 {path}: {e}', file=sys.stderr)
        return

    size = struct.calcsize(UTMP_FMT)
    for off in range(0, len(data) - size + 1, size):
        try:
            (ut_type, ut_pid, ut_line, _ut_id, ut_user, ut_host,
             _e1, _e2, _sess, tv_sec, _usec, *_rest) = struct.unpack(
                UTMP_FMT, data[off:off + size])
        except struct.error:
            continue
        yield (
            ut_type,
            ut_user.split(b'\x00')[0].decode('utf-8', 'replace'),
            ut_line.split(b'\x00')[0].decode('utf-8', 'replace'),
            ut_host.split(b'\x00')[0].decode('utf-8', 'replace'),
            ut_pid, tv_sec)


# ---------------------------------------------------------------- 主流程

def main():
    ap = argparse.ArgumentParser(description='Linux 日志快速分诊（应急响应）')
    ap.add_argument('logdir', help='日志目录')
    ap.add_argument('--year', type=int, default=None,
                    help='syslog 缺失年份时使用（默认从 access.log 推断，否则当前年）')
    ap.add_argument('--tz', type=int, default=0, help='输出时区偏移，8 表示 UTC+8（默认 0）')
    ap.add_argument('--since', default=None, help='只看该时间之后的事件，如 "2022-12-14 01:00"')
    ap.add_argument('--until', default=None, help='只看该时间之前的事件，如 "2022-12-14 03:00"')
    ap.add_argument('--brute-threshold', type=int, default=50, help='判定暴力的失败次数阈值')
    args = ap.parse_args()

    if not os.path.isdir(args.logdir):
        sys.exit(f'[error] 不是目录: {args.logdir}')

    def parse_clamp(s):
        for f in ('%Y-%m-%d %H:%M:%S', '%Y-%m-%d %H:%M', '%Y-%m-%dT%H:%M:%S', '%Y-%m-%dT%H:%M', '%Y-%m-%d'):
            try:
                return datetime.strptime(s, f)
            except ValueError:
                continue
        sys.exit(f'[error] 无法解析时间: {s}（示例：2022-12-14 01:00）')

    since = parse_clamp(args.since) if args.since else None
    until = parse_clamp(args.until) if args.until else None

    files = [(os.path.join(r, n), classify(os.path.join(r, n)))
             for r, _, names in os.walk(args.logdir) for n in names]
    files = [(p, t) for p, t in files if t]
    if not files:
        sys.exit('[error] 未找到可识别的日志文件（access/auth/syslog/audit/mysql/wtmp）')

    skipped = sorted({os.path.basename(p) for p, _ in
                      [(os.path.join(r, n), classify(os.path.join(r, n)))
                       for r, _, names in os.walk(args.logdir) for n in names]
                      if not classify(p)})

    # ---------------- 年份基准
    year = args.year
    if year is None:
        for p, t in files:
            if t == 'access':
                for line in open_text(p).splitlines():
                    m = RE_ACCESS.match(line)
                    if m:
                        ym = re.search(r'/(\d{4}):', m.group(2))
                        if ym:
                            year = int(ym.group(1))
                            break
                if year:
                    break
    if year is None:
        year = datetime.now().year

    web_ips = defaultdict(lambda: {'count': 0, 'first': None, 'last': None,
                                   'ua': Counter(), 'codes': Counter()})
    web_brute = defaultdict(list)       # ip -> [(dt, path, code)]
    ssh_fail = defaultdict(list)        # ip -> [dt]
    ssh_ok = []                         # [(dt, msg)]
    su_events, sudo_events, privesc_events, user_events = [], [], [], []
    sudo_fail = defaultdict(list)       # ip -> [dt]
    cron_change, cron_backdoor = [], []
    cron_all = []                       # [(dt, cmd)]
    mysql_conn, mysql_deny, mysql_risky = [], [], []
    mysql_err_events = []               # [(dt, msg)]
    webshell = defaultdict(list)        # (path, desc) -> [(dt, ip, code)]
    ws_exec = []                        # [(dt, ip, msg)] error.log 中的 PHP 木马执行痕迹
    audit_logins = []                   # [(dt, user, addr, ok)]
    audit_cmds = []                     # [(dt, user, cmd, exe, res)]
    audit_backdoor = []                 # [(dt, cmd, desc)]
    audit_avc = []                      # [(dt, msg)]
    wtmp_logins, wtmp_boots, wtmp_years = [], [], set()
    btmp_fail = defaultdict(list)       # host -> [(dt, user)]
    logins_all = []                     # 统一登录记录（syslog + audit + wtmp）
    seen = set()
    lines_seen = defaultdict(int)
    month_seen = set()

    def in_window(dt):
        if dt is None:
            return False
        if since and dt < since:
            return False
        if until and dt > until:
            return False
        return True

    def dedup(dt, msg):
        key = (dt, msg)
        if key in seen:
            return False
        seen.add(key)
        return True

    def scan_backdoor(cmd):
        for pat, desc in BACKDOOR_PATTERNS:
            if re.search(pat, cmd, re.I):
                return desc
        return None

    def handle_event(dt, proc, msg):
        """处理一条已解析出时间与进程的认证 / 系统事件（多种日志格式复用同一套规则）。"""
        if dt is None or not in_window(dt):
            return
        proc = (proc or '').lower()
        if not dedup(dt, msg):
            return
        if proc in ('sshd', 'su', 'sudo', 'pkexec', 'cron', 'crontab', 'systemd'):
            month_seen.add(dt.strftime('%Y-%m'))

        if msg.startswith('Accepted') or 'Accepted password' in msg or 'Accepted publickey' in msg:
            ssh_ok.append((dt, msg))
            am = re.search(r'for (\S+) from (\S+)', msg)
            logins_all.append((dt, am.group(1) if am else '?', am.group(2) if am else '?', 'ssh'))
        if 'Failed password' in msg or 'authentication failure' in msg:
            # 两种来源：sshd 的 "from IP"，pam 的 "rhost=IP"
            im = re.search(r'from (\d+\.\d+\.\d+\.\d+)', msg) or \
                re.search(r'rhost=(\d+\.\d+\.\d+\.\d+)', msg)
            if im:
                ip = im.group(1)
                if proc == 'sudo' or 'sudo' in msg:
                    sudo_fail[ip].append(dt)
                else:
                    ssh_fail[ip].append(dt)
        if 'Successful su for' in msg or (proc == 'su' and 'session opened' in msg):
            su_events.append((dt, msg))
            sm = re.search(r'session opened for user (\S+)', msg)
            logins_all.append((dt, sm.group(1) if sm else '?', 'local(su)', 'su'))
        if proc == 'sudo' and 'session opened' in msg:
            sudo_events.append((dt, msg))
        if proc in ('useradd', 'usermod', 'userdel', 'groupadd') or 'new user:' in msg:
            if ' to group ' not in msg and 'group added to' not in msg \
                    and 'to shadow group' not in msg:
                user_events.append((dt, msg))
        if proc in ('passwd', 'chpasswd') and 'password changed' in msg:
            user_events.append((dt, f'口令被修改 :: {msg}'))

        for pat, desc in PRIVESC_PATTERNS:
            if re.search(pat, msg, re.I):
                privesc_events.append((dt, f'{desc} :: {msg}'))
                break

        if proc == 'crontab':
            if 'REPLACE' in msg:
                cron_change.append((dt, msg))
            elif 'LIST' in msg:
                cron_change.append((dt, '[查看] ' + msg))
        if proc == 'cron' and 'CMD' in msg:
            cm = re.search(r'CMD \((.*)\)\s*$', msg)
            cmd = cm.group(1) if cm else msg
            cron_all.append((dt, cmd))
            desc = scan_backdoor(cmd)
            if desc:
                cron_backdoor.append((dt, cmd, desc))

    for p, kind in sorted(files):
        # ---------------------------------------------- 二进制登录记录
        if kind == 'utmp':
            is_btmp = os.path.basename(p).lower().startswith('btmp')
            for ut_type, user, line, host, _pid, sec in iter_utmp(p):
                dt = parse_epoch(sec)
                if dt is None or not in_window(dt):
                    continue
                lines_seen['utmp'] += 1
                if ut_type == UT_BOOT_TIME:
                    wtmp_boots.append(dt)
                elif ut_type in (UT_USER_PROCESS, UT_LOGIN_PROCESS):
                    if user == 'UNKNOWN' or not user:
                        continue
                    if is_btmp:
                        # btmp 的失败登录记录 type=6（LOGIN_PROCESS），ssh 场景 host 为来源 IP
                        btmp_fail[host or '?'].append((dt, user))
                    elif ut_type == UT_USER_PROCESS:
                        # wtmp 只认 7：type=6 是 getty 登录提示符，不是真实会话
                        wtmp_logins.append((dt, user, line, host))
                        wtmp_years.add(dt.year)
                        logins_all.append((dt, user, host or 'local', 'wtmp'))
            continue

        # ---------------------------------------------- auditd
        if kind == 'audit':
            for line in open_text(p).splitlines():
                m = RE_AUDIT.match(line)
                if not m:
                    continue
                a_type, epoch, _evid, body = m.groups()
                dt = parse_epoch(epoch)
                if dt is None or not in_window(dt):
                    continue
                lines_seen['audit'] += 1
                month_seen.add(dt.strftime('%Y-%m'))

                if a_type in ('USER_LOGIN', 'USER_AUTH', 'CRED_ACQ'):
                    acct = re.search(r'\bacct="([^"]*)"', body)
                    addr = re.search(r'\baddr=([0-9a-fA-F.:]+)', body)
                    ok = 'res=success' in body or 'res=1' in body
                    user = acct.group(1) if acct else '?'
                    ip = addr.group(1) if addr else '?'
                    audit_logins.append((dt, user, ip, ok))
                    if ok and a_type == 'USER_LOGIN':
                        logins_all.append((dt, user, ip, 'audit'))
                elif a_type == 'USER_CMD':
                    cmd_hex = re.search(r'\bcmd=([0-9a-fA-F]+)', body)
                    exe = re.search(r'\bexe="([^"]*)"', body)
                    raw = decode_hex(cmd_hex.group(1)) if cmd_hex else None
                    if raw:
                        res = 'success' if 'res=success' in body else 'failed'
                        who = re.search(r'\bauid=(\d+)', body)
                        audit_cmds.append((dt, f'uid={who.group(1)}' if who else 'uid=?',
                                           raw, exe.group(1) if exe else '', res))
                        desc = scan_backdoor(raw)
                        if desc:
                            audit_backdoor.append((dt, raw, desc))
                elif a_type == 'EXECVE':
                    parts = RE_AUDIT_ARGV.findall(body)
                    if parts:
                        argv = [v.strip('"') for _, v in sorted(parts, key=lambda x: int(x[0]))]
                        cmd = ' '.join(argv)
                        audit_cmds.append((dt, '进程', cmd, argv[0] if argv else '', 'execve'))
                        desc = scan_backdoor(cmd)
                        if desc:
                            audit_backdoor.append((dt, cmd, desc))
                elif a_type == 'AVC':
                    audit_avc.append((dt, body[:160]))
            continue

        # ---------------------------------------------- MySQL error log
        if kind == 'mysql_err':
            for line in open_text(p).splitlines():
                m = RE_MYSQL_ERR.match(line)
                if not m:
                    continue
                d_, t_, lvl, msg = m.groups()
                try:
                    dt = datetime.strptime(f'{d_} {t_}', '%Y-%m-%d %H:%M:%S')
                except ValueError:
                    continue
                if not in_window(dt):
                    continue
                lines_seen['mysql_err'] += 1
                if 'Access denied' in msg or 'denied' in msg.lower():
                    mysql_deny.append((dt, '-', msg))
                elif 'Aborted connection' in msg or 'ERROR' in lvl:
                    mysql_err_events.append((dt, msg))
            continue

        # ---------------------------------------------- PHP-FPM（木马执行痕迹的高价值来源）
        if kind == 'phpfpm':
            for line in open_text(p).splitlines():
                m = RE_FPM.match(line)
                if not m:
                    continue
                d_, mon, y_, t_, lvl, msg = m.groups()
                try:
                    dt = datetime(int(y_), MONTHS[mon], int(d_),
                                  *[int(x) for x in t_.split(':')])
                except (KeyError, ValueError):
                    continue
                if not in_window(dt):
                    continue
                lines_seen['phpfpm'] += 1
                if is_suspicious_php_error(msg):
                    ws_exec.append((dt, 'fpm', msg[:140]))
            continue

        # ---------------------------------------------- text 日志
        for line in open_text(p).splitlines():
            if not line.strip():
                continue

            # ------------------------------------------------ Web 访问
            if kind == 'access':
                m = RE_ACCESS.match(line)
                if not m:
                    continue
                ip, ts, method, path, code, _size, _ref, ua = m.groups()
                dt = parse_apache_time(ts)
                if dt is None or not in_window(dt):
                    continue
                lines_seen['access'] += 1
                clean = path.split('?')[0]
                rec = web_ips[ip]
                rec['count'] += 1
                rec['first'] = dt if rec['first'] is None or dt < rec['first'] else rec['first']
                rec['last'] = dt if rec['last'] is None or dt > rec['last'] else rec['last']
                if ua:
                    rec['ua'][ua] += 1
                rec['codes'][code] += 1

                if method == 'POST' and is_login_endpoint(clean, path):
                    web_brute[ip].append((dt, clean, code))

                for pat, desc in WEBSHELL_HINTS:
                    if clean.endswith(('.php', '.jsp', '.asp', '.aspx', '.phtml')) \
                            and re.search(pat, clean, re.I):
                        webshell[(clean, desc)].append((dt, ip, code))
                        break
                else:
                    if method == 'POST' and clean.endswith('.php') and code == '200' \
                            and not is_login_endpoint(clean, path) \
                            and not BENIGN_ENTRY.search(clean):
                        webshell[(clean, 'POST 直连 PHP 脚本并返回 200')].append((dt, ip, code))

            # ------------------------------------------------ Apache / nginx error
            elif kind == 'apache_err':
                # 有的发行版把 error.log 也写进 syslog，先兼容带前缀的形态
                ms = RE_SYSLOG.match(line)
                if ms:
                    ts, _host, proc, _pid, msg = ms.groups()
                    lines_seen['error'] += 1
                    dt = parse_syslog_time(ts, year)
                    handle_event(dt, proc, msg)
                    mt = RE_APACHE_TIME.match(msg)
                    if mt:
                        cip, _lvl, text = apache_err_parts(mt.group(2))
                        if cip and is_suspicious_php_error(text) and in_window(dt):
                            ws_exec.append((dt, cip, text[:140]))
                    continue
                mt = RE_APACHE_TIME.match(line)
                if mt:
                    dt = parse_apache_err_time(mt.group(1))
                    if dt and in_window(dt):
                        lines_seen['error'] += 1
                        cip, _lvl, text = apache_err_parts(mt.group(2))
                        if cip and is_suspicious_php_error(text):
                            ws_exec.append((dt, cip, text[:140]))
                    continue
                mn = RE_NGINX_ERR.match(line)
                if mn:
                    t_, _lvl, text = mn.groups()
                    try:
                        dt = datetime.strptime(t_, '%Y/%m/%d %H:%M:%S')
                    except ValueError:
                        dt = None
                    if dt and in_window(dt):
                        lines_seen['error'] += 1
                        if is_suspicious_php_error(text):
                            ws_exec.append((dt, 'nginx', text[:140]))
                    continue

            # ------------------------------------------------ 认证 / 系统
            elif kind in ('auth', 'syslog'):
                m = RE_SYSLOG.match(line)
                if m:
                    ts, _host, proc, _pid, msg = m.groups()
                    dt = parse_syslog_time(ts, year)
                    if in_window(dt):
                        lines_seen[kind] += 1
                    handle_event(dt, proc, msg)
                    continue
                mi = RE_SYSLOG_ISO.match(line)
                if mi:
                    ts, _host, proc, _pid, msg = mi.groups()
                    try:
                        dt = datetime.strptime(ts, '%Y-%m-%dT%H:%M:%S')
                    except ValueError:
                        dt = None
                    if in_window(dt):
                        lines_seen[kind] += 1
                    handle_event(dt, proc, msg)
                    continue

            # ------------------------------------------------ MySQL general log
            elif kind == 'mysql':
                m = RE_MYSQL.match(line)
                if not m:
                    continue
                d_, t_, tid, cmd, arg = m.groups()
                try:
                    dt = datetime.strptime(f'{d_} {t_}', '%Y-%m-%d %H:%M:%S')
                except ValueError:
                    continue
                if not in_window(dt):
                    continue
                lines_seen['mysql'] += 1
                arg = arg.strip()
                if cmd == 'Connect':
                    if 'Access denied' in arg:
                        mysql_deny.append((dt, tid, arg))
                    else:
                        mysql_conn.append((dt, tid, arg))
                elif cmd == 'Query':
                    for pat, desc in MYSQL_RISKY:
                        if re.search(pat, arg, re.I):
                            mysql_risky.append((dt, f'{desc} :: {arg[:160]}'))
                            break

    # MySQL general log 对同一次失败连接会先记 Connect 再记 Access denied，
    # 需剔除这些"看似成功"的 Connect，否则会把爆破尝试误读为登录成功
    deny_ids = {(dt, tid) for dt, tid, _ in mysql_deny}
    mysql_conn = [c for c in mysql_conn if (c[0], c[1]) not in deny_ids]

    # error log 与 general log 会对同一次拒绝双写（一份带连接号、一份不带），
    # 按 (时间, 消息) 去重，优先保留带连接号的那条
    _deny = {}
    for dt, tid, msg in mysql_deny:
        k = (dt, msg.strip())
        if k not in _deny or _deny[k][1] == '-':
            _deny[k] = (dt, tid, msg)
    mysql_deny = sorted(_deny.values())

    off = timedelta(hours=args.tz)

    def fmt(dt):
        return (dt + off).strftime('%Y-%m-%d %H:%M:%S') if dt else '-'

    out = []
    A = out.append

    A('=' * 92)
    A('  Linux 日志快速分诊报告 / Incident Response Log Triage')
    A(f'  目录: {os.path.abspath(args.logdir)}')
    A(f'  时间基准年: {year}    输出时区: UTC{args.tz:+d}')
    if since or until:
        A(f'  时间窗: {args.since or "最早"} ~ {args.until or "最晚"}')
    A('  已解析: ' + ', '.join(f'{k}={v}' for k, v in sorted(lines_seen.items())))
    if skipped:
        A('  未识别文件: ' + ', '.join(skipped[:8]) + (' ...' if len(skipped) > 8 else ''))
    if len(month_seen) > 1:
        A(f'  [提示] 事件跨越多个月份 {sorted(month_seen)}；若同一事件链被拆散，'
          f'用 --since/--until 收窄窗口（环境快照恢复也会造成此现象）')
    if wtmp_years and year not in wtmp_years:
        A(f'  [警告] 基准年 {year} 不在 wtmp 记录年份 {sorted(wtmp_years)} 中——'
          f'syslog 无年份的时间可能补错，建议按 {sorted(wtmp_years)} 复核（wtmp 为绝对时间，可信）')

    # 年份校正：btmp/wtmp 是绝对时间（epoch），而 auth.log 只有月日没有年。
    # 若两边「月-日-时-分」完全重合但年份不同，说明 --year 补错了一年。
    sig_syslog = {(dt.month, dt.day, dt.hour, dt.minute)
                  for evs in ssh_fail.values() for dt in evs}
    sig_utmp = {(dt.month, dt.day, dt.hour, dt.minute): dt.year
                for evs in btmp_fail.values() for dt, _u in evs}
    wrong_years = sorted({sig_utmp[k] for k in sig_syslog & set(sig_utmp)
                          if sig_utmp[k] != year})
    if wrong_years:
        A(f'  [警告] btmp 中有记录的月日时分与 auth.log 完全一致、但年份为 {wrong_years}'
          f'（auth.log 按 {year} 补全）——年份可能错了一年，'
          f'建议用 --year {wrong_years[0]} 复核 syslog 侧结论（btmp 为绝对时间，可信）')
    A('=' * 92)

    # 1. Web 来源
    A('\n【1】Web 访问来源 TOP')
    A(f'{"IP":<20}{"请求数":>7}  {"首次访问":<20}{"末次访问":<20} 状态码 / 主要 UA')
    A('-' * 92)
    for ip, r in sorted(web_ips.items(), key=lambda x: -x[1]['count'])[:15]:
        codes = ','.join(f'{k}:{v}' for k, v in r['codes'].most_common(4))
        ua = r['ua'].most_common(1)[0][0][:26] if r['ua'] else '-'
        A(f'{ip:<20}{r["count"]:>7}  {fmt(r["first"]):<20}{fmt(r["last"]):<20} {codes}  {ua}')

    # 2. 爆破
    A('\n【2】口令爆破 / 暴力登录')
    hit = False
    for ip, evs in sorted(web_brute.items(), key=lambda x: -len(x[1])):
        if len(evs) >= 10:
            hit = True
            tag = '  <<< 疑似暴力破解' if len(evs) >= args.brute_threshold else ''
            A(f'  [Web]  {ip:<18} 登录接口 POST {len(evs)} 次  '
              f'{fmt(evs[0][0])} ~ {fmt(evs[-1][0])}{tag}')
    for ip, evs in sorted(ssh_fail.items(), key=lambda x: -len(x[1])):
        if len(evs) >= 5:
            hit = True
            tag = '  <<< 疑似暴力破解' if len(evs) >= args.brute_threshold else ''
            A(f'  [SSH]  {ip:<18} 认证失败 {len(evs)} 次  '
              f'{fmt(sorted(evs)[0])} ~ {fmt(sorted(evs)[-1])}{tag}')
    for ip, evs in sorted(btmp_fail.items(), key=lambda x: -len(x[1])):
        if len(evs) >= 3:
            hit = True
            users = ','.join(sorted({u for _, u in evs}))[:40]
            A(f'  [btmp] {ip:<18} 失败登录 {len(evs)} 次  '
              f'{fmt(sorted(e[0] for e in evs)[0])} ~ {fmt(sorted(e[0] for e in evs)[-1])}'
              f'  尝试用户 {users}')
    for ip, evs in sorted(sudo_fail.items(), key=lambda x: -len(x[1])):
        if len(evs) >= 3:
            hit = True
            A(f'  [sudo] {ip:<18} sudo 认证失败 {len(evs)} 次  {compress_runs(evs, fmt)}'
              f'  <<< 疑似本地提权尝试')
    if not hit:
        A('  （未达到阈值的失败记录）')

    # 3. 登录成功
    A('\n【3】登录成功记录')
    A(f'  (syslog 时间戳不含年份，已统一按 {year} 补全；日志实际跨年时用 --year 指定事件年份)')
    if ssh_ok:
        for dt, msg in sorted(ssh_ok):
            A(f'  {fmt(dt)}  [ssh]   {msg}')
    if audit_logins:
        A('  --- auditd 登录事件（USER_LOGIN / USER_AUTH / CRED_ACQ）---')
        for dt, user, ip, ok in sorted(audit_logins):
            A(f'  {fmt(dt)}  [audit] {"成功" if ok else "失败"}  {user:<12} <- {ip}')
    if wtmp_logins:
        A('  --- wtmp 登录会话（绕过 syslog 删除也能看到）---')
        for dt, user, line, host in sorted(wtmp_logins):
            A(f'  {fmt(dt)}  [wtmp]  {user:<12} {line:<8} <- {host or "local"}')
    if wtmp_boots:
        A('  --- 重启记录（判断环境快照恢复/时钟异常）---')
        for dt in sorted(wtmp_boots):
            A(f'  {fmt(dt)}  [boot]  系统启动')
    if not (ssh_ok or wtmp_logins or audit_logins):
        A('  （无登录成功记录；务必检查 auth.log.1 / .2.gz 等轮转文件）')

    # 4. 账户与提权
    A('\n【4】账户变更 / 本地提权')
    if user_events:
        for dt, msg in sorted(user_events)[:25]:
            A(f'  {fmt(dt)}  [账户] {msg}')
    for dt, msg in sorted(su_events)[:30]:
        uidm = re.search(r'by \(uid=(\d+)\)', msg)
        who = ''
        if uidm:
            u = int(uidm.group(1))
            who = f'   ← 执行者 uid={u}（{DEFAULT_UID.get(u, "未知")}）'
        A(f'  {fmt(dt)}  [su]   {msg}{who}')
    for dt, msg in sorted(sudo_events)[:20]:
        A(f'  {fmt(dt)}  [sudo] {msg}')
    if audit_cmds:
        A('  --- auditd 命令执行（sudo/execve，按时间）---')
        for dt, who, cmd, exe, res in sorted(audit_cmds)[:25]:
            A(f'  {fmt(dt)}  [audit] {who:<9} {res:<8} {cmd[:110]}')
    if privesc_events:
        A('  --- 提权利用指纹 ---')
        for dt, msg in sorted(privesc_events)[:15]:
            A(f'  {fmt(dt)}  [!!] {msg}')
    if audit_avc:
        A(f'  --- SELinux AVC 拒绝 {len(audit_avc)} 条（常伴随提权尝试）---')
        for dt, msg in sorted(audit_avc)[:5]:
            A(f'  {fmt(dt)}  [AVC] {msg}')
    if not (user_events or su_events or sudo_events or audit_cmds or privesc_events):
        A('  （未匹配已知提权指纹；仍需人工核查 /tmp、SUID、内核版本、sudoers）')

    # 5. 计划任务
    A('\n【5】计划任务变更与可疑执行')
    if cron_change:
        for dt, msg in sorted(cron_change)[:20]:
            A(f'  {fmt(dt)}  [变更] {msg}')
    elif cron_backdoor or audit_backdoor:
        A('  （无 crontab 文件变更记录，但下方存在可疑执行——'
          '可能来自已有计划任务、被篡改的 /etc/cron.d 或交互式会话）')
    else:
        A('  （无 crontab 变更记录；仍需查 /etc/cron.d、/etc/crontab、systemd timer）')
    if cron_backdoor or audit_backdoor:
        A('  --- 命中后门特征的执行记录（按命令聚合）---')
        agg = defaultdict(list)
        for dt, cmd, desc in cron_backdoor + audit_backdoor:
            agg[(cmd, desc)].append(dt)
        for (cmd, desc), times in sorted(agg.items(), key=lambda x: x[1][0]):
            A(f'  [!!] {desc}')
            A(f'       执行: {compress_runs(times, fmt)}')
            A(f'       命令: {cmd[:220]}')
        if cron_all:
            A('  --- 其他 cron 执行样本（末 8 条，用于比对正常基线）---')
            for dt, cmd in sorted(cron_all)[-8:]:
                A(f'  {fmt(dt)}  {cmd[:150]}')

    # 6. WebShell
    A('\n【6】WebShell / 恶意脚本访问线索')
    if webshell:
        for (path, desc), evs in sorted(webshell.items(), key=lambda x: x[1][0][0])[:25]:
            ips = ','.join(sorted({e[1] for e in evs}))
            codes = Counter(e[2] for e in evs)
            code_s = ','.join(f'{k}:{v}' for k, v in codes.most_common())
            A(f'  {path}')
            A(f'      来源 {ips}   命中 {len(evs)} 次   状态码 {code_s}')
            A(f'      时间 {compress_runs([e[0] for e in evs], fmt)}')
            A(f'      判定 {desc}')
            if all(e[2] == '404' for e in evs):
                A('      备注 全部 404 —— 攻击者在试探路径，文件未落地')
            elif any(e[2] == '200' for e in evs):
                A('      备注 存在 200 响应 —— 文件已落地并可访问，需立即上机确认')
    if ws_exec:
        A('  --- error.log 中的脚本执行痕迹（最强落地证据）---')
        agg = defaultdict(list)
        for dt, ip, msg in ws_exec:
            agg[(ip, msg[:80])].append(dt)
        for (ip, msg), times in sorted(agg.items(), key=lambda x: x[1][0])[:10]:
            label = {'fpm': 'php-fpm', 'nginx': 'nginx'}.get(ip, f'client={ip}')
            A(f'  [!!] {label}  {compress_runs(times, fmt)}')
            A(f'       {msg}')
    if not (webshell or ws_exec):
        A('  （未匹配；需结合文件系统 ctime 排查落地文件）')

    # 7. MySQL
    A('\n【7】数据库访问')
    if mysql_deny:
        A('  --- 认证失败（重点：攻击者常在拿到系统口后试探数据库）---')
        for dt, tid, msg in sorted(mysql_deny):
            A(f'  {fmt(dt)}  [拒绝] [{tid}] {msg}')
    if mysql_conn:
        A('  --- 成功连接 ---')
        for dt, tid, msg in sorted(mysql_conn)[:30]:
            A(f'  {fmt(dt)}  [连接] [{tid}] {msg}')
    if mysql_risky:
        A('  --- 高危 SQL ---')
        for dt, msg in sorted(mysql_risky)[:15]:
            A(f'  {fmt(dt)}  [!!] {msg}')
    if mysql_err_events:
        A('  --- error log 异常 ---')
        for dt, msg in sorted(mysql_err_events)[:10]:
            A(f'  {fmt(dt)}  [err] {msg[:130]}')
    if not (mysql_deny or mysql_conn or mysql_risky or mysql_err_events):
        A('  （无 MySQL 日志；确认 general_log 是否开启，或 log_error 是否指向别处）')

    # 8. 统一时间线
    A('\n【8】统一时间线（关键事件）')
    A('-' * 92)
    timeline = []
    timeline += [(dt, '认证', m[:110]) for dt, m in ssh_ok]
    timeline += [(dt, 'su  ', m[:110]) for dt, m in su_events]
    timeline += [(dt, 'sudo', m[:110]) for dt, m in sudo_events]
    timeline += [(dt, '提权', m[:110]) for dt, m in privesc_events]
    timeline += [(dt, 'cron', m[:110]) for dt, m in cron_change]
    timeline += [(dt, '后门', f'{d} :: {c[:90]}') for dt, c, d in cron_backdoor + audit_backdoor]
    timeline += [(dt, 'MySQL', f'[{t}] {m[:100]}') for dt, t, m in mysql_conn]
    timeline += [(dt, 'MySQL', f'[拒绝][{t}] {m[:90]}') for dt, t, m in mysql_deny]
    timeline += [(dt, '账户', m[:110]) for dt, m in user_events]
    timeline += [(dt, 'audit', f'{w} {c[:100]}') for dt, w, c, _e, _r in audit_cmds[:60]]
    timeline += [(dt, 'wtmp', f'{u} <- {h}') for dt, u, _l, h in wtmp_logins]
    timeline += [(dt, 'boot', '系统启动') for dt in wtmp_boots]
    for (path, desc), evs in webshell.items():
        first = min(e[0] for e in evs)
        ips = ','.join(sorted({e[1] for e in evs}))
        timeline.append((first, 'Web', f'{ips} -> {path}  ({desc})'))
    for dt, ip, msg in ws_exec[:20]:
        label = {'fpm': 'php-fpm', 'nginx': 'nginx'}.get(ip, f'client={ip}')
        timeline.append((dt, '执行', f'{label} {msg[:90]}'))

    if timeline:
        for dt, tag, msg in sorted(timeline, key=lambda x: x[0]):
            A(f'  {fmt(dt)}  [{tag}] {msg}')
    else:
        A('  （无可归入时间线的事件）')

    # 9. IOC
    A('\n【9】IOC 快速清单（可直接用于封禁与全盘排查）')
    attackers = {}
    for ip, evs in web_brute.items():
        if len(evs) >= 10:
            attackers.setdefault(ip, []).append(f'Web 登录爆破 {len(evs)} 次')
    for (path, _d), evs in webshell.items():
        for e in evs:
            if e[2] == '200':
                attackers.setdefault(e[1], []).append(f'WebShell 访问 {path}')
    for ip, evs in ssh_fail.items():
        if len(evs) >= 5:
            attackers.setdefault(ip, []).append(f'SSH 认证失败 {len(evs)} 次')
    for ip, evs in btmp_fail.items():
        if len(evs) >= 3:
            attackers.setdefault(ip, []).append(f'btmp 失败登录 {len(evs)} 次')
    for dt, ip, _m in ws_exec:
        if re.match(r'^[0-9a-fA-F:.]{3,}$', ip):
            attackers.setdefault(ip, []).append('错误日志记录的脚本执行')

    # 关联规则：既尝试过登录接口、又访问了落地成功（200）的木马 ——
    # 即使失败次数没达到爆破阈值，也应按攻击者处理（弱口令一次成功的场景）
    ws_200 = {e[1] for evs in webshell.values() for e in evs if e[2] == '200'}
    for ip in ws_200:
        if web_brute.get(ip) and ip not in attackers:
            attackers[ip] = [f'登录接口尝试 {len(web_brute[ip])} 次 + 访问落地木马']

    if attackers:
        A('  -- 攻击者 IP --')
        for ip, why in sorted(attackers.items(), key=lambda x: -len(x[1])):
            A(f'    {ip:<18} {"; ".join(sorted(set(why)))[:100]}')
        ops = [ip for ip in web_ips if ip not in attackers]
        if ops:
            A('  -- 同期其他 Web 来源（无爆破/上传行为，倾向运维，需人工确认）--')
            A('    ' + ', '.join(sorted(ops)[:12]))
    else:
        A('  （未识别出明确攻击者 IP）')

    ws_status = {}
    for (p, _d), evs in webshell.items():
        # 同一路径既有 404 试探又有 200 命中时，以"已落地"为准
        if any(e[2] == '200' for e in evs) or ws_status.get(p) == '已落地(200)':
            ws_status[p] = '已落地(200)'
        else:
            ws_status[p] = '仅试探(无 200)'
    if ws_status:
        A('  -- 可疑文件路径 --')
        for f in sorted(ws_status, key=lambda x: (ws_status[x] != '已落地(200)', x))[:12]:
            A(f'    {f}  [{ws_status[f]}]')
    c2 = set()
    for _dt, cmd, _d in cron_backdoor + audit_backdoor:
        c2 |= extract_c2(cmd)
    if c2:
        A('  -- 外联地址（后门载荷中提取，含 base64 解码）--')
        for a in sorted(c2):
            A(f'    {a}')
    new_users = []
    _seen_u = set()
    for dt, msg in user_events:
        # 只认 "new user:"，否则新建同名 group 会被误当成账户重复列出
        um = re.search(r'new user: name=([\w.-]+)', msg) or re.search(r'new user: (\w+)', msg)
        if not um:
            continue
        key = (um.group(1), fmt(dt))
        if key in _seen_u:
            continue
        _seen_u.add(key)
        new_users.append(f'{um.group(1)} @ {fmt(dt)}')
    if new_users:
        A('  -- 新建/变更账户 --')
        for u in new_users[:10]:
            A(f'    {u}')
    if not (attackers or ws_status or c2 or new_users):
        A('  （本次未提取到可用 IOC）')

    # 10. 下一步
    A('\n【10】下一步必查项（日志无法覆盖，需上机取证）')
    A('  · 落地文件：find / -xdev -newermt "<窗口起点>" -type f 2>/dev/null')
    A('  · 时间戳：stat 看 ctime，mtime 可能被 touch 伪造——以 ctime 为准')
    A('  · 持久化：/etc/cron.d /etc/crontab /etc/rc.local systemd unit')
    A('            ~/.ssh/authorized_keys /etc/ld.so.preload /etc/profile.d/')
    A('  · 提权残留：ls -la /tmp /dev/shm /var/tmp；find / -perm -4000 -newer <基准>')
    A('  · 账户：awk -F: \'$3==0\' /etc/passwd；核对新增 UID、空口令账户')
    A('  · Web：站点目录内 php 按 ctime 排序；grep -rE "eval|assert|base64_decode|system\\(" ')
    A('  · 网络：ss -antp 查异常外连；iptables -L 查放通规则')
    A('  · journal：日志目录含 journal/ 时，用 journalctl -D <dir> --since "<起点>" 另查')
    A('')

    print('\n'.join(out))


if __name__ == '__main__':
    main()
