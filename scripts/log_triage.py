#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Linux 日志快速分诊器 / Linux log triage for incident response.

扫描一个日志目录（可含轮转文件、gz 压缩），自动提取入侵线索并输出统一时间线。

用法:
    python3 log_triage.py <log_dir> [--year 2022] [--tz 8] [--brute-threshold 50]

示例:
    python3 log_triage.py ./var/log --year 2022
    python3 log_triage.py /var/log --tz 8

设计原则:
  - 只读，不修改任何日志
  - 容错：空文件、非 UTF-8、gzip、格式混杂都不应中断分析
  - auth.log 与 syslog 常重复记录同一事件，需按 (时间, 原文) 去重
  - 输出到 stdout，便于重定向或二次处理
"""

import argparse
import gzip
import os
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime, timedelta

# ---------------------------------------------------------------- 正则

# Apache / Nginx combined:
# 1.2.3.4 - - [14/Dec/2022:01:52:39 +0000] "GET /x HTTP/1.1" 200 1234 "ref" "ua"
RE_ACCESS = re.compile(
    r'^(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"([A-Z]+)\s+(\S+?)(?:\s+\S+)?"\s+(\d{3})\s+(\S+)'
    r'(?:\s+"([^"]*)"\s+"([^"]*)")?'
)

# syslog 系: Dec 14 01:56:48 host proc[pid]: msg
RE_SYSLOG = re.compile(
    r'^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+([\w./\-]+?)(?:\[(\d+)\])?:\s(.*)$'
)

# MySQL general log: 2022-12-14T02:07:13.892649Z  10 Connect  lee@localhost on  using Socket
RE_MYSQL = re.compile(
    r'^(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2}:\d{2})(?:\.\d+)?Z?\s+(\d+)\s+'
    r'(Connect|Query|Quit|Init DB|Field|Prepare|Execute|Close stmt|Statistics|Shutdown)\s*(.*)$'
)

# ---------------------------------------------------------------- 指纹

# 后门 / 反弹 shell 特征
BACKDOOR_PATTERNS = [
    (r'base64\s*-d.*\|\s*(?:ba)?sh', 'Base64 编码管道执行（无文件落地）'),
    (r'/dev/tcp/', 'bash /dev/tcp 反弹 Shell'),
    (r'\bnc\b[^|]*\s-e\s', 'netcat -e 反弹 Shell'),
    (r'curl[^|]*\|\s*(?:ba)?sh', 'curl 管道执行'),
    (r'wget[^|]*\|\s*(?:ba)?sh', 'wget 管道执行'),
    (r'python[0-9.]*\s+-c[^|]*socket', 'Python 反弹 Shell'),
    (r'perl\s+-e[^|]*socket', 'Perl 反弹 Shell'),
    (r'chmod\s+\+x[^|]*(?:/tmp|/dev/shm|/var/tmp)', '临时目录植入可执行文件'),
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
]

MONTHS = {m: i for i, m in enumerate(
    ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'], 1)}

DEFAULT_UID = {0: 'root', 33: 'www-data', 1000: 'ubuntu', 111: 'mysql', 1001: 'lee'}


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


def classify(path):
    """按文件名判断日志类型。"""
    base = os.path.basename(path).lower()
    if base.startswith('access') or base.endswith('-access.log') or 'access_log' in base:
        return 'access'
    if base.startswith('error') or base.endswith('-error.log') or 'error_log' in base:
        return 'error'
    if base.startswith('auth') or base.startswith('secure') or base.startswith('sshd'):
        return 'auth'
    if base.startswith('cron') or base.startswith('syslog') or base.startswith('messages'):
        return 'syslog'
    if 'mysql' in base or 'general' in base or base.startswith('slow'):
        return 'mysql'
    return None


def compress_runs(times, fmt):
    """把一串时间点压缩成 '首次 ~ 末次（N 次）'，避免刷屏。"""
    if not times:
        return '-'
    times = sorted(times)
    if len(times) == 1:
        return fmt(times[0])
    return f'{fmt(times[0])} ~ {fmt(times[-1])}（{len(times)} 次）'


def main():
    ap = argparse.ArgumentParser(description='Linux 日志快速分诊（应急响应）')
    ap.add_argument('logdir', help='日志目录')
    ap.add_argument('--year', type=int, default=None,
                    help='syslog 缺失年份时使用（默认从 access.log 推断，否则当前年）')
    ap.add_argument('--tz', type=int, default=0, help='输出时间线的时区偏移，8 表示 UTC+8（默认 0）')
    ap.add_argument('--brute-threshold', type=int, default=50, help='判定暴力的失败次数阈值')
    args = ap.parse_args()

    if not os.path.isdir(args.logdir):
        sys.exit(f'[error] 不是目录: {args.logdir}')

    files = [(os.path.join(r, n), classify(os.path.join(r, n)))
             for r, _, names in os.walk(args.logdir) for n in names]
    files = [(p, t) for p, t in files if t]
    if not files:
        sys.exit('[error] 未找到可识别的日志文件（access/auth/cron/mysql）')

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
    web_brute = defaultdict(list)       # ip -> [(dt, path)]
    ssh_fail = defaultdict(list)        # ip -> [dt]
    ssh_ok = []                         # [(dt, msg)]
    su_events, sudo_events, privesc_events, user_events = [], [], [], []
    cron_change, cron_backdoor = [], []  # [(dt, msg)] / [(dt, cmd, desc)]
    cron_all = []                        # [(dt, cmd)]
    mysql_conn, mysql_deny, mysql_risky = [], [], []
    webshell = defaultdict(list)         # (path, desc) -> [(dt, ip, code)]
    seen = set()                         # 跨文件去重
    lines_seen = defaultdict(int)
    year_conflict = set()

    def dedup(dt, msg):
        key = (dt, msg)
        if key in seen:
            return False
        seen.add(key)
        return True

    for p, kind in sorted(files):
        for line in open_text(p).splitlines():
            if not line.strip():
                continue
            lines_seen[kind] += 1

            # ------------------------------------------------ Web 访问
            if kind == 'access':
                m = RE_ACCESS.match(line)
                if not m:
                    continue
                ip, ts, method, path, code, size, ref, ua = m.groups()
                dt = parse_apache_time(ts)
                if dt is None:
                    continue
                clean = path.split('?')[0]
                rec = web_ips[ip]
                rec['count'] += 1
                rec['first'] = dt if rec['first'] is None or dt < rec['first'] else rec['first']
                rec['last'] = dt if rec['last'] is None or dt > rec['last'] else rec['last']
                if ua:
                    rec['ua'][ua] += 1
                rec['codes'][code] += 1

                # 登录入口的 POST —— 爆破候选
                if method == 'POST' and is_login_endpoint(clean, path):
                    web_brute[ip].append((dt, clean, code))

                # 可疑脚本路径
                for pat, desc in WEBSHELL_HINTS:
                    if clean.endswith(('.php', '.jsp', '.asp', '.aspx', '.phtml')) \
                            and re.search(pat, clean, re.I):
                        webshell[(clean, desc)].append((dt, ip, code))
                        break
                else:
                    # POST 直连 PHP 且 200 —— 交互式木马特征
                    if method == 'POST' and clean.endswith('.php') and code == '200' \
                            and not is_login_endpoint(clean, path) \
                            and not BENIGN_ENTRY.search(clean):
                        webshell[(clean, 'POST 直连 PHP 脚本并返回 200')].append((dt, ip, code))

            # ------------------------------------------------ 认证 / 系统
            elif kind in ('auth', 'syslog', 'error'):
                m = RE_SYSLOG.match(line)
                if not m:
                    continue
                ts, host, proc, pid, msg = m.groups()
                dt = parse_syslog_time(ts, year)
                if dt is None:
                    continue
                proc = (proc or '').lower()

                if not dedup(dt, msg):
                    continue

                # 跨年检测：syslog 中出现与基准年不同的真实年份无法直接判断，
                # 但若时间明显晚于 access 窗口（> 30 天），提示可能存在时钟异常
                if dt.year == year and proc in ('sshd', 'su', 'sudo', 'pkexec', 'cron', 'crontab'):
                    year_conflict.add(dt.strftime('%Y-%m'))

                if msg.startswith('Accepted') or 'Accepted password' in msg or 'Accepted publickey' in msg:
                    ssh_ok.append((dt, msg))
                if 'Failed password' in msg or 'authentication failure' in msg:
                    im = re.search(r'from (\d+\.\d+\.\d+\.\d+)', msg)
                    if im:
                        ssh_fail[im.group(1)].append(dt)
                if 'Successful su for' in msg or (proc == 'su' and 'session opened' in msg):
                    su_events.append((dt, msg))
                if proc == 'sudo' and 'session opened' in msg:
                    sudo_events.append((dt, msg))
                if proc in ('useradd', 'usermod', 'userdel', 'groupadd') or 'new user:' in msg:
                    # 过滤 "add 'x' to group" 类噪音，只保留建号/改口令等高价值事件
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
                    for pat, desc in BACKDOOR_PATTERNS:
                        if re.search(pat, cmd, re.I):
                            cron_backdoor.append((dt, cmd, desc))
                            break

            # ------------------------------------------------ MySQL
            elif kind == 'mysql':
                m = RE_MYSQL.match(line)
                if not m:
                    continue
                d_, t_, tid, cmd, arg = m.groups()
                try:
                    dt = datetime.strptime(f'{d_} {t_}', '%Y-%m-%d %H:%M:%S')
                except ValueError:
                    continue
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

    off = timedelta(hours=args.tz)

    def fmt(dt):
        return (dt + off).strftime('%Y-%m-%d %H:%M:%S') if dt else '-'

    out = []
    A = out.append

    A('=' * 80)
    A('  Linux 日志快速分诊报告 / Incident Response Log Triage')
    A(f'  目录: {os.path.abspath(args.logdir)}')
    A(f'  时间基准年: {year}    输出时区: UTC{args.tz:+d}')
    A(f'  已解析行数: ' + ', '.join(f'{k}={v}' for k, v in sorted(lines_seen.items())))
    if len(year_conflict) > 1:
        A(f'  [注意] 日志跨越多个年月 {sorted(year_conflict)}，可能存在环境重置或时钟异常')
    A('=' * 80)

    # 1. Web 来源
    A('\n【1】Web 访问来源 TOP')
    A(f'{"IP":<18}{"请求数":>8}  {"首次访问":<20}{"末次访问":<20} 状态码')
    A('-' * 80)
    for ip, r in sorted(web_ips.items(), key=lambda x: -x[1]['count'])[:15]:
        codes = ','.join(f'{k}:{v}' for k, v in r['codes'].most_common(4))
        A(f'{ip:<18}{r["count"]:>8}  {fmt(r["first"]):<20}{fmt(r["last"]):<20} {codes}')

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
    if not hit:
        A('  （未达到阈值的失败记录）')

    # 3. 登录成功
    A('\n【3】登录成功记录')
    A(f'  (syslog 时间戳不含年份，已统一按 {year} 补全；日志实际跨年时用 --year 指定事件年份)')
    if ssh_ok:
        for dt, msg in sorted(ssh_ok):
            A(f'  {fmt(dt)}  {msg}')
    else:
        A('  （无 Accepted 记录；务必检查 auth.log.1 / .2.gz 等轮转文件）')

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
    if privesc_events:
        A('  --- 提权利用指纹 ---')
        for dt, msg in sorted(privesc_events)[:15]:
            A(f'  {fmt(dt)}  [!!] {msg}')
    else:
        A('  （未匹配已知提权指纹；仍需人工核查 /tmp、SUID、内核版本、sudoers）')

    # 5. 计划任务
    A('\n【5】计划任务变更与可疑执行')
    if cron_change:
        for dt, msg in sorted(cron_change)[:20]:
            A(f'  {fmt(dt)}  [变更] {msg}')
    else:
        A('  （无 crontab 变更记录；仍需查 /etc/cron.d、/etc/crontab、systemd timer）')
    if cron_backdoor:
        A('  --- 命中后门特征的 cron（按命令聚合）---')
        agg = defaultdict(list)
        for dt, cmd, desc in cron_backdoor:
            agg[(cmd, desc)].append(dt)
        for (cmd, desc), times in sorted(agg.items(), key=lambda x: x[1][0]):
            A(f'  [!!] {desc}')
            A(f'       执行: {compress_runs(times, fmt)}')
            A(f'       命令: {cmd[:220]}')
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
    else:
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
    if not (mysql_deny or mysql_conn):
        A('  （无 MySQL 通用日志；确认 general_log 是否开启）')

    # 8. 统一时间线
    A('\n【8】统一时间线（关键事件）')
    A('-' * 80)
    timeline = []
    timeline += [(dt, '认证', m[:110]) for dt, m in ssh_ok]
    timeline += [(dt, 'su  ', m[:110]) for dt, m in su_events]
    timeline += [(dt, 'sudo', m[:110]) for dt, m in sudo_events]
    timeline += [(dt, '提权', m[:110]) for dt, m in privesc_events]
    timeline += [(dt, 'cron', m[:110]) for dt, m in cron_change]
    timeline += [(dt, '后门', f'{d} :: {c[:90]}') for dt, c, d in cron_backdoor]
    timeline += [(dt, 'MySQL', f'[{t}] {m[:100]}') for dt, t, m in mysql_conn]
    timeline += [(dt, 'MySQL', f'[拒绝][{t}] {m[:90]}') for dt, t, m in mysql_deny]
    timeline += [(dt, '账户', m[:110]) for dt, m in user_events]
    for (path, desc), evs in webshell.items():
        first = min(e[0] for e in evs)
        ips = ','.join(sorted({e[1] for e in evs}))
        timeline.append((first, 'Web', f'{ips} -> {path}  ({desc})'))

    if timeline:
        for dt, tag, msg in sorted(timeline, key=lambda x: x[0]):
            A(f'  {fmt(dt)}  [{tag}] {msg}')
    else:
        A('  （无可归入时间线的事件）')

    # 9. 下一步
    A('\n【9】下一步必查项（日志无法覆盖，需上机取证）')
    A('  · 落地文件：find / -xdev -newermt "<窗口起点>" -type f 2>/dev/null')
    A('  · 时间戳：stat 看 ctime，mtime 可能被 touch 伪造——以 ctime 为准')
    A('  · 持久化：/etc/cron.d /etc/crontab /etc/rc.local systemd unit')
    A('            ~/.ssh/authorized_keys /etc/ld.so.preload /etc/profile.d/')
    A('  · 提权残留：ls -la /tmp /dev/shm /var/tmp；find / -perm -4000 -newer <基准>')
    A('  · 账户：awk -F: \'$3==0\' /etc/passwd；核对新增 UID、空口令账户')
    A('  · Web：站点目录内 php 按 ctime 排序；grep -rE "eval|assert|base64_decode|system\\(" ')
    A('  · 网络：ss -antp 查异常外连；iptables -L 查放通规则')
    A('')

    print('\n'.join(out))


if __name__ == '__main__':
    main()
