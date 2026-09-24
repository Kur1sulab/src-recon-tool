# -*- coding: utf-8 -*-
"""常用端口扫描（纯 Python socket，零外部依赖）。

安全约束（设计即边界）：
  - 默认只扫内置常用端口表（~100 个，参考 nmap top-ports 思路 + 国内常见服务）；
  - 并发 ≤32、连接超时默认 1.5s、banner 抓取每步等待 ≤1s；
  - banner 以**被动接收**为主，收不到时最多补发一个换行（对服务无副作用）催一次；
    HTTP 端口则补一个只读的 HEAD 请求——全程不发送任何可能改变状态的输入；
  - 域名目标先解析（取首个 A 记录），解析失败优雅降级为空结果；
  - ⚠️ 仅限授权目标：未授权端口扫描是违法行为，README/输出中均已注明。

输出 out/<target>/ports.json + ports.txt。
"""
import concurrent.futures
import ipaddress
import json
import re
import socket

try:                                  # 作为包导入时（tests / recon.py）用相对导入
    from . import netutil
except ImportError:                   # 直接执行本文件时的兜底
    import netutil

DEFAULT_TIMEOUT = 1.5                 # 单端口连接超时（秒）
DEFAULT_WORKERS = 32                  # 并发上限（克制）
BANNER_WAIT = 1.0                     # banner 抓取单步等待（秒）
MAX_PORT_RANGE = 8192                 # 单段 --ports a-b 最大跨度（防失控）

# (端口, 常见服务名)，~100 个常用端口
COMMON_PORTS = [
    (21, "ftp"), (22, "ssh"), (23, "telnet"), (25, "smtp"), (53, "dns"),
    (69, "tftp"), (80, "http"), (81, "http-alt"), (88, "kerberos"), (110, "pop3"),
    (111, "rpcbind"), (135, "msrpc"), (139, "netbios-ssn"), (143, "imap"), (161, "snmp"),
    (389, "ldap"), (443, "https"), (445, "smb"), (465, "smtps"), (500, "isakmp"),
    (514, "syslog"), (515, "printer"), (548, "afp"), (554, "rtsp"), (587, "submission"),
    (623, "ipmi"), (636, "ldaps"), (873, "rsync"), (993, "imaps"), (995, "pop3s"),
    (1080, "socks"), (1099, "java-rmi"), (1194, "openvpn"), (1433, "mssql"), (1434, "mssql-dac"),
    (1521, "oracle"), (1723, "pptp"), (1883, "mqtt"), (2049, "nfs"), (2082, "cpanel"),
    (2083, "cpanel-ssl"), (2181, "zookeeper"), (2375, "docker"), (2376, "docker-tls"),
    (2379, "etcd"), (3128, "squid"), (3268, "ldap-gc"), (3306, "mysql"), (3389, "rdp"),
    (5432, "postgresql"), (5555, "adb"), (5601, "kibana"), (5672, "amqp"), (5900, "vnc"),
    (5984, "couchdb"), (6379, "redis"), (6443, "k8s-api"), (7001, "weblogic"), (7002, "weblogic-ssl"),
    (8000, "http-alt"), (8001, "http-alt"), (8009, "ajp"), (8010, "http-alt"), (8069, "odoo"),
    (8080, "http-proxy"), (8081, "http-alt"), (8088, "http-alt"), (8089, "http-alt"), (8090, "http-alt"),
    (8161, "activemq"), (8181, "http-alt"), (8443, "https-alt"), (8500, "consul"), (8848, "nacos"),
    (8899, "http-alt"), (9000, "http-alt"), (9001, "http-alt"), (9042, "cassandra"), (9090, "http-alt"),
    (9092, "kafka"), (9200, "elasticsearch"), (9300, "es-cluster"), (9999, "http-alt"), (10000, "webmin"),
    (10050, "zabbix-agent"), (10051, "zabbix"), (11211, "memcached"), (15672, "rabbitmq-mgmt"),
    (27017, "mongodb"), (27018, "mongodb"), (27019, "mongodb"), (28017, "mongo-web"),
    (50000, "sap"), (50070, "hadoop-namenode"), (61616, "activemq"), (18080, "http-alt"),
]
_PORT_NAME = dict(COMMON_PORTS)

# 可能跑 HTTP 的端口：banner 被动收不到时用只读 HEAD 探测
_HTTP_LIKELY = {80, 81, 443, 591, 7001, 8000, 8001, 8008, 8009, 8010, 8069, 8080, 8081,
                8088, 8089, 8090, 8161, 8181, 8443, 8848, 8899, 9000, 9001, 9090, 9200,
                9443, 9999, 10000, 18080, 28017}

# banner → 服务名（小写匹配，顺序即优先级）
_SIGS = [
    ("SSH",        lambda b: b.startswith("ssh-")),
    ("HTTP",       lambda b: b.startswith("http/")),
    ("FTP",        lambda b: b.startswith("220") and any(k in b for k in ("ftp", "vsftpd", "proftpd", "filezilla", "pure-ftpd"))),
    ("SMTP",       lambda b: "esmtp" in b or "smtp" in b or b.startswith("220") and "mail" in b),
    ("Redis",      lambda b: "redis" in b or b.startswith("-err") or "+pong" in b),
    ("Memcached",  lambda b: "memcached" in b or b == "error"),
    ("MySQL",      lambda b: "mysql" in b or "mariadb" in b),
    ("MongoDB",    lambda b: "mongodb" in b),
    ("VNC",        lambda b: b.startswith("rfb ")),
    ("AMQP",       lambda b: "amqp" in b),
    ("Elasticsearch", lambda b: "elasticsearch" in b or "cluster_name" in b),
    ("Telnet",     lambda b: "login:" in b or "password:" in b),
]


def parse_ports(spec: str = "") -> list:
    """'80,443,8000-8100' → 有序去重端口表；空 → 内置常用端口表。

    非法段跳过并告警；单段跨度 >8192 截断（防失控扫描）。
    """
    if not spec or not spec.strip():
        return sorted(p for p, _n in COMMON_PORTS)
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, _, b = part.partition("-")
            try:
                lo, hi = int(a), int(b)
            except ValueError:
                print(f"[!] 端口段 '{part}' 非法，忽略")
                continue
            lo, hi = max(1, lo), min(65535, hi)
            if lo > hi:
                print(f"[!] 端口段 '{part}' 范围颠倒，忽略")
                continue
            if hi - lo + 1 > MAX_PORT_RANGE:
                print(f"[!] 端口段 '{part}' 跨度过大（>{MAX_PORT_RANGE}），截断")
                hi = lo + MAX_PORT_RANGE - 1
            ports.update(range(lo, hi + 1))
        else:
            try:
                p = int(part)
            except ValueError:
                print(f"[!] 端口 '{part}' 非法，忽略")
                continue
            if 1 <= p <= 65535:
                ports.add(p)
            else:
                print(f"[!] 端口 '{part}' 超出 1-65535，忽略")
    return sorted(ports)


def classify_banner(banner: str, port: int) -> str:
    """banner 特征 → 服务名；认不出时退回端口表里的常见服务名。"""
    b = (banner or "").strip().lower()
    for name, test in _SIGS:
        try:
            if test(b):
                return name
        except Exception:
            continue
    return _PORT_NAME.get(port, "")


def _recv_some(s: socket.socket, wait: float = BANNER_WAIT) -> bytes:
    try:
        s.settimeout(wait)
        return s.recv(512)
    except OSError:
        return b""


def _grab_banner(s: socket.socket, port: int) -> str:
    """被动收 banner；收不到时补一次最小探测（HTTP 口发只读 HEAD，其余发换行）。"""
    data = _recv_some(s)
    if not data:
        try:
            if port in _HTTP_LIKELY:
                s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")     # 只读请求，无副作用
            else:
                s.sendall(b"\r\n")                        # 空行：多数服务回一条错误/横幅
            data = _recv_some(s)
        except OSError:
            data = b""
    text = data[:512].decode("utf-8", "replace")
    return re.sub(r"\s+", " ", text).strip()[:200]


def scan_port(host: str, port: int, timeout: float = DEFAULT_TIMEOUT) -> dict:
    """TCP connect + 轻量 banner；返回 {port, open, service, banner}（不抛异常）。"""
    row = {"port": port, "open": False, "service": "", "banner": ""}
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            row["open"] = True
            row["banner"] = _grab_banner(s, port)
    except OSError:
        pass
    if row["open"]:
        row["service"] = classify_banner(row["banner"], port)
    return row


def render_txt(r: dict) -> str:
    L = [f"# 端口扫描 — {r['target']}（{r.get('ip') or '解析失败'}）",
         f"- 扫描 {r.get('scanned', 0)} 个端口（常用端口表，并发 ≤{DEFAULT_WORKERS}，超时 {r.get('timeout')}s）",
         "- 声明: 仅限授权目标；服务名是启发式识别，以人工复核为准\n"]
    open_rows = r.get("open") or []
    if not open_rows:
        L.append("（开放端口：无）")
    for row in open_rows:
        b = f"  banner: {row['banner']}" if row.get("banner") else ""
        L.append(f"[+] {row['port']}/tcp  {row.get('service') or '未知'}{b}")
    return "\n".join(L) + "\n"


def run_portscan(target: str, out: str, ports="", timeout: float = DEFAULT_TIMEOUT,
                 workers: int = DEFAULT_WORKERS) -> list:
    """target 接受域名或 IP；域名先解析首个 A 记录，两者都记入产出。"""
    print(f"[*] 端口扫描: {target}（仅限授权目标；未授权扫描违法）")
    out = netutil.safe_outdir(out)            # 目录穿越防御（见 netutil.safe_outdir）
    timeout = max(0.2, min(float(timeout), 10))
    workers = max(1, min(int(workers), DEFAULT_WORKERS))
    port_list = parse_ports(ports if isinstance(ports, str) else ",".join(str(p) for p in ports))
    host, ip = target, ""
    try:
        ipaddress.ip_address(target)
        ip = target
    except ValueError:
        try:
            infos = socket.getaddrinfo(target, None, socket.AF_INET)
            ip = infos[0][4][0]
            print(f"[*] {target} -> {ip}")
        except OSError as e:
            print(f"[!] 域名解析失败（{e}），输出空结果（优雅降级）")
    result = {"target": target, "ip": ip, "scanned": len(port_list), "timeout": timeout,
              "open": []}
    if ip:
        print(f"[*] 扫描 {len(port_list)} 个常用端口（并发 ≤{workers}，连接超时 {timeout}s）")
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
            # map 保序；每个线程独立建连，无共享可变状态（并发安全）
            for r in ex.map(lambda p: scan_port(ip, p, timeout), port_list):
                if r["open"]:
                    result["open"].append(r)
                    b = f"  banner: {r['banner'][:60]}" if r["banner"] else ""
                    print(f"[+] {ip}:{r['port']} 开放  {r['service'] or '未知服务'}{b}")
    result["open"].sort(key=lambda x: x["port"])
    safe_write_payload = json.dumps(result, ensure_ascii=False, indent=2)
    p1 = netutil.safe_write(out, "ports.json", safe_write_payload)
    netutil.safe_write(out, "ports.txt", render_txt(result))
    print(f"[+] 端口扫描完成：开放 {len(result['open'])}/{len(port_list)} -> {p1}")
    return result["open"]


if __name__ == "__main__":
    import sys
    run_portscan(sys.argv[1], "out")
