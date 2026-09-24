# -*- coding: utf-8 -*-
"""portscan 模块：解析/识别单测 + 本机可控 socket 靶标集成测试。

关注点：
  1) parse_ports：默认表规模合理、区间/去重/非法输入、超大区间截断（防失控）；
  2) classify_banner：常见服务 banner 特征识别 + 端口名兜底；
  3) 集成：本机起 SSH 样/Redis 样/静默三个 TCP 靶标 + 一个确定关闭的端口，
     验证开放判定与服务识别；关闭端口不误报；
  4) 域名解析失败优雅降级（mock，不碰真网）。
"""
import json
import os
import socket
import socketserver
import sys
import threading
import unittest
from contextlib import redirect_stdout
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))

OUT = os.path.join(ROOT, "out", "_unittest_ports")


def _quiet(fn, *a, **kw):
    buf = io_stringio()
    with redirect_stdout(buf):
        return fn(*a, **kw)


def io_stringio():
    import io
    return io.StringIO()


class _PushHandler(socketserver.BaseRequestHandler):
    """连上就推一条 SSH 样横幅（真实 SSH 的行为）。"""
    payload = b"SSH-2.0-OpenSSH_9.0\r\n"

    def handle(self):
        try:
            self.request.sendall(self.payload)
        except Exception:
            pass


class _EchoErrHandler(socketserver.BaseRequestHandler):
    """收一行再回 Redis 样错误（真实 Redis 对未知命令的行为）。"""

    def handle(self):
        try:
            self.request.recv(256)
            self.request.sendall(b"-ERR unknown command 'q'\r\n")
        except Exception:
            pass


class _SilentHandler(socketserver.BaseRequestHandler):
    """什么都不发（连接成功但无横幅 → 服务未知，不算误报）。"""

    def handle(self):
        pass


class TestParsePorts(unittest.TestCase):
    def test_default_table(self):
        from modules.portscan import COMMON_PORTS, parse_ports
        default = parse_ports("")
        self.assertEqual(default, sorted(p for p, _n in COMMON_PORTS))
        self.assertGreaterEqual(len(default), 90)
        self.assertLessEqual(len(default), 110)
        self.assertEqual(default, sorted(set(default)))
        for p in default:
            self.assertTrue(1 <= p <= 65535)

    def test_ranges_and_dedup(self):
        from modules.portscan import parse_ports
        self.assertEqual(parse_ports("80,443"), [80, 443])
        self.assertEqual(parse_ports("8000-8003,80"), [80, 8000, 8001, 8002, 8003])
        self.assertEqual(parse_ports("80,80,443,80"), [80, 443])
        self.assertEqual(parse_ports(" 90 , 91 "), [90, 91])

    def test_invalid_ignored(self):
        from modules.portscan import parse_ports
        self.assertEqual(parse_ports("abc,70000,0,-1,443"), [443])
        self.assertEqual(parse_ports("500-100"), [])            # 区间颠倒
        self.assertEqual(parse_ports("zz"), [])

    def test_huge_range_truncated(self):
        from modules.portscan import MAX_PORT_RANGE, parse_ports
        got = parse_ports("1-65535")
        self.assertEqual(len(got), MAX_PORT_RANGE)
        self.assertEqual(got[0], 1)


class TestClassifyBanner(unittest.TestCase):
    def test_known_banners(self):
        from modules.portscan import classify_banner
        self.assertEqual(classify_banner("SSH-2.0-OpenSSH_9.0", 2222), "SSH")
        self.assertEqual(classify_banner("HTTP/1.1 400 Bad Request", 1), "HTTP")
        self.assertEqual(classify_banner("-ERR unknown command", 1), "Redis")
        self.assertEqual(classify_banner("+PONG", 1), "Redis")
        self.assertEqual(classify_banner("220-vsftpd 3.0.3", 1), "FTP")
        self.assertEqual(classify_banner("220 mail.example.com ESMTP", 1), "SMTP")

    def test_fallback_by_port(self):
        from modules.portscan import classify_banner
        self.assertEqual(classify_banner("", 3306), "mysql")
        self.assertEqual(classify_banner("", 80), "http")
        self.assertEqual(classify_banner("", 12345), "")


class TestPortscanIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # 三个本机 TCP 靶标 + 一个确定关闭的端口
        cls.servers = []
        for handler in (_PushHandler, _EchoErrHandler, _SilentHandler):
            srv = socketserver.ThreadingTCPServer(("127.0.0.1", 0), handler)
            srv.daemon_threads = True
            t = threading.Thread(target=srv.serve_forever, daemon=True)
            t.start()
            cls.servers.append((srv, srv.server_address[1]))
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(("127.0.0.1", 0))
        cls.closed_port = s.getsockname()[1]
        s.close()
        os.makedirs(OUT, exist_ok=True)

    @classmethod
    def tearDownClass(cls):
        for srv, _p in cls.servers:
            srv.shutdown()
            srv.server_close()

    def test_scan_local_targets(self):
        from modules.portscan import run_portscan
        ssh_port = self.servers[0][1]
        redis_port = self.servers[1][1]
        silent_port = self.servers[2][1]
        ports = f"{ssh_port},{redis_port},{silent_port},{self.closed_port}"
        rows = _quiet(run_portscan, "127.0.0.1", OUT, ports=ports, timeout=1.0, workers=4)
        got = {r["port"]: r for r in rows}
        # 连接成功的端口都应判开（静默服务判开但服务名未知，不算误报）
        self.assertIn(ssh_port, got)
        self.assertIn(redis_port, got)
        self.assertIn(silent_port, got)
        self.assertNotIn(self.closed_port, got, "关闭端口被误报为开放")
        # banner 特征识别
        self.assertEqual(got[ssh_port]["service"], "SSH")
        self.assertIn("SSH-2.0", got[ssh_port]["banner"])
        self.assertEqual(got[redis_port]["service"], "Redis")
        # 产出文件
        data = json.loads(open(os.path.join(OUT, "ports.json"), encoding="utf-8").read())
        self.assertEqual(data["target"], "127.0.0.1")
        self.assertEqual(data["scanned"], 4)
        self.assertEqual(len(data["open"]), 3)
        self.assertTrue(os.path.getsize(os.path.join(OUT, "ports.txt")) > 0)

    def test_dns_failure_degrades(self):
        from modules.portscan import run_portscan
        with mock.patch("socket.getaddrinfo", side_effect=OSError("resolve fail")):
            rows = _quiet(run_portscan, "nonexistent.invalid", OUT, ports="80", timeout=0.5)
        self.assertEqual(rows, [])
        data = json.loads(open(os.path.join(OUT, "ports.json"), encoding="utf-8").read())
        self.assertEqual(data["ip"], "")
        self.assertEqual(data["open"], [])


if __name__ == "__main__":
    unittest.main()
