# -*- coding: utf-8 -*-
"""--progress-file 进度事件落盘：emit 契约单测 + 子进程端到端冒烟（离线安全）。

关注点：
  1) _emit 事件契约：JSONL 一行一条，键恰为 {ts,event,module,detail}，ts 为数值；
  2) 追加语义：多次 emit 顺序落盘，不覆盖历史；
  3) 容错：进度文件路径非法（指向目录）时静默吞掉，绝不影响扫描主流程；
  4) 关闭态：--progress-file 未提供时零副作用；
  5) 冒烟：portscan -t 127.0.0.1 --ports 1 --timeout 0.1（本机回环拒绝连接，零外网）
     端到端验证 pipeline_start → start/done(portscan) → pipeline_end(done) 事件顺序。
"""
import json
import os
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))

import recon  # noqa: E402


class EmitContractTest(unittest.TestCase):
    def setUp(self):
        self._old = recon._PROGRESS_FILE
        fd, self.path = tempfile.mkstemp(prefix="prog_", suffix=".jsonl")
        os.close(fd)
        os.remove(self.path)  # 只留路径，emit 自己负责创建/追加

    def tearDown(self):
        recon._PROGRESS_FILE = self._old
        if os.path.exists(self.path):
            os.remove(self.path)

    def test_emit_writes_jsonl_contract(self):
        recon._PROGRESS_FILE = self.path
        recon._emit("start", "api", "探测开始")
        with open(self.path, "r", encoding="utf-8") as f:
            lines = [ln for ln in f.read().splitlines() if ln.strip()]
        self.assertEqual(len(lines), 1)
        rec = json.loads(lines[0])
        self.assertEqual(set(rec.keys()), {"ts", "event", "module", "detail"})
        self.assertIsInstance(rec["ts"], float)
        self.assertEqual(rec["event"], "start")
        self.assertEqual(rec["module"], "api")
        self.assertEqual(rec["detail"], "探测开始")

    def test_emit_appends_lines_in_order(self):
        recon._PROGRESS_FILE = self.path
        recon._emit("pipeline_start", "pipeline", "portscan")
        recon._emit("pipeline_end", "pipeline", "done")
        with open(self.path, "r", encoding="utf-8") as f:
            recs = [json.loads(ln) for ln in f if ln.strip()]
        self.assertEqual([r["event"] for r in recs], ["pipeline_start", "pipeline_end"])
        self.assertEqual(recs[0]["ts"] <= recs[1]["ts"], True)

    def test_emit_noop_when_disabled(self):
        recon._PROGRESS_FILE = ""
        recon._emit("start", "api", "")  # 不应抛异常也不应创建文件
        self.assertEqual(os.path.exists(self.path), False)

    def test_emit_tolerates_bad_path(self):
        # 目录当文件写 → 打开必炸，但 emit 必须吞掉异常保证扫描不受影响
        d = tempfile.mkdtemp(prefix="prog_dir_")
        try:
            recon._PROGRESS_FILE = d
            recon._emit("start", "api", "")  # 不抛即通过
        finally:
            os.rmdir(d)


class SmokeTest(unittest.TestCase):
    """子进程端到端：目标 127.0.0.1:1 立即拒绝连接，离线安全。"""

    def test_portscan_smoke_emits_pipeline_events(self):
        fd, pf = tempfile.mkstemp(prefix="prog_smoke_", suffix=".jsonl")
        os.close(fd)
        os.remove(pf)
        try:
            p = subprocess.run(
                [sys.executable, os.path.join("src", "recon.py"),
                 "--progress-file", pf,
                 "portscan", "-t", "127.0.0.1", "--ports", "1", "--timeout", "0.1"],
                cwd=ROOT, timeout=120,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self.assertEqual(p.returncode, 0)
            with open(pf, "r", encoding="utf-8") as f:
                recs = [json.loads(ln) for ln in f if ln.strip()]
            events = [(r["event"], r["module"]) for r in recs]
            self.assertIn(("pipeline_start", "pipeline"), events)
            self.assertIn(("start", "portscan"), events)
            self.assertIn(("done", "portscan"), events)
            self.assertIn(("pipeline_end", "pipeline"), events)
            # 顺序：pipeline_start 最先，pipeline_end 最后
            self.assertEqual(events[0], ("pipeline_start", "pipeline"))
            self.assertEqual(events[-1][0], "pipeline_end")
            end_rec = recs[-1]
            self.assertEqual(end_rec["detail"], "done")
        finally:
            if os.path.exists(pf):
                os.remove(pf)


if __name__ == "__main__":
    unittest.main()
