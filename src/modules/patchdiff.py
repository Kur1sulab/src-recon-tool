#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""patchdiff —— 补丁差分 → 变种狩猎。

思路：厂商修洞时改的那几行就是漏洞的「指纹」。
  · 被删掉的行 ≈ 漏洞写法
  · 新增的行   ≈ 补上的检查
把「被删写法」压成扫描规则（semgrep 骨架），就能拿它去扫兄弟项目/二开版本，
从 n-day（别人修过的洞）推出变种 0day。

用法：
  python src/recon.py patchdiff -r /path/to/repo                 # 自动找安全相关提交
  python src/recon.py patchdiff -r /path/to/repo --commit <sha>  # 只看某个提交
  python src/recon.py patchdiff -r /path/to/repo --range v1.2..v1.3
  python src/recon.py patchdiff -r /path/to/repo --emit-rule out.yaml
"""
import json
import os
import re
import subprocess
import time

# 修复信号：出现在 added 行 → 这一 hunk 很可能在补洞
FIX_SIGNALS = [
    (r'htmlspecialchars|htmlentities|esc_html|escape_html', 'XSS 转义'),
    (r'addslashes|mysqli_real_escape_string|pg_escape|escapeString', 'SQL 转义'),
    (r'prepare\s*\(|bindParam|bindValue|PreparedStatement', '参数化查询'),
    (r'intval|\(int\)|\bint\s*\(|parseInt|Integer\.parseInt|is_numeric|cctype_digit|strconv\.Atoi', '整数化'),
    (r'basename|realpath|filepath\.Clean|path\.normalize', '路径规范化'),
    (r'is_uploaded_file|getimagesize|whitelist|allowlist', '上传白名单'),
    (r'csrf|nonce|samesite', 'CSRF/令牌'),
    (r'is_admin|hasRole|checkPermission|@PreAuthorize|authorize', '鉴权'),
    (r'preg_quote|re\.escape|Pattern\.quote', '正则转义'),
    (r'safe_load|SafeLoader|allow_?list', '序列化加固'),
    (r'urlparse|allowed_hosts|validate_url|is_private', 'SSRF 防护'),
    (r'escapeshellarg|escapeshellcmd|shlex\.quote', '命令转义'),
]
# 漏洞写法痕迹：出现在 removed 行
VULN_SIGNALS = [
    (r'\$_GET|\$_POST|\$_REQUEST|\$_COOKIE', 'PHP 输入源'),
    (r'getParameter|getHeader|@RequestParam', 'Java 输入源'),
    (r'request\.(args|form|GET|POST)', 'Python 输入源'),
    (r'req\.(query|body|params)', 'Node 输入源'),
    (r'eval\s*\(|exec\s*\(|system\s*\(|Runtime\.getRuntime\(\)\.exec|child_process', '命令/代码执行'),
    (r'unserialize|readObject|ObjectInputStream|pickle\.load|yaml\.load\s*\(', '反序列化'),
    (r'\+\s*\$|\.\s*\$_(GET|POST|REQUEST)', 'SQL 拼接'),
    (r'include\s*\(|require\s*\(', '文件包含'),
]


def _sh(cmd, cwd=None, timeout=120):
    env = os.environ.copy()
    env.pop('PYTHONPATH', None)
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, cwd=cwd, env=env)
    return p.returncode, p.stdout, p.stderr


def _commits(repo, commit=None, rng=None, limit=20):
    if commit:
        return [commit]
    cmd = ['git', 'log', '--pretty=%H', '-n', str(limit)]
    if rng:
        cmd = ['git', 'log', '--pretty=%H', rng]
    else:
        # git --grep 默认 BRE，竖线不是「或」，必须拆成多个 --grep（踩过的坑）
        cmd = ['git', 'log', '--pretty=%H', '-i',
               '--grep=fix', '--grep=security', '--grep=cve', '--grep=vuln', '--grep=bypass',
               '-n', str(limit)]
    rc, out, _ = _sh(cmd, cwd=repo)
    return [x.strip() for x in out.splitlines() if x.strip()] if rc == 0 else []


def _parse_hunks(diff_text):
    files, cur, hunk = [], None, None
    for line in diff_text.splitlines():
        if line.startswith('diff --git'):
            m = re.search(r'\sb/(.+)$', line)
            cur = {'file': m.group(1) if m else line, 'hunks': []}
            files.append(cur)
            hunk = None
        elif line.startswith('@@'):
            if cur is None:
                continue
            hunk = {'header': line, 'removed': [], 'added': []}
            cur['hunks'].append(hunk)
        elif hunk is not None:
            if line.startswith('-') and not line.startswith('---'):
                hunk['removed'].append(line[1:])
            elif line.startswith('+') and not line.startswith('+++'):
                hunk['added'].append(line[1:])
    return files


def _classify(files):
    rows = []
    for f in files:
        for h in f['hunks']:
            fix = []
            for a in h['added']:
                for pat, lab in FIX_SIGNALS:
                    if re.search(pat, a, re.I) and lab not in fix:
                        fix.append(lab)
                # 上下文判定：execute(...) 里出现占位符 → 参数化查询
                if re.search(r'execute\s*\(', a, re.I) and re.search(r'\?\s*[,)]', a):
                    if '参数化查询' not in fix:
                        fix.append('参数化查询')
            vuln = []
            for r in h['removed']:
                for pat, lab in VULN_SIGNALS:
                    if re.search(pat, r, re.I) and lab not in vuln:
                        vuln.append(lab)
                # 上下文判定：SQL 语句里出现字符串拼接 → 典型的注入写法
                if re.search(r'\b(select|insert|update|delete)\b', r, re.I) and '+' in r:
                    if 'SQL 拼接' not in vuln:
                        vuln.append('SQL 拼接')
            if fix or vuln:
                rows.append({'file': f['file'], 'header': h['header'], 'fix': fix,
                             'vuln': vuln, 'removed': h['removed'][:10], 'added': h['added'][:10]})
    return rows


def emit_rule(rows, path):
    """把「被删的危险写法」压成 semgrep 规则骨架。"""
    pats = []
    for r in rows:
        for line in r['removed']:
            s = line.strip()
            if len(s) < 6 or s.startswith(('//', '#', '*')):
                continue
            esc = re.sub(r'([\\"\[\]\(\)\{\}\.\*\+\?\|\^\$])', r'\\\1', s)[:120]
            pats.append(esc)
    pats = list(dict.fromkeys(pats))[:12]
    body = f"""rules:
- id: patchdiff.variant-hunt
  languages: [generic]
  severity: WARNING
  message: 该写法在修复补丁中被移除，疑似同类漏洞变种，需人工确认可达性
  metadata:
    confidence: LOW
    source: patchdiff
  patterns:
    - pattern-regex: ({'|'.join(pats) if pats else 'TODO_PATTERN'})
"""
    with open(path, 'w', encoding='utf-8') as f:
        f.write(body)
    return path


def run_patchdiff(repo, commit=None, rng=None, limit=20, emit=None, outdir=None, quiet=False):
    """返回 dict；供 CLI 与测试调用。"""
    repo = os.path.abspath(repo)
    if not os.path.isdir(os.path.join(repo, '.git')):
        return {'ok': False, 'error': '不是 git 仓库: ' + repo}

    shas = _commits(repo, commit, rng, limit)
    all_rows, meta = [], []
    for sha in shas:
        rc, diff, _ = _sh(['git', 'show', '--unified=3', '--format=%H%n%ad%n%s', '--date=short', sha], cwd=repo)
        if rc != 0 or not diff.strip():
            continue
        head = diff.splitlines()[:3]
        rows = _classify(_parse_hunks(diff))
        meta.append({'sha': sha[:10], 'date': head[1] if len(head) > 1 else '',
                     'subject': head[2] if len(head) > 2 else '', 'hunks': len(rows)})
        for r in rows:
            r['sha'] = sha[:10]
            all_rows.append(r)

    outdir = outdir or os.path.join(os.getcwd(), 'patchdiff-out')
    os.makedirs(outdir, exist_ok=True)
    json_path = os.path.join(outdir, 'patchdiff.json')
    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump({'commits': meta, 'hunks': all_rows}, f, ensure_ascii=False, indent=1)

    rule = None
    if emit:
        rule = emit_rule(all_rows, os.path.join(outdir, emit) if not os.path.isabs(emit) else emit)

    if not quiet:
        print(f'[patchdiff] 仓库 {repo}｜提交 {len(meta)} 个｜安全相关 hunk {len(all_rows)} 个')
        for m in meta:
            print(f"  {m['sha']} {m['date']} {m['subject'][:60]} → {m['hunks']} hunk")
        top = sorted(all_rows, key=lambda r: -(len(r['fix']) * 2 + len(r['vuln'])))[:5]
        for r in top:
            print(f"  · {r['sha']} {r['file']}")
            print(f"    修复信号: {', '.join(r['fix']) or '—'}｜漏洞痕迹: {', '.join(r['vuln']) or '—'}")
        print(f'[patchdiff] 结果: {json_path}' + (f'｜规则: {rule}' if rule else ''))

    return {'ok': True, 'commits': meta, 'hunks': all_rows, 'json': json_path, 'rule': rule}


if __name__ == '__main__':
    import argparse
    ap = argparse.ArgumentParser(description='补丁差分 → 变种狩猎')
    ap.add_argument('-r', '--repo', required=True)
    ap.add_argument('--commit')
    ap.add_argument('--range', dest='rng')
    ap.add_argument('--limit', type=int, default=20)
    ap.add_argument('--emit-rule')
    a = ap.parse_args()
    run_patchdiff(a.repo, a.commit, a.rng, a.limit, a.emit_rule)
