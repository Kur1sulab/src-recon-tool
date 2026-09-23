# src-recon-tool

![tests](https://github.com/Kur1sulab/src-recon-tool/actions/workflows/tests.yml/badge.svg)

SRC 漏洞挖掘信息收集自动化工具（Python）。将子域枚举、资产测绘、指纹识别、
敏感路径探测与 YAML 化 POC 验证编排为一条流水线，单次全流程约 30 分钟内完成。

> ⚠️ 仅限授权范围内的安全测试使用。禁止用于未授权目标。

## 功能模块

| 模块 | 说明 |
|---|---|
| subdomain | OneForAll 子域枚举（未配置时自动降级 crt.sh 证书日志查询，无需 key） |
| asset | FOFA / Hunter 资产测绘（API key 走环境变量，未配置自动跳过） |
| fingerprint | 内置常用指纹规则（ThinkPHP/Shiro/Spring/WordPress/Nginx 等，headers+body 双通道） |
| paths | 敏感路径探测（.git/.env/swagger/actuator/druid 等） |
| poc | YAML 化 POC 模板引擎（nuclei 风格子集，status/contains matcher，and/or 条件） |
| llm | LLM 辅助资产分级与攻击面总结（可选，无 key 自动降级） |

## 架构

```
target → recon.py → subdomain / asset / fingerprint / paths → out/<target>/
                                              ↓
                                       poc_engine（YAML 模板）
                                              ↓
                                       llm_assist（总结报告）
```

## 安装

```bash
pip install -r requirements.txt
# OneForAll 需单独部署，路径经环境变量 ONEFORALL_HOME 指定（可选）
```

## 用法

```bash
export FOFA_EMAIL=... FOFA_KEY=... HUNTER_KEY=...   # Windows: setx
python src/recon.py all -d example.com        # 全流程
python src/recon.py subdomain -d example.com  # 仅子域
python src/recon.py asset -d example.com      # 仅资产测绘
python src/recon.py fingerprint -u https://example.com
python src/recon.py paths -u https://example.com
python src/recon.py poc -t https://example.com -p pocs/example-http-detect.yaml
python src/recon.py llm -d example.com        # 仅 LLM 总结
```

无任何 API key 时，`all` 全流程仍可跑通：子域走 crt.sh，其余模块自动降级跳过。

## POC 模板示例

```yaml
id: example-admin-detect
info:
  name: Admin Panel Detect
  severity: info
requests:
  - method: GET
    path: "/admin"
    matchers:
      - type: status
        status: [200, 401, 403]
```

## LLM 辅助（可选）

设置 `LLM_API_KEY`（OpenAI 兼容接口，`LLM_BASE_URL`/`LLM_MODEL` 可配）后，
自动对收集结果做资产分级与攻击面提示，输出 `out/<target>/llm_summary.md`；
未配置 key 时流水线自动跳过，不影响主流程。

## 效果

多源并行 + 模板化后，单次信息收集从约 2 小时压缩至 30 分钟内；
已用于 EDUSRC 授权范围内的实战挖洞。

## 目录

```
src/recon.py            CLI 入口
src/modules/            各功能模块
pocs/                   YAML POC 模板
tests/                  单元测试
out/                    输出目录（gitignore）
```

## License

MIT
