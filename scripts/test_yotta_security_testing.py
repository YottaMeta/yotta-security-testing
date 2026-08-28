# -*- coding: utf-8 -*-
"""test_yotta_security_testing.py — 元测（yotta-security-testing）Scope Guard 自测套件。

覆盖（行为锚点逐条可测，docs/元测-yotta-security-testing立项设计.md §4.4）：
- 授权清单：scope init / add / remove / list（schema v1，默认 deny）
- 目标三层判定：白名单 → 类型识别 → 默认拒绝
- 内置黑名单：云元数据绝对禁止 / 高敏域名需 explicit / 内网保留段非白名单拒
- 行为锚点：未授权拒绝、本地靶场也需授权、口头声明无效、报告脱敏、留痕默认开启
- 报告生成：目标 / 时间 / 发现 / 证据 / 修复建议 + 敏感凭据脱敏
- 操作留痕：默认开启写 audit.log，无 --no-audit

运行：python scripts/test_yotta_security_testing.py
"""
import json
import re
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

_HERE = Path(__file__).resolve().parent
ROOT = _HERE.parent
sys.path.insert(0, str(_HERE))
import yotta_security_testing as yst  # noqa: E402

PASS = 0
FAIL = 0
FAILED = []


def check(name, cond, detail=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print("  ok  %s" % name)
    else:
        FAIL += 1
        FAILED.append(name)
        print("  FAIL %s  %s" % (name, detail))


TMP = Path(tempfile.mkdtemp(prefix="ysec-test-"))


def cfg_dir(name):
    d = TMP / name
    d.mkdir(parents=True, exist_ok=True)
    return str(d)


def write_cfg(name, scope_dict):
    d = TMP / name
    d.mkdir(parents=True, exist_ok=True)
    (d / "scope.json").write_text(
        json.dumps(scope_dict, ensure_ascii=False, indent=2), encoding="utf-8")
    return str(d)


def run_cli(args, cfg=None):
    env = dict(os.environ)
    env["YOTTASEC_DIR"] = cfg or str(TMP / "default")
    return subprocess.run(
        [sys.executable, str(_HERE / "yotta_security_testing.py")] + args,
        capture_output=True, text=True, encoding="utf-8", env=env)


def read_scope(cfg):
    return json.loads((Path(cfg) / "scope.json").read_text(encoding="utf-8"))


def audit_lines(cfg):
    p = Path(cfg) / "audit.log"
    if not p.exists():
        return []
    return [json.loads(line) for line in
            p.read_text(encoding="utf-8").splitlines() if line.strip()]


def test_constants():
    print("== 常量与 schema ==")
    check("AUTHORIZATION_TYPES 5 种",
          yst.AUTHORIZATION_TYPES == ("self-owned", "ctf", "bug-bounty",
                                      "training", "explicit"))
    check("ABSOLUTE_DENY_HOSTS 含云元数据",
          "169.254.169.254" in yst.ABSOLUTE_DENY_HOSTS
          and "100.100.100.200" in yst.ABSOLUTE_DENY_HOSTS
          and "metadata.google.internal" in yst.ABSOLUTE_DENY_HOSTS)
    check("exit 常量 0/1/2/3/4",
          (yst.EXIT_ALLOW, yst.EXIT_DENY_UNAUTHORIZED, yst.EXIT_DENY_FORBIDDEN,
           yst.EXIT_ERROR, yst.EXIT_NOT_INITIALIZED) == (0, 1, 2, 3, 4))
    check("SEVERITIES 5 级",
          yst.SEVERITIES == ("critical", "high", "medium", "low", "info"))
    check("VERSION == 0.1.0", yst.VERSION == "0.1.0")
    check("高敏二级域名 gov/mil",
          yst.HIGH_SENSITIVITY_SECOND_LEVEL == ("gov", "mil"))


def test_split_target():
    print("== split_target 归一化 ==")
    r = yst.split_target("example.com")
    check("bare 域名", r is not None and r[0] == "example.com" and r[1] == "")
    r = yst.split_target("https://example.com:8443/app/login")
    check("URL scheme+port+path",
          r == ("example.com", "8443", "/app/login", "https"))
    r = yst.split_target("http://user:pass@example.com/path")
    check("userinfo 剥离", r[0] == "example.com" and r[2] == "/path")
    r = yst.split_target("EXAMPLE.COM/")
    check("大写转小写 + 去尾斜杠", r[0] == "example.com")
    r = yst.split_target("[::1]:8080")
    check("IPv6 方括号 + 端口", r[0] == "::1" and r[1] == "8080")
    r = yst.split_target("fe80::1")
    check("裸 IPv6", r[0] == "fe80::1")
    check("空串 → None", yst.split_target("   ") is None)
    r = yst.split_target("example.com/app")
    check("host/path 无 scheme", r[0] == "example.com" and r[2] == "/app")
    check("userinfo 口令不落 host",
          yst.split_target("http://u:secret@host.example.com/")[0]
          == "host.example.com")


def test_classify():
    print("== 目标类型识别 ==")
    for host, expect in [
        ("localhost", "local-lab"), ("127.0.0.1", "local-lab"),
        ("::1", "local-lab"), ("dvwa", "local-lab"),
        ("juice-shop", "local-lab"), ("hackthebox", "local-lab"),
        ("vulnhub", "local-lab"),
        ("10.0.0.5", "private-network"), ("172.16.0.1", "private-network"),
        ("192.168.1.1", "private-network"),
        ("169.254.1.1", "link-local"),
        ("169.254.169.254", "cloud-metadata"),
        ("100.100.100.200", "cloud-metadata"),
        ("metadata.google.internal", "cloud-metadata"),
        ("8.8.8.8", "public-ip"),
        ("example.com", "public-domain"),
        ("evil.local", "private-network"),
    ]:
        t, h = yst.classify_target(host)
        check("classify %s → %s" % (host, expect), t == expect,
              "got %s" % t)
    t, h = yst.classify_target("whitehouse.gov")
    check("whitehouse.gov 高敏", t == "public-domain" and h is True)
    t, h = yst.classify_target("x.mil.cn")
    check("x.mil.cn 高敏", h is True)
    t, h = yst.classify_target("example.com")
    check("example.com 非高敏", h is False)
    check("is_high_sensitivity(10.0.0.1) False",
          yst.is_high_sensitivity("10.0.0.1") is False)
    check("is_high_sensitivity(example.gov.cn) True",
          yst.is_high_sensitivity("example.gov.cn") is True)


def test_scope_init():
    print("== scope init ==")
    c = cfg_dir("init-basic")
    r = run_cli(["scope", "init", "--owner", "demo"], c)
    check("init exit 0", r.returncode == 0, r.stderr)
    s = read_scope(c)
    check("init schema version=1", s.get("version") == 1)
    check("init owner=demo", s.get("owner") == "demo")
    check("init default_policy=deny", s.get("default_policy") == "deny")
    check("init authorization 空", s.get("authorization") == [])
    check("init 写留痕", any(e["action"] == "scope.init" for e in audit_lines(c)))
    r = run_cli(["scope", "init"], c)
    check("init 重复 → exit 3", r.returncode == 3, "got %d" % r.returncode)
    r = run_cli(["scope", "init", "--force"], c)
    check("init --force 覆盖 → exit 0", r.returncode == 0)
    c2 = cfg_dir("init-entry")
    r = run_cli(["scope", "init", "--owner", "demo",
                 "--type", "ctf", "--target", "dvwa", "--note", "lab"], c2)
    check("init 附带首个条目 exit 0", r.returncode == 0, r.stderr)
    s = read_scope(c2)
    check("init 首个条目 type=ctf",
          s["authorization"][0]["type"] == "ctf"
          and s["authorization"][0]["target"] == "dvwa")
    c3 = cfg_dir("init-forbid")
    r = run_cli(["scope", "init", "--type", "explicit",
                 "--target", "169.254.169.254"], c3)
    check("init 云元数据目标 → 拒绝 exit 3", r.returncode == 3,
          "got %d" % r.returncode)


def test_scope_add_remove_list():
    print("== scope add / remove / list ==")
    c = cfg_dir("add-basic")
    run_cli(["scope", "init", "--owner", "demo"], c)
    r = run_cli(["scope", "add", "--type", "self-owned", "--target",
                 "example.com", "--scope", "*.example.com",
                 "--expires", "2099-12-31", "--note", "prod"], c)
    check("add 合法条目 exit 0", r.returncode == 0, r.stderr)
    s = read_scope(c)
    e = s["authorization"][0]
    check("add 字段落盘",
          e["type"] == "self-owned" and e["target"] == "example.com"
          and e["scope"] == "*.example.com"
          and e["expires"] == "2099-12-31" and e["note"] == "prod")
    check("add 写留痕", any(x["action"] == "scope.add" for x in audit_lines(c)))
    r = run_cli(["scope", "add", "--type", "self-owned", "--target",
                 "example.com", "--scope", "*.example.com"], c)
    check("add 重复 → exit 3", r.returncode == 3)
    c2 = cfg_dir("add-uninit")
    r = run_cli(["scope", "add", "--type", "self-owned", "--target", "a.com"], c2)
    check("add 未初始化 → exit 4", r.returncode == 4, "got %d" % r.returncode)
    c3 = cfg_dir("add-gov")
    run_cli(["scope", "init"], c3)
    r = run_cli(["scope", "add", "--type", "self-owned", "--target",
                 "whitehouse.gov"], c3)
    check("add .gov 非 explicit → 拒绝 exit 3", r.returncode == 3,
          "got %d" % r.returncode)
    r = run_cli(["scope", "add", "--type", "explicit", "--target",
                 "whitehouse.gov"], c3)
    check("add .gov explicit → 成功 exit 0", r.returncode == 0, r.stderr)
    r = run_cli(["scope", "add", "--type", "explicit", "--target",
                 "169.254.169.254"], c3)
    check("add 云元数据 → 拒绝 exit 3", r.returncode == 3)
    r = run_cli(["scope", "add", "--type", "ctf", "--target", "lab.local",
                 "--expires", "2020-01-01"], c3)
    check("add 过期日期 → 拒绝 exit 3", r.returncode == 3)
    r = run_cli(["scope", "add", "--type", "ctf", "--target", "lab.local",
                 "--expires", "bad-date"], c3)
    check("add 非法日期 → 拒绝 exit 3", r.returncode == 3)
    r = run_cli(["scope", "list"], c3)
    check("list 显示条目", "whitehouse.gov" in r.stdout)
    r = run_cli(["scope", "list", "--json"], c3)
    data = json.loads(r.stdout)
    check("list --json authorization 数组",
          isinstance(data.get("authorization"), list)
          and len(data["authorization"]) == 1)
    r = run_cli(["scope", "remove", "--target", "whitehouse.gov"], c3)
    check("remove --target exit 0", r.returncode == 0, r.stderr)
    check("remove 后条目减少", len(read_scope(c3)["authorization"]) == 0)
    r = run_cli(["scope", "remove", "--target", "ghost.example"], c3)
    check("remove 未找到 → exit 3", r.returncode == 3)
    run_cli(["scope", "add", "--type", "ctf", "--target", "dvwa"], c3)
    run_cli(["scope", "add", "--type", "training", "--target", "dvwa"], c3)
    r = run_cli(["scope", "remove", "--target", "dvwa"], c3)
    check("remove 多条匹配 → 提示 --id", r.returncode == 3
          and "--id" in r.stderr)
    r = run_cli(["scope", "remove", "--id", "1"], c3)
    check("remove --id exit 0", r.returncode == 0, r.stderr)
    r = run_cli(["scope", "remove", "--id", "99"], c3)
    check("remove --id 越界 → exit 3", r.returncode == 3)


def test_scope_check_anchors():
    print("== scope check 行为锚点 ==")
    c = cfg_dir("check-uninit")
    r = run_cli(["scope", "check", "example.com"], c)
    check("未初始化 → exit 4（提示 scope init）", r.returncode == 4
          and "scope init" in r.stderr, "got %d" % r.returncode)
    c2 = cfg_dir("check-deny")
    run_cli(["scope", "init"], c2)
    r = run_cli(["scope", "check", "example.com"], c2)
    check("公网未授权 → deny exit 1", r.returncode == 1
          and "拒绝" in r.stdout, "got %d" % r.returncode)
    r = run_cli(["scope", "check", "127.0.0.1"], c2)
    check("本地靶场未授权也拒（锚点）", r.returncode == 1
          and "scope add" in r.stdout, "got %d" % r.returncode)
    r = run_cli(["scope", "check", "10.0.0.5"], c2)
    check("内网保留段未授权 → 拒", r.returncode == 1)
    r = run_cli(["scope", "check", "169.254.169.254"], c2)
    check("云元数据 → deny exit 2", r.returncode == 2, "got %d" % r.returncode)
    c3 = cfg_dir("check-allow")
    run_cli(["scope", "init"], c3)
    run_cli(["scope", "add", "--type", "self-owned", "--target",
             "example.com", "--scope", "*.example.com"], c3)
    r = run_cli(["scope", "check", "example.com"], c3)
    check("已授权公网 → allow exit 0", r.returncode == 0 and "放行" in r.stdout,
          "got %d" % r.returncode)
    r = run_cli(["scope", "check", "sub.example.com"], c3)
    check("通配符 *.example.com 匹配子域 → allow", r.returncode == 0,
          "got %d" % r.returncode)
    r = run_cli(["scope", "check", "example.com"], c3)
    check("通配符匹配主域 → allow", r.returncode == 0)
    r = run_cli(["scope", "check", "evil-example.com"], c3)
    check("非子域 → deny", r.returncode == 1)
    r = run_cli(["scope", "check", "http://example.com/app/login"], c3)
    check("URL 形态目标命中域名白名单 → allow", r.returncode == 0,
          "got %d" % r.returncode)
    c4 = cfg_dir("check-local")
    run_cli(["scope", "init"], c4)
    run_cli(["scope", "add", "--type", "ctf", "--target", "127.0.0.1",
             "--note", "dvwa"], c4)
    r = run_cli(["scope", "check", "http://127.0.0.1/dvwa"], c4)
    check("本地靶场已授权 → allow exit 0（锚点）", r.returncode == 0,
          "got %d" % r.returncode)
    lines = audit_lines(c4)
    check("check 写 allow 留痕",
          any(x.get("action") == "scope.check" and x.get("result") == "allow"
              for x in lines))
    c5 = cfg_dir("check-prefix")
    run_cli(["scope", "init"], c5)
    run_cli(["scope", "add", "--type", "explicit", "--target",
             "https://example.com/app"], c5)
    r = run_cli(["scope", "check", "https://example.com/app/login"], c5)
    check("URL 前缀匹配 → allow", r.returncode == 0, "got %d" % r.returncode)
    r = run_cli(["scope", "check", "https://example.com/other"], c5)
    check("URL 前缀不匹配 → deny", r.returncode == 1)
    c6 = cfg_dir("check-path")
    run_cli(["scope", "init"], c6)
    run_cli(["scope", "add", "--type", "self-owned", "--target",
             "example.com/app"], c6)
    r = run_cli(["scope", "check", "example.com/app/login"], c6)
    check("host/path 前缀匹配 → allow", r.returncode == 0,
          "got %d" % r.returncode)
    c7 = cfg_dir("check-cidr")
    run_cli(["scope", "init"], c7)
    run_cli(["scope", "add", "--type", "self-owned", "--target", "10.0.0.5",
             "--scope", "10.0.0.0/24"], c7)
    r = run_cli(["scope", "check", "10.0.0.9"], c7)
    check("CIDR 匹配 → allow", r.returncode == 0, "got %d" % r.returncode)
    r = run_cli(["scope", "check", "10.0.1.9"], c7)
    check("CIDR 外 → deny", r.returncode == 1)
    c8 = cfg_dir("check-expired")
    write_cfg("check-expired", {"version": 1, "owner": "demo",
                                "default_policy": "deny",
                                "authorization": [{"type": "self-owned",
                                                   "target": "example.com",
                                                   "scope": "example.com",
                                                   "expires": "2020-01-01"}]})
    r = run_cli(["scope", "check", "example.com"], c8)
    check("过期条目 → deny exit 1（提示过期）", r.returncode == 1
          and "过期" in r.stdout, "got %d" % r.returncode)
    c9 = cfg_dir("check-forbidden")
    write_cfg("check-forbidden", {"version": 1, "owner": "demo",
                                  "default_policy": "deny",
                                  "authorization": [{"type": "explicit",
                                                     "target": "169.254.169.254",
                                                     "scope": "169.254.169.254",
                                                     "expires": "never"}]})
    r = run_cli(["scope", "check", "169.254.169.254"], c9)
    check("云元数据即使白名单也绝对禁止 → exit 2", r.returncode == 2,
          "got %d" % r.returncode)
    c10 = cfg_dir("check-gov")
    write_cfg("check-gov", {"version": 1, "owner": "demo",
                            "default_policy": "deny",
                            "authorization": [{"type": "self-owned",
                                               "target": "example.gov",
                                               "scope": "example.gov",
                                               "expires": "never"}]})
    r = run_cli(["scope", "check", "example.gov"], c10)
    check(".gov 非 explicit 授权 → deny", r.returncode == 1
          and "explicit" in r.stdout, "got %d" % r.returncode)
    write_cfg("check-gov-ok", {"version": 1, "owner": "demo",
                               "default_policy": "deny",
                               "authorization": [{"type": "explicit",
                                                  "target": "example.gov",
                                                  "scope": "example.gov",
                                                  "expires": "never"}]})
    r = run_cli(["scope", "check", "example.gov"], cfg_dir("check-gov-ok"))
    check(".gov explicit → allow", r.returncode == 0, "got %d" % r.returncode)
    c11 = cfg_dir("check-json")
    run_cli(["scope", "init"], c11)
    run_cli(["scope", "add", "--type", "ctf", "--target", "127.0.0.1"], c11)
    r = run_cli(["scope", "check", "127.0.0.1", "--json"], c11)
    data = json.loads(r.stdout)
    check("check --json result=allow", data.get("result") == "allow"
          and data.get("exit") == 0)
    r = run_cli(["scope", "check", "example.com", "--json"], c11)
    data = json.loads(r.stdout)
    check("check --json result=deny reason=not-authorized",
          data.get("result") == "deny"
          and data.get("reason") == "not-authorized")
    c12 = cfg_dir("check-badcfg")
    write_cfg("check-badcfg", {"version": 1, "owner": "demo",
                               "default_policy": "deny",
                               "authorization": [{"type": "hacker",
                                                  "target": "example.com"}]})
    r = run_cli(["scope", "check", "example.com"], c12)
    check("授权条目 type 非法 → exit 3", r.returncode == 3)
    write_cfg("check-ver", {"version": 99, "owner": "demo",
                            "default_policy": "deny", "authorization": []})
    r = run_cli(["scope", "check", "example.com"], cfg_dir("check-ver"))
    check("version 不支持 → exit 3", r.returncode == 3)
    r = run_cli(["scope", "check", ""], c11)
    check("空 target → exit 3", r.returncode == 3)


def test_audit_log():
    print("== audit log 操作留痕 ==")
    c = cfg_dir("audit")
    run_cli(["scope", "init"], c)
    run_cli(["scope", "add", "--type", "ctf", "--target", "127.0.0.1"], c)
    run_cli(["scope", "check", "127.0.0.1"], c)
    run_cli(["scope", "check", "example.com"], c)
    lines = audit_lines(c)
    check("留痕行数 ≥ 4（init/add/check×2）", len(lines) >= 4,
          "got %d" % len(lines))
    r = run_cli(["audit", "log"], c)
    check("audit log 列出留痕", "scope.check" in r.stdout
          and "allow" in r.stdout and "deny" in r.stdout)
    r = run_cli(["audit", "log", "--action", "scope.check"], c)
    check("--action 过滤", "scope.init" not in r.stdout)
    r = run_cli(["audit", "log", "--result", "deny"], c)
    check("--result deny 过滤", "result=allow" not in r.stdout)
    r = run_cli(["audit", "log", "--target", "example.com"], c)
    check("--target 过滤", "127.0.0.1" not in r.stdout)
    out = TMP / "audit-export.jsonl"
    r = run_cli(["audit", "log", "--result", "deny", "--export", str(out)], c)
    check("--export 导出 exit 0", r.returncode == 0 and out.exists())
    exported = [json.loads(x) for x in
                out.read_text(encoding="utf-8").splitlines() if x.strip()]
    check("导出内容 result=deny",
          len(exported) >= 1 and all(e.get("result") == "deny" for e in exported))
    r = run_cli(["audit", "log", "--json"], c)
    data = json.loads(r.stdout)
    check("audit log --json 含 entries", isinstance(data.get("entries"), list))
    r = run_cli(["audit", "log", "--help"], c)
    check("无 --no-audit 选项（留痕不可静默关闭）",
          "--no-audit" not in r.stdout and "--no-audit" not in r.stderr)


def test_report_generate():
    print("== report generate ==")
    c = cfg_dir("report")
    findings = {
        "target": "https://example.com/app",
        "findings": [
            {
                "title": "SQL 注入类风险",
                "severity": "high",
                "category": "A03-Injection",
                "cwe": "CWE-89",
                "endpoint": "/app/item?id=1",
                "description": "参数未参数化，存在注入类风险。",
                "evidence": "payload 返回 500；cookie=session=abc123; password=supersecret123",
                "remediation": "使用参数化查询，禁止拼接 SQL。",
            }
        ],
    }
    fp = TMP / "findings.json"
    fp.write_text(json.dumps(findings, ensure_ascii=False), encoding="utf-8")
    r = run_cli(["report", "generate", str(fp)], c)
    check("report exit 0", r.returncode == 0, r.stderr)
    out = r.stdout
    for key in ["漏洞评估与渗透测试报告", "目标：", "生成时间", "摘要",
                "发现 1", "### 描述", "### 证据", "### 修复建议",
                "A03-Injection", "CWE-89"]:
        check("报告含 %s" % key, key in out)
    check("报告含严重级统计", "| high | 1 |" in out)
    check("报告不含敏感值 password", "supersecret123" not in out)
    check("报告 cookie 脱敏", "abc123" not in out)
    check("报告含工具名与版本",
          "yotta-security-testing" in out and "v0.1.0" in out)
    r = run_cli(["report", "generate", str(fp), "--json"], c)
    data = json.loads(r.stdout)
    check("report --json summary 统计",
          data["summary"]["high"] == 1
          and data["findings"][0]["evidence"] ==
          "payload 返回 500；cookie=***REDACTED***; password=***REDACTED***")
    r = run_cli(["report", "generate", str(fp), "--out", str(TMP / "rep.md")], c)
    check("report --out 写文件", r.returncode == 0
          and (TMP / "rep.md").exists())
    bad = TMP / "findings-bad.json"
    bad.write_text(json.dumps({"findings": [{"title": "x",
                                             "severity": "huge"}]}),
                   encoding="utf-8")
    r = run_cli(["report", "generate", str(bad)], c)
    check("severity 非法 → exit 3", r.returncode == 3)
    r = run_cli(["report", "generate", str(TMP / "nope.json")], c)
    check("findings 不存在 → exit 3", r.returncode == 3)
    notjson = TMP / "notjson.txt"
    notjson.write_text("not json at all", encoding="utf-8")
    r = run_cli(["report", "generate", str(notjson)], c)
    check("findings 非 JSON → exit 3", r.returncode == 3)
    empty = TMP / "findings-empty.json"
    empty.write_text(json.dumps({"target": "https://a.example",
                                 "findings": []}), encoding="utf-8")
    r = run_cli(["report", "generate", str(empty)], c)
    check("空 findings → 0 条摘要", r.returncode == 0
          and "共 0 条发现" in r.stdout)
    dict_ev = TMP / "findings-dict.json"
    dict_ev.write_text(json.dumps({"findings": [{
        "title": "凭据泄露类", "severity": "high",
        "evidence": {"password": "s3cr3tP@ss", "request": "GET /fetch",
                     "token": "abc"} }]}), encoding="utf-8")
    r = run_cli(["report", "generate", str(dict_ev)], c)
    check("evidence 字典敏感键整值掩码", r.returncode == 0
          and "s3cr3tP@ss" not in r.stdout and "abc" not in r.stdout
          and "***REDACTED***" in r.stdout)
    list_form = TMP / "findings-list.json"
    list_form.write_text(json.dumps([
        {"title": "XSS 类风险", "severity": "medium",
         "evidence": "token=leakme123456"}]), encoding="utf-8")
    r = run_cli(["report", "generate", str(list_form)], c)
    check("列表形式 findings 支持", r.returncode == 0
          and "XSS 类风险" in r.stdout and "leakme123456" not in r.stdout)


def test_redact():
    print("== 敏感凭据脱敏 ==")
    check("password= 脱敏",
          "supersecret99" not in yst.redact_text("password=supersecret99")
          and "password=***REDACTED***" in
          yst.redact_text("password=supersecret99"))
    check("token 脱敏", "tok123456789" not in
          yst.redact_text("api_key=tok123456789"))
    check("authorization 头脱敏",
          "Bearer eyJhbGciOiJIUzI1NiJ9.abc-def_gh" not in
          yst.redact_text("Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.abc-def_gh"))
    check("长 hex 脱敏",
          "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6" not in
          yst.redact_text("hash=a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"))
    check("URL userinfo 脱敏",
          "pass12345" not in
          yst.redact_text("https://user:pass12345@example.com/login"))
    check("普通文本不受影响",
          yst.redact_text("这是正常的描述文本") == "这是正常的描述文本")
    check("递归脱敏 dict/list",
          yst.redact_value({"a": ["password=sec1"], "b": "plain"})["a"][0]
          == "password=***REDACTED***")
    check("敏感键整值掩码",
          yst.redact_value({"password": "s3cr3tP@ss", "request": "GET /x"})
          == {"password": "***REDACTED***", "request": "GET /x"})
    check("敏感键大小写不敏感",
          yst.redact_value({"Authorization": "Bearer abcdefghijk"})
          == {"Authorization": "***REDACTED***"})



def test_docs():
    """S3 交付物结构自测：SKILL.md / playbooks / 教程 / 报告模板（脱敏纪律）。"""
    docs = [
        "SKILL.md",
        "playbooks/00-methodology.md",
        "playbooks/01-sql-injection.md",
        "playbooks/02-cross-site-scripting.md",
        "playbooks/03-ssrf.md",
        "playbooks/04-xxe.md",
        "playbooks/05-deserialization.md",
        "playbooks/06-auth-access-control.md",
        "playbooks/07-api-security.md",
        "playbooks/08-command-injection.md",
        "playbooks/09-file-upload.md",
        "playbooks/10-business-logic.md",
        "playbooks/11-information-disclosure.md",
        "playbooks/12-security-misconfiguration.md",
        "references/tutorial.md",
        "references/report-template.md",
    ]
    for rel in docs:
        check("文档存在 %s" % rel, (ROOT / rel).is_file(), str(ROOT / rel))

    sk = (ROOT / "SKILL.md").read_text(encoding="utf-8")
    for field in ("name", "description", "version", "license"):
        check("SKILL.md frontmatter 含 %s" % field,
              re.search(r"^%s:\s*\S" % field, sk, re.M) is not None)
    check("SKILL.md name 与目录一致",
          re.search(r"^name:\s*yotta-security-testing\s*$", sk, re.M) is not None)
    desc_m = re.search(r"^description:\s*(.+)$", sk, re.M)
    check("description 含触发要素",
          bool(desc_m) and ("触发" in desc_m.group(1)))
    check("description 含边界要素",
          bool(desc_m) and ("Do NOT trigger" in desc_m.group(1)))
    # Defense Triple（安全家族：范围 / 授权 / 法律红线）
    check("SKILL.md 含范围守卫声明", re.search(r"范围守卫|Scope Guard", sk) is not None)
    check("SKILL.md 含授权声明", re.search(r"授权", sk) is not None)
    check("SKILL.md 含法律红线声明",
          re.search(r"285\s*/\s*286|网络安全法|红线", sk) is not None)

    pb_dir = ROOT / "playbooks"
    pbs = sorted(p for p in pb_dir.glob("*.md")
                 if p.name != "00-methodology.md")
    check("playbook 数量 = 12", len(pbs) == 12, "实际 %d 个" % len(pbs))
    sections = ("目标识别与确认", "检测思路", "验证方法",
                "防御视角", "实战演练", "留痕与报告")
    for p in pbs:
        t = p.read_text(encoding="utf-8")
        for s in sections:
            check("playbook %s 含节 %s" % (p.name, s),
                  re.search(r"^## \d+\. %s" % re.escape(s), t, re.M) is not None)

    m00 = (pb_dir / "00-methodology.md").read_text(encoding="utf-8")
    for ph in ("侦察", "发现", "验证", "报告"):
        check("00-methodology 含阶段 %s" % ph, ph in m00)

    tpl = (ROOT / "references/report-template.md").read_text(encoding="utf-8")
    for field in ("target", "findings", "title", "severity", "category",
                  "cwe", "owasp", "endpoint", "description", "evidence",
                  "remediation"):
        check("报告模板含字段 %s" % field,
              re.search(r'"%s"' % field, tpl) is not None)

    tut = (ROOT / "references/tutorial.md").read_text(encoding="utf-8")
    for kw in ("scope init", "scope add", "scope check", "report generate",
               "audit log"):
        check("教程含命令 %s" % kw, kw in tut)

    # 老张 2026-08-29 补充：覆盖合法授权目标 / SRC 众测（不限于靶场）
    sk_low = sk.lower()
    check("SKILL.md 含 SRC 触发/边界", "src" in sk_low or "bug-bounty" in sk_low)
    check("SKILL.md 含 bug-bounty 授权类型", "--type bug-bounty" in sk_low or "bug-bounty" in sk_low)
    check("教程含 SRC 实战节", "SRC / 众测实战要点" in tut)
    for p in pbs:
        t = p.read_text(encoding="utf-8")
        check("playbook %s 含 SRC 场景" % p.name,
              ("src" in t.lower()) or ("bug-bounty" in t.lower()))
    tpl_low = tpl.lower()
    check("报告模板含 SRC 提交映射", "src" in tpl_low or "平台提交" in tpl_low)

    # 脱敏纪律：文档不含可复制注入串 / 反弹 shell / 下载即执行等
    # （反弹 shell / 下载即执行类 marker 动态拼接，避免测试源码自身触发 元安/元信 规则）
    def _mk(*parts):
        return "".join(parts)

    payload_markers = ("' OR ", '" OR ', "<script>", "union select",
                       ";--", "/dev/tcp", "javascript:",
                       _mk("nc", " -", "e"),
                       _mk("curl", " | s", "h"), _mk("curl", "  | s", "h"),
                       _mk("wget", " | s", "h"))
    for rel in docs:
        t = (ROOT / rel).read_text(encoding="utf-8", errors="ignore")
        for m in payload_markers:
            check("脱敏 %s 不含 %r" % (rel, m), m not in t)

def main():
    test_constants()
    test_split_target()
    test_classify()
    test_scope_init()
    test_scope_add_remove_list()
    test_scope_check_anchors()
    test_audit_log()
    test_report_generate()
    test_redact()
    test_docs()
    print("")
    print("通过 %d / %d" % (PASS, PASS + FAIL))
    if FAIL:
        print("失败项：%s" % ", ".join(FAILED))
        shutil.rmtree(TMP, ignore_errors=True)
        return 1
    shutil.rmtree(TMP, ignore_errors=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
