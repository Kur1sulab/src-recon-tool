/* ============================================================
 * app.js — 路由 / 共享工具函数 / 键盘操作 / 视图注册
 * 全局对象：App
 * 视图文件（js/views/*.js）通过 App.registerView(name, {enter, leave}) 注册。
 * ============================================================ */
(function () {
  "use strict";

  var App = {};

  /* ---------- DOM 工具函数（动态数据一律走 textContent，杜绝注入） ---------- */

  // h("td", {class:"mono", text:safe}, child, ...) → Element
  App.h = function (tag, attrs) {
    var el = document.createElement(tag);
    if (attrs) {
      Object.keys(attrs).forEach(function (k) {
        var v = attrs[k];
        if (v === null || v === undefined) return;
        if (k === "text") { el.textContent = String(v); }
        else if (k === "class") { el.className = v; }
        else if (k === "dataset") {
          Object.keys(v).forEach(function (d) { el.dataset[d] = v[d]; });
        }
        else if (k.slice(0, 2) === "on" && typeof v === "function") {
          el.addEventListener(k.slice(2).toLowerCase(), v);
        }
        else if (k === "hidden") { el.hidden = !!v; }
        else { el.setAttribute(k, String(v)); }
      });
    }
    for (var i = 2; i < arguments.length; i++) {
      var c = arguments[i];
      if (c === null || c === undefined) continue;
      if (Array.isArray(c)) { c.forEach(function (x) { if (x) el.appendChild(x); }); }
      else if (typeof c === "string") { el.appendChild(document.createTextNode(c)); }
      else { el.appendChild(c); }
    }
    return el;
  };

  App.q = function (sel) { return document.querySelector(sel); };

  /* ---------- 格式化 ---------- */

  var pad = function (n) { return (n < 10 ? "0" : "") + n; };

  // ts 兼容秒/毫秒时间戳；空值返回 "-"
  App.fmtTs = function (ts) {
    if (ts === undefined || ts === null || ts === "") return "-";
    var n = Number(ts);
    if (!isFinite(n) || n <= 0) return "-";
    if (n > 1e12) n = Math.floor(n);      // 毫秒
    else n = Math.floor(n * 1000);        // 秒
    var d = new Date(n);
    if (isNaN(d.getTime())) return "-";
    return pad(d.getMonth() + 1) + "-" + pad(d.getDate()) + " " +
      pad(d.getHours()) + ":" + pad(d.getMinutes()) + ":" + pad(d.getSeconds());
  };

  // 毫秒 → "1.2s" / "2m03s"
  App.fmtDur = function (ms) {
    if (!isFinite(ms) || ms < 0) return "-";
    if (ms < 1000) return Math.round(ms) + "ms";
    var s = ms / 1000;
    if (s < 60) return (Math.round(s * 10) / 10) + "s";
    var m = Math.floor(s / 60);
    var rest = Math.round(s - m * 60);
    return m + "m" + pad(rest) + "s";
  };

  App.fmtSize = function (bytes) {
    var n = Number(bytes);
    if (!isFinite(n) || n < 0) return "-";
    if (n < 1024) return n + " B";
    if (n < 1024 * 1024) return (Math.round(n / 102.4) / 10) + " KB";
    return (Math.round(n / (1024 * 102.4)) / 10) + " MB";
  };

  // 从对象按优先级取第一个非空字段（列表接口时间字段契约未定，防御式读取）
  App.pick = function (obj, keys) {
    for (var i = 0; i < keys.length; i++) {
      var v = obj ? obj[keys[i]] : undefined;
      if (v !== undefined && v !== null && v !== "") return v;
    }
    return undefined;
  };

  /* ---------- 领域词汇表 ---------- */

  App.CMD_META = {
    "all":         { label: "全流程",   kind: "target", hint: "全流程：子域 → 存活 → 资产 → 反查/备案 → 指纹 → 路径 → API → JS 情报 → 端口 → 证据包。目标为域名或 IP。" },
    "paths":       { label: "敏感路径", kind: "url",    hint: "目标为完整 URL，含协议，如 http://127.0.0.1:8799/real" },
    "api":         { label: "API 探测", kind: "url",    hint: "目标为完整 URL，含协议，如 http://127.0.0.1:8799/real" },
    "fingerprint": { label: "指纹识别", kind: "url",    hint: "目标为完整 URL，含协议，如 http://127.0.0.1:8799/real" },
    "jsintel":     { label: "JS 情报",  kind: "url",    hint: "目标为完整 URL，含协议，如 http://127.0.0.1:8799/jssite" },
    "portscan":    { label: "端口扫描", kind: "target", hint: "目标为域名或 IP；可用可选参数控制端口范围，如 --ports 1-1000" },
    "subdomain":   { label: "子域收集", kind: "domain", hint: "目标为域名（不含路径），如 xycovo.com" },
    "reverse":     { label: "IP 反查",  kind: "ip",     hint: "目标为 IP 地址，如 47.100.49.228" },
    "icp":         { label: "备案查询", kind: "domain", hint: "目标为域名（不含路径），如 xycovo.com" }
  };

  App.STATUS_META = {
    "created": "已创建",
    "running": "运行中",
    "done":    "已完成",
    "fail":    "失败",
    "stopped": "已停止"
  };

  App.statusLabel = function (s) {
    return App.STATUS_META[s] || (s ? String(s) : "未知");
  };

  App.MODULE_LABEL = {
    "pipeline":   "流水线",
    "subdomain":  "子域收集",
    "verify":     "存活验证",
    "asset":      "资产档案",
    "reverse":    "IP 反查",
    "icp":        "备案查询",
    "fingerprint":"指纹识别",
    "paths":      "敏感路径",
    "api":        "API 探测",
    "jsintel":    "JS 情报",
    "portscan":   "端口扫描",
    "report":     "证据包报告"
  };

  App.moduleLabel = function (m) {
    if (!m) return "-";
    return App.MODULE_LABEL[m] || String(m);
  };

  /**
   * 纯函数：把 progress 事件流按模块配对成进度行。
   * progress: [{ts,event,module,detail}]
   * → { rows: [{module,label,status:"running"|"done"|"fail",startTs,endTs,durMs,detail}],
   *     pipeline: {startTs,endTs} }
   * event ∈ start|done|fail 为模块级事件；pipeline_start/pipeline_end 为流水线事件。
   */
  App.pairProgress = function (progress) {
    var rows = [];
    var byMod = {};
    var pipeline = { startTs: undefined, endTs: undefined };
    (progress || []).forEach(function (ev) {
      if (!ev) return;
      var mod = ev.module || "";
      var evt = ev.event || "";
      if (evt === "pipeline_start") { pipeline.startTs = ev.ts; return; }
      if (evt === "pipeline_end")   { pipeline.endTs = ev.ts; return; }
      if (evt !== "start" && evt !== "done" && evt !== "fail") {
        // 未知事件：若有模块则当作备注行，否则忽略
        if (mod && !byMod[mod]) {
          byMod[mod] = { module: mod, label: App.moduleLabel(mod), status: evt, startTs: ev.ts, endTs: undefined, durMs: undefined, detail: ev.detail || "" };
          rows.push(byMod[mod]);
        }
        return;
      }
      if (!byMod[mod]) {
        byMod[mod] = { module: mod, label: App.moduleLabel(mod), status: undefined, startTs: undefined, endTs: undefined, durMs: undefined, detail: "" };
        rows.push(byMod[mod]);
      }
      var row = byMod[mod];
      if (evt === "start") {
        row.startTs = ev.ts;
        if (row.status !== "done" && row.status !== "fail") row.status = "running";
      } else { // done | fail
        row.endTs = ev.ts;
        row.status = evt;
        row.detail = ev.detail || row.detail;
        if (row.startTs !== undefined && row.endTs !== undefined) {
          row.durMs = Math.round((Number(row.endTs) - Number(row.startTs)) * 1000);
        }
      }
    });
    return { rows: rows, pipeline: pipeline };
  };

  /* ---------- 操作反馈条 ---------- */

  var toastTimer = null;
  App.toast = function (msg, kind) {
    var t = App.q("#toast");
    if (!t) return;
    t.textContent = msg;
    t.className = "toast " + (kind || "");
    if (toastTimer) clearTimeout(toastTimer);
    toastTimer = setTimeout(function () { t.classList.add("hidden"); }, 2800);
  };

  /* ---------- 视图注册与路由 ---------- */

  App.views = {};
  App.registerView = function (name, impl) { App.views[name] = impl || {}; };

  var VIEW_TITLE = {
    tasks: "任务列表", new: "新建侦察", detail: "任务详情",
    evidence: "证据包", settings: "设置"
  };
  // Ctrl+1..5 对应的页面顺序
  var VIEW_ORDER = ["tasks", "new", "detail", "evidence", "settings"];

  var current = { name: null, param: null };

  function parseHash() {
    var raw = location.hash.replace(/^#\/?/, "");
    var parts = raw.split("/").filter(Boolean);
    var name = parts[0] || "tasks";
    if (!App.views[name]) name = "tasks";
    return { name: name, param: parts.slice(1).join("/") || null };
  }

  function render() {
    var r = parseHash();
    if (r.name === current.name && r.param === current.param) return;
    if (current.name && App.views[current.name] && App.views[current.name].leave) {
      try { App.views[current.name].leave(); } catch (e) { /* 忽略视图离开异常 */ }
    }
    Object.keys(App.views).forEach(function (name) {
      var sec = document.getElementById("view-" + name);
      if (sec) sec.hidden = (name !== r.name);
    });
    document.querySelectorAll(".nav-item").forEach(function (a) {
      var on = a.dataset.nav === r.name;
      a.classList.toggle("active", on);
      if (on) a.setAttribute("aria-current", "page");
      else a.removeAttribute("aria-current");
    });
    var title = document.getElementById("viewTitle");
    if (title) title.textContent = VIEW_TITLE[r.name] || r.name;
    current = r;
    if (App.views[r.name].enter) {
      try { App.views[r.name].enter(r.param); } catch (e) {
        App.toast("页面渲染出错：" + (e && e.message ? e.message : e), "err");
      }
    }
  }

  App.navigate = function (hash) { location.hash = hash; };
  App.currentRoute = function () { return current; };

  /* ---------- 键盘操作 ---------- */

  function keyHandler(e) {
    // Ctrl+1..5 切页
    if ((e.ctrlKey || e.metaKey) && !e.altKey && !e.shiftKey) {
      var idx = -1;
      if (/^[1-5]$/.test(e.key)) idx = Number(e.key) - 1;
      else if (/^[1-5]$/.test(String(e.code).replace("Digit", "")) && e.code.indexOf("Digit") === 0) idx = Number(e.code.slice(5)) - 1;
      if (idx >= 0 && VIEW_ORDER[idx]) {
        e.preventDefault();
        App.navigate("#/" + VIEW_ORDER[idx]);
        return;
      }
    }
    // Esc 停止运行中任务
    if (e.key === "Escape") {
      App.stopMostRelevantRunning();
    }
  }

  /** Esc：优先停当前详情任务；否则停最近一个运行中任务 */
  App.stopMostRelevantRunning = function () {
    var route = App.currentRoute();
    var candidateId = null;
    if (route.name === "detail" && route.param) candidateId = route.param;
    if (!candidateId) {
      var list = App.latestScans || [];
      for (var i = 0; i < list.length; i++) {
        if (list[i].status === "running") { candidateId = list[i].id; break; }
      }
    }
    if (!candidateId) { App.toast("当前没有运行中的任务"); return; }
    API.stopScan(candidateId).then(function () {
      App.toast("停止指令已提交（任务 " + shortId(candidateId) + "）", "ok");
    }).catch(function (err) {
      App.toast(err && err.message ? err.message : "停止失败", "err");
    });
  };

  function shortId(id) { return String(id || "").slice(0, 8); }
  App.shortId = shortId;

  /* ---------- 后端在线状态 ---------- */

  App.setLatestScans = function (scans) {
    App.latestScans = scans || [];
    var anyRunning = App.latestScans.some(function (s) { return s.status === "running"; });
    var hint = document.getElementById("escHint");
    if (hint) hint.classList.toggle("hidden", !anyRunning);
  };

  /* ---------- 启动 ---------- */

  function init() {
    API.onStatus(function (offline) {
      var dot = document.getElementById("backendDot");
      var text = document.getElementById("backendText");
      var banner = document.getElementById("offlineBanner");
      if (dot) dot.className = "dot " + (offline ? "offline" : "online");
      if (text) text.textContent = offline ? "后端离线" : "本地服务在线";
      if (banner) banner.classList.toggle("hidden", !offline);
    });
    document.addEventListener("keydown", keyHandler);
    window.addEventListener("hashchange", render);
    render();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }

  window.App = App;
})();
