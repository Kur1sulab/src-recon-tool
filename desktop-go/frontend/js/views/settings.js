/* ============================================================
 * views/settings.js — ⑤ 设置：运行环境自检（GET /api/env）+ 白名单只读展示
 * python 路径由环境变量 RECON_PYTHON 或 PATH 决定，本页只读。
 * ============================================================ */
(function () {
  "use strict";

  function kv(label, node) {
    return [App.h("div", { class: "k", text: label }), App.h("div", { class: "v" }, node)];
  }

  function flagChip(ok, okText, badText) {
    // 圆点颜色走 chip-lv-ok/-bad 的 CSS 规则（CSP 禁内联 style，内联会被整体丢弃）
    return App.h("span", { class: "chip " + (ok ? "chip-lv-ok" : "chip-lv-bad") },
      App.h("span", { class: "dot" }),
      ok ? okText : badText);
  }

  function render(env) {
    var grid = document.getElementById("envGrid");
    grid.textContent = "";
    var py = (env && env.python) || {};

    var rows = [];
    if (py.found) {
      rows.push(kv("Python", flagChip(true, "已找到", "")));
      rows.push(kv("版本", App.h("span", { class: "mono", text: String(py.version || "-") })));
      rows.push(kv("Python 路径", App.h("span", { class: "mono", text: String(py.path || "-") })));
      rows.push(kv("引擎依赖", py.deps_ok
        ? flagChip(true, "依赖完整", "")
        : flagChip(false, "", "依赖缺失（pip install -r requirements.txt）")));
    } else {
      rows.push(kv("Python", flagChip(false, "", "未找到 Python")));
      rows.push(kv("处理办法", App.h("span", {
        text: "将 Python 加入 PATH，或设置环境变量 RECON_PYTHON 指向 python 可执行文件后重启应用。"
      })));
    }
    rows.push(kv("输出目录", App.h("span", { class: "mono", text: String((env && env.out_dir) || "-") })));
    rows.push(kv("mock 靶站", (env && env.mock_reachable)
      ? flagChip(true, "可达（127.0.0.1:8799）", "")
      : flagChip(false, "", "不可达（启动 tests/mock_server.py 8799 后重试）")));

    rows.forEach(function (r) { grid.appendChild(r[0]); grid.appendChild(r[1]); });

    // 白名单只读表
    var wrapEl = document.getElementById("envWhitelistWrap");
    wrapEl.textContent = "";
    var wl = (env && Array.isArray(env.whitelist)) ? env.whitelist : [];
    if (!wl.length) {
      wrapEl.appendChild(App.h("div", { class: "empty-hint", text: "白名单暂不可用（服务端未返回）。" }));
      return;
    }
    var tbody = App.h("tbody", null, wl.map(function (w) {
      var entry = String(w);
      var note = entry.indexOf("127.0.0.1") === 0 ? "本机 mock 靶站" : "用户自有资产（已授权）";
      return App.h("tr", null,
        App.h("td", { class: "mono", text: entry }),
        App.h("td", { text: note }));
    }));
    wrapEl.appendChild(App.h("table", { class: "data" }, App.h("thead", null,
      App.h("tr", null,
        App.h("th", { text: "目标" }),
        App.h("th", { text: "说明" }))), tbody));
  }

  function runCheck(notify) {
    return API.env().then(function (env) {
      render(env);
      if (notify) App.toast("自检完成", "ok");
    }).catch(function (err) {
      render(null);
      if (notify) App.toast(err && err.message ? err.message : "自检失败", "err");
    });
  }

  App.registerView("settings", {
    enter: function () {
      document.getElementById("envCheck").onclick = function () { runCheck(true); };
      runCheck(false);
    }
  });
})();
