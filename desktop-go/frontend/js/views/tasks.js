/* ============================================================
 * views/tasks.js — ① 任务列表：统计区 + 目标/子命令/状态/时间/操作
 * 800ms 轮询 GET /api/scans
 * 统计数字全部由列表现算（总/运行中/成功/失败），零占位假数。
 * 行内操作：查看 / 停止（运行中）/ 重开（预填新建表单）/
 *          删除（仅终态；out/ 产物保留在盘）/ 证据包（仅终态）
 * ============================================================ */
(function () {
  "use strict";

  var poll = null;
  var wrap = null;
  var everLoaded = false; // 载态/空态区分：首次成功前不显示空态

  function chip(status) {
    return App.h("span", { class: "chip", "data-s": status || "" },
      App.h("span", { class: "dot" }),
      App.statusLabel(status));
  }

  function cmdCell(cmd) {
    var meta = App.CMD_META[cmd];
    return App.h("span", { class: "chip" },
      (meta ? meta.label : String(cmd || "-")) + " · " + String(cmd || "-"));
  }

  /* ---------- 统计区：由同一份列表现算 ---------- */

  function renderStats(scans) {
    var box = document.getElementById("taskStats");
    if (!box) return;
    var st = { total: scans.length, running: 0, done: 0, fail: 0 };
    scans.forEach(function (s) {
      if (s.status === "running") st.running++;
      else if (s.status === "done") st.done++;
      else if (s.status === "fail") st.fail++;
    });
    var cards = [
      { k: "total", label: "总任务", num: st.total },
      { k: "running", label: "运行中", num: st.running },
      { k: "done", label: "已完成", num: st.done },
      { k: "fail", label: "失败", num: st.fail }
    ];
    box.textContent = "";
    cards.forEach(function (c) {
      box.appendChild(App.h("div", { class: "stat-card", "data-k": c.k },
        App.h("span", { class: "dot" + (c.k === "running" && c.num > 0 ? " live" : "") }),
        App.h("span", { class: "stat-num", text: String(c.num) }),
        App.h("span", { class: "stat-label", text: c.label })));
    });
  }

  /* ---------- 行内操作 ---------- */

  function reopen(s) {
    // 重开 = 取该任务 target/cmd/args 预填新建表单（纯前端跨页槽，见 app.js）
    App.reopenPrefill = {
      id: s.id, target: s.target || "", cmd: s.cmd || "all", args: s.args || ""
    };
    App.navigate("#/new");
  }

  function del(s) {
    var ok = window.confirm(
      "删除任务 " + App.shortId(s.id) + "（" + (s.target || "-") + "）？\n\n" +
      "· 仅删除任务记录、进度与日志文件\n" +
      "· out/ 产物保留在盘");
    if (!ok) return;
    API.deleteScan(s.id).then(function () {
      App.toast("任务已删除（out/ 产物保留在盘）", "ok");
      refresh().catch(function () { });
    }).catch(function (err) {
      App.toast(err && err.message ? err.message : "删除失败", "err");
    });
  }

  function renderRow(s) {
    var pending = s.status === "running" || s.status === "created";
    var terminal = s.status === "done" || s.status === "fail" || s.status === "stopped";
    var ts = App.pick(s, ["created_at", "started_at", "ts", "updated_at"]);

    var actions = App.h("td", null,
      App.h("button", {
        class: "btn", type: "button", text: "查看",
        onclick: function () { App.navigate("#/detail/" + encodeURIComponent(s.id)); }
      }));
    if (pending) {
      actions.appendChild(App.h("button", {
        class: "btn btn-danger", type: "button", text: "停止",
        onclick: function () {
          API.stopScan(s.id).then(function () {
            App.toast("停止指令已提交（任务 " + App.shortId(s.id) + "）", "ok");
          }).catch(function (err) {
            App.toast(err && err.message ? err.message : "停止失败", "err");
          });
        }
      }));
    }
    actions.appendChild(App.h("button", {
      class: "btn", type: "button", text: "重开",
      title: "按此任务的目标与参数预填新建表单",
      onclick: function () { reopen(s); }
    }));
    actions.appendChild(App.h("button", {
      class: "btn", type: "button", text: "删除",
      disabled: !terminal,
      title: terminal ? "删除任务记录（out/ 产物保留在盘）" : "运行中的任务需先停止才能删除",
      onclick: function () { del(s); }
    }));
    if (terminal) {
      actions.appendChild(App.h("button", {
        class: "btn", type: "button", text: "证据包",
        title: "导出该任务的证据包 zip",
        onclick: function () {
          App.downloadEvidenceZip(s.id).catch(function (err) {
            App.toast(err && err.message ? err.message : "证据包导出失败", "err");
          });
        }
      }));
    }
    return App.h("tr", null,
      App.h("td", { class: "mono", text: App.shortId(s.id) }),
      App.h("td", { class: "mono", text: s.target || "-" }),
      App.h("td", null, cmdCell(s.cmd)),
      App.h("td", null, chip(s.status)),
      App.h("td", { class: "mono", text: App.fmtTs(ts) }),
      actions);
  }

  function renderTable(scans) {
    wrap.textContent = "";
    if (!scans.length) {
      wrap.appendChild(App.h("div", { class: "empty-hint" },
        App.h("div", { text: "还没有扫描任务。" }),
        App.h("div", { text: "到「新建侦察」页面对授权目标发起第一次扫描。" }),
        App.h("a", { class: "btn btn-primary", href: "#/new", text: "前往新建侦察" })));
      return;
    }
    var thead = App.h("thead", null, App.h("tr", null,
      App.h("th", { text: "任务" }),
      App.h("th", { text: "目标" }),
      App.h("th", { text: "子命令" }),
      App.h("th", { text: "状态" }),
      App.h("th", { text: "时间" }),
      App.h("th", { text: "操作" })));
    var tbody = App.h("tbody", null, scans.map(renderRow));
    wrap.appendChild(App.h("table", { class: "data" }, thead, tbody));
  }

  function renderLoadState() {
    wrap.textContent = "";
    wrap.appendChild(App.h("div", { class: "empty-hint", text: "正在加载任务列表…" }));
  }

  function renderError(err) {
    wrap.textContent = "";
    var offline = err && err.status === 0;
    wrap.appendChild(App.h("div", { class: "empty-hint" },
      App.h("div", {
        text: offline
          ? "离线：无法获取任务列表，本地服务恢复后将自动刷新。"
          : "任务列表获取失败：" + (err && err.message ? err.message : "未知错误")
      }),
      offline ? null : App.h("button", {
        class: "btn", type: "button", text: "重试",
        onclick: function () { refresh().catch(function () { }); }
      })));
  }

  function refresh() {
    return API.listScans().then(function (scans) {
      everLoaded = true;
      App.setLatestScans(scans);
      renderStats(scans);
      renderTable(scans);
    }).catch(function (err) {
      // 统计与表格同源：失败时统计区一并回落为可读错态，不留旧数假装在线
      renderError(err);
      var stats = document.getElementById("taskStats");
      if (stats && !everLoaded) stats.textContent = "";
      throw err;
    });
  }

  App.registerView("tasks", {
    enter: function () {
      wrap = document.getElementById("tasksTableWrap");
      document.getElementById("tasksRefresh").onclick = function () {
        refresh().catch(function () { /* 错态已就地呈现 */ });
      };
      if (!everLoaded) renderLoadState();
      refresh().catch(function () { });
      poll = API.poll(refresh, 800);
    },
    leave: function () {
      if (poll) { poll.stop(); poll = null; }
    }
  });
})();
