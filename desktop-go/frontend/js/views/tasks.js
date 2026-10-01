/* ============================================================
 * views/tasks.js — ① 任务列表：目标 / 子命令 / 状态 / 时间
 * 800ms 轮询 GET /api/scans
 * ============================================================ */
(function () {
  "use strict";

  var poll = null;
  var wrap = null;

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

  function renderRow(s) {
    var running = s.status === "running" || s.status === "created";
    var ts = App.pick(s, ["created_at", "started_at", "ts", "updated_at"]);
    var viewBtn = App.h("button", {
      class: "btn", type: "button", text: "查看",
      onclick: function () { App.navigate("#/detail/" + encodeURIComponent(s.id)); }
    });
    var actions = App.h("td", null, viewBtn);
    if (running) {
      // 与前一个按钮的间距走 CSS（.data td .btn + .btn），CSP 禁内联 style
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

  function refresh() {
    return API.listScans().then(function (scans) {
      App.setLatestScans(scans);
      renderTable(scans);
    });
  }

  App.registerView("tasks", {
    enter: function () {
      wrap = document.getElementById("tasksTableWrap");
      document.getElementById("tasksRefresh").onclick = function () {
        refresh().catch(function () { /* 离线态由全局横幅提示 */ });
      };
      refresh().catch(function () { });
      poll = API.poll(refresh, 800);
    },
    leave: function () {
      if (poll) { poll.stop(); poll = null; }
    }
  });
})();
