/* ============================================================
 * views/tasks.js — ① 任务列表：统计区 + 状态筛选 + 分页表格
 * 800ms 轮询 GET /api/scans；轮询只重画当前筛选的当前页（每页 50 行，
 * 页码跨轮询保持），避免任务数过百后整表全量重建卡顿。
 * 统计数字全部由列表现算（总/运行中/完成/失败），零占位假数；
 * 首次成功后再遇错时统计卡保留旧数字并标注「离线前旧值」，与表格错态对齐。
 * 行内操作：查看 / 停止（待开始+运行中）/ 重开（预填新建表单）/
 *          删除（仅终态；应用内确认面板；out/ 产物保留在盘）/ 证据包（仅终态）
 * ============================================================ */
(function () {
  "use strict";

  var PAGE = 50;
  var poll = null;
  var wrap = null;
  var everLoaded = false; // 载态/空态区分：首次成功前不显示空态
  var lastScans = [];     // 最近一次成功拉取的全量列表（筛选/分页/统计同源）
  var filter = "all";     // 状态筛选：all|created|running|done|fail|stopped
  var page = 0;           // 当前页（0 基），翻页与轮询间保持

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

  // 错态回落：统计卡保留旧数字，但明示「离线前旧值」（样式挂钩 data-stale 由美术线接）
  function setStatsStale(on) {
    var note = document.getElementById("taskStatsStale");
    if (note) note.classList.toggle("hidden", !on);
    var stats = document.getElementById("taskStats");
    if (!stats) return;
    if (on) stats.setAttribute("data-stale", "1");
    else stats.removeAttribute("data-stale");
  }

  /* ---------- 行内操作 ---------- */

  function reopen(s) {
    // 重开 = 取该任务 target/cmd/args 预填新建表单（纯前端跨页槽，见 app.js）
    App.reopenPrefill = {
      id: s.id, target: s.target || "", cmd: s.cmd || "all", args: s.args || ""
    };
    App.navigate("#/new");
  }

  /* ---------- 应用内删除确认面板 ----------
   * 类名契约：.confirm-scrim > .confirm-box，内部复用 .panel-title 与 .btn/.btn-danger。
   * 替代 window.confirm（WebView2 壳内原生对话框可用性未实测，应用内面板最稳）。
   * 打开时经 App.activeConfirm 挂到全局：Esc 只关面板，不触发两段式停止。
   */
  var confirmEl = null;

  function closeConfirm() {
    if (confirmEl) { confirmEl.remove(); confirmEl = null; }
    App.activeConfirm = null;
  }

  function openDeleteConfirm(s) {
    closeConfirm();
    var sid = App.shortId(s.id);
    var busy = false; // 确认中禁点
    var btnCancel = App.h("button", {
      class: "btn", type: "button", text: "取消",
      onclick: function () { closeConfirm(); }
    });
    var btnOk = App.h("button", {
      class: "btn btn-danger", type: "button", text: "确认删除",
      onclick: function () {
        if (busy) return;
        busy = true;
        btnCancel.disabled = true;
        btnOk.disabled = true;
        btnOk.textContent = "删除中…";
        API.deleteScan(s.id).then(function () {
          closeConfirm();
          App.toast("任务已删除（out/ 产物保留在盘）", "ok");
          refresh().catch(function () { });
        }).catch(function (err) {
          closeConfirm();
          App.toast(err && err.message ? err.message : "删除失败", "err");
        });
      }
    });
    var box = App.h("div", {
      class: "confirm-box",
      role: "alertdialog",
      "aria-modal": "true",
      "aria-label": "确认删除任务 " + sid
    },
      App.h("div", { class: "panel-title", text: "删除任务 " + sid + "（" + (s.target || "-") + "）" }),
      App.h("p", { text: "只删除任务记录、进度与日志文件；out/ 产物保留在盘。" }),
      App.h("p", { text: "删除后无法恢复，确定要删除吗？" }),
      App.h("div", { class: "form-actions" }, btnCancel, btnOk));
    // 焦点困住：Tab / Shift+Tab 只在取消与确认两个按钮间循环
    box.addEventListener("keydown", function (e) {
      if (e.key !== "Tab") return;
      var order = [btnCancel, btnOk];
      var idx = order.indexOf(document.activeElement);
      if (e.shiftKey && idx <= 0) { e.preventDefault(); btnOk.focus(); }
      else if (!e.shiftKey && idx !== 0) { e.preventDefault(); btnCancel.focus(); }
    });
    confirmEl = App.h("div", { class: "confirm-scrim" }, box);
    document.body.appendChild(confirmEl);
    App.activeConfirm = { close: function () { closeConfirm(); } };
    btnCancel.focus();
  }

  function del(s) {
    openDeleteConfirm(s);
  }

  function renderRow(s) {
    var pending = s.status === "running" || s.status === "created";
    var terminal = s.status === "done" || s.status === "fail" || s.status === "stopped";
    var sid = App.shortId(s.id);
    var target = s.target || "-";

    var actions = App.h("td", null,
      App.h("button", {
        class: "btn", type: "button", text: "查看",
        "aria-label": "查看任务 " + sid + " " + target,
        onclick: function () { App.navigate("#/detail/" + encodeURIComponent(s.id)); }
      }));
    if (pending) {
      actions.appendChild(App.h("button", {
        class: "btn btn-danger", type: "button", text: "停止",
        "aria-label": "停止任务 " + sid + " " + target,
        title: s.status === "created" ? "任务尚未开始运行，也可停止" : "停止该扫描任务",
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
      "aria-label": "按任务 " + sid + " 的目标与参数预填新建表单",
      onclick: function () { reopen(s); }
    }));
    actions.appendChild(App.h("button", {
      class: "btn", type: "button", text: "删除",
      disabled: !terminal,
      title: terminal ? "删除任务记录（out/ 产物保留在盘）" : "运行中的任务需先停止才能删除",
      "aria-label": "删除任务 " + sid + " " + target + (terminal ? "" : "（需先停止）"),
      onclick: function () { del(s); }
    }));
    if (terminal) {
      actions.appendChild(App.h("button", {
        class: "btn", type: "button", text: "证据包",
        title: "导出该任务的证据包 zip",
        "aria-label": "导出任务 " + sid + " 的证据包",
        onclick: function () {
          App.downloadEvidenceZip(s.id).catch(function (err) {
            App.toast(err && err.message ? err.message : "证据包导出失败", "err");
          });
        }
      }));
    }
    return App.h("tr", null,
      App.h("td", { class: "mono", text: sid }),
      App.h("td", { class: "mono", text: target }),
      App.h("td", null, cmdCell(s.cmd)),
      App.h("td", null, chip(s.status)),
      // 「创建时间」固定取 created_at，缺失显示 -
      App.h("td", { class: "mono", text: App.fmtTs(s.created_at) }),
      actions);
  }

  function visibleScans() {
    if (filter === "all") return lastScans;
    return lastScans.filter(function (s) { return s.status === filter; });
  }

  function renderTable() {
    wrap.textContent = "";
    if (!lastScans.length) {
      wrap.appendChild(App.h("div", { class: "empty-hint" },
        App.h("div", { text: "还没有扫描任务。" }),
        App.h("div", { text: "到「新建任务」页面对授权目标发起第一次扫描。" }),
        App.h("a", { class: "btn btn-primary", href: "#/new", text: "前往新建任务" })));
      return;
    }
    var visible = visibleScans();
    if (!visible.length) {
      wrap.appendChild(App.h("div", { class: "empty-hint",
        text: "没有符合当前筛选状态的任务，可切换上方筛选，或到「新建任务」发起扫描。" }));
      return;
    }
    var info = App.paginate(visible.length, page, PAGE);
    page = info.page; // 夹紧（列表缩短时页码回退），跨轮询保持
    var slice = visible.slice(info.offset, info.offset + info.limit);

    var thead = App.h("thead", null, App.h("tr", null,
      App.h("th", { scope: "col", text: "任务" }),
      App.h("th", { scope: "col", text: "目标" }),
      App.h("th", { scope: "col", text: "子命令" }),
      App.h("th", { scope: "col", text: "状态" }),
      App.h("th", { scope: "col", text: "创建时间" }),
      App.h("th", { scope: "col", text: "操作" })));
    var tbody = App.h("tbody", null, slice.map(renderRow));
    wrap.appendChild(App.h("table", { class: "data" },
      App.h("caption", { text: "扫描任务列表" }), thead, tbody));
    App.renderPager(document.getElementById("tasksPager"), info, function (p) {
      page = p;
      renderTable(); // 就地翻页：从已取数据切片，不重新请求
    });
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
      lastScans = scans;
      App.setLatestScans(scans);
      setStatsStale(false);
      renderStats(scans);
      renderTable();
    }).catch(function (err) {
      // 统计与表格同源：首次成功后再遇错，统计卡保留旧数字并标注「旧值」，
      // 与表格错态对齐；从未成功过则统计区一并清空，不留假数。
      renderError(err);
      if (everLoaded) {
        setStatsStale(true);
      } else {
        var stats = document.getElementById("taskStats");
        if (stats) stats.textContent = "";
      }
      throw err;
    });
  }

  App.registerView("tasks", {
    enter: function () {
      wrap = document.getElementById("tasksTableWrap");
      document.getElementById("tasksRefresh").onclick = function () {
        refresh().catch(function () { /* 错态已就地呈现 */ });
      };
      var sel = document.getElementById("taskStatusFilter");
      sel.value = filter;
      sel.onchange = function () {
        filter = this.value;
        page = 0; // 换筛选回第一页
        renderTable();
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
