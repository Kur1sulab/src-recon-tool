/* ============================================================
 * views/detail.js — ③ 任务详情
 * 模块进度表（模块 / 状态 / 耗时 / 详情）+ 结果产物表 + 原始日志 tail
 * 800ms 轮询 GET /api/scans/{id}，终态后停止轮询
 * ============================================================ */
(function () {
  "use strict";

  var poll = null;
  var currentId = null;
  var lastLogLen = -1;
  var pickerEl = null;

  function chip(status) {
    return App.h("span", { class: "chip", "data-s": status || "" },
      App.h("span", { class: "dot" }),
      App.statusLabel(status));
  }

  function staticPanels() {
    var body = document.getElementById("detailBody");
    return Array.prototype.filter.call(body.children, function (el) {
      return el.classList && el.classList.contains("panel");
    });
  }

  function showPicker(on) {
    staticPanels().forEach(function (p) { p.hidden = on; });
    if (!on && pickerEl) { pickerEl.remove(); pickerEl = null; }
  }

  function renderMeta(s) {
    var grid = document.getElementById("detailMeta");
    grid.textContent = "";
    var exit = s.exit_code;
    var cmd = s.cmd || "-";
    var cmdLabel = App.CMD_META[cmd] ? App.CMD_META[cmd].label + "（" + cmd + "）" : cmd;
    var rows = [
      ["任务", App.h("span", { class: "mono", text: String(s.id || "-") })],
      ["目标", App.h("span", { class: "mono", text: String(s.target || "-") })],
      ["子命令", App.h("span", { text: cmdLabel })],
      ["状态", chip(s.status)],
      ["退出码", App.h("span", { class: "mono", text: (exit === undefined || exit === null || exit === "") ? "-" : String(exit) })],
      ["开始时间", App.h("span", { class: "mono", text: App.fmtTs(App.pick(s, ["started_at", "created_at", "ts"])) })],
      ["结束时间", App.h("span", { class: "mono", text: App.fmtTs(App.pick(s, ["finished_at", "ended_at", "updated_at"])) })]
    ];
    rows.forEach(function (r) {
      grid.appendChild(App.h("div", { class: "k", text: r[0] }));
      grid.appendChild(App.h("div", { class: "v" }, r[1]));
    });

    var running = s.status === "running" || s.status === "created";
    document.getElementById("detailStop").hidden = !running;
    document.getElementById("detailEvidenceLink")
      .setAttribute("href", "#/evidence/" + encodeURIComponent(s.id || ""));
  }

  function renderProgress(progress) {
    var wrapEl = document.getElementById("detailProgressWrap");
    var note = document.getElementById("detailPipelineNote");
    wrapEl.textContent = "";
    note.textContent = "";

    var paired = App.pairProgress(progress);
    if (paired.pipeline.startTs !== undefined) {
      note.textContent = "流水线：" + App.fmtTs(paired.pipeline.startTs) +
        (paired.pipeline.endTs !== undefined ? " → " + App.fmtTs(paired.pipeline.endTs) : " → 进行中");
    }

    if (!paired.rows.length) {
      wrapEl.appendChild(App.h("div", { class: "empty-hint", text: "该任务暂无模块级进度（单模块任务直接查看下方日志）。" }));
      return;
    }
    var tbody = App.h("tbody", null, paired.rows.map(function (r) {
      var statusText = r.status === "running" ? "运行中"
        : (r.status === "done" ? "完成"
          : (r.status === "fail" ? "失败" : String(r.status || "-")));
      return App.h("tr", null,
        App.h("td", { text: r.label }),
        App.h("td", { class: "mono", text: String(r.module) }),
        App.h("td", null, App.h("span", {
          class: "chip",
          "data-s": r.status === "running" ? "running" : (r.status || "")
        }, App.h("span", { class: "dot" }), statusText)),
        App.h("td", { class: "num", text: r.durMs !== undefined ? App.fmtDur(r.durMs) : "-" }),
        App.h("td", { class: "mono", text: r.detail || "" }));
    }));
    wrapEl.appendChild(App.h("table", { class: "data" }, App.h("thead", null,
      App.h("tr", null,
        App.h("th", { text: "模块" }),
        App.h("th", { text: "标识" }),
        App.h("th", { text: "状态" }),
        App.h("th", { text: "耗时" }),
        App.h("th", { text: "详情" }))), tbody));
  }

  function renderArtifacts(artifacts) {
    var wrapEl = document.getElementById("detailArtifactsWrap");
    wrapEl.textContent = "";
    if (!artifacts || !artifacts.length) {
      wrapEl.appendChild(App.h("div", { class: "empty-hint", text: "暂无产物文件（任务运行中或模块未产出文件）。" }));
      return;
    }
    var tbody = App.h("tbody", null, artifacts.map(function (a) {
      return App.h("tr", null,
        App.h("td", { class: "mono", text: String(a.name || "-") }),
        App.h("td", { class: "num", text: App.fmtSize(a.size) }));
    }));
    wrapEl.appendChild(App.h("table", { class: "data" }, App.h("thead", null,
      App.h("tr", null,
        App.h("th", { text: "产物文件" }),
        App.h("th", { text: "大小" }))), tbody));
  }

  function renderLog(logTail) {
    var el = document.getElementById("detailLog");
    var text = logTail || "";
    if (text === "" && lastLogLen <= 0) { el.textContent = "（暂无日志）"; return; }
    // 用户上滚查看历史时不强制拉底
    var nearBottom = el.scrollHeight - el.scrollTop - el.clientHeight < 48;
    if (text.length !== lastLogLen) {
      el.textContent = text;
      lastLogLen = text.length;
      if (nearBottom) el.scrollTop = el.scrollHeight;
    }
  }

  function refresh() {
    if (!currentId) return Promise.resolve(false);
    return API.getScan(currentId).then(function (s) {
      renderMeta(s);
      renderProgress(s.progress || []);
      renderArtifacts(s.artifacts || []);
      renderLog(s.log_tail);
      var terminal = s.status === "done" || s.status === "fail" || s.status === "stopped";
      return !terminal; // false → 轮询自动停止
    });
  }

  function renderPicker() {
    showPicker(true);
    if (pickerEl) return;
    var sel = App.h("select", { class: "input", id: "pickerSelect" });
    sel.appendChild(App.h("option", { value: "", text: "加载任务列表…" }));
    var btn = App.h("button", {
      class: "btn btn-primary", type: "button", text: "打开",
      onclick: function () {
        if (sel.value) App.navigate("#/detail/" + encodeURIComponent(sel.value));
      }
    });
    pickerEl = App.h("div", { class: "panel" },
      App.h("div", { class: "panel-head" },
        App.h("div", { class: "panel-title", text: "未选择任务" })),
      App.h("div", { class: "task-picker" }, sel, btn),
      App.h("div", { class: "panel-foot", text: "选择一个任务查看模块进度、产物与日志，或先到「新建侦察」发起扫描。" }));
    document.getElementById("detailBody").appendChild(pickerEl);
    API.listScans().then(function (scans) {
      sel.textContent = "";
      if (!scans.length) {
        sel.appendChild(App.h("option", { value: "", text: "（暂无任务）" }));
        return;
      }
      scans.forEach(function (s) {
        sel.appendChild(App.h("option", {
          value: String(s.id),
          text: "#" + App.shortId(s.id) + " " + (s.target || "-") + " · " + (s.cmd || "-") + " · " + App.statusLabel(s.status)
        }));
      });
    }).catch(function () {
      sel.textContent = "";
      sel.appendChild(App.h("option", { value: "", text: "（无法连接本地服务）" }));
    });
  }

  App.registerView("detail", {
    enter: function (id) {
      currentId = id ? decodeURIComponent(id) : null;
      lastLogLen = -1;
      if (!currentId) {
        renderPicker();
        return;
      }
      showPicker(false);
      document.getElementById("detailRefresh").onclick = function () {
        refresh().catch(function () { });
      };
      document.getElementById("detailStop").onclick = function () {
        API.stopScan(currentId).then(function () {
          App.toast("停止指令已提交", "ok");
          refresh().catch(function () { });
        }).catch(function (err) {
          App.toast(err && err.message ? err.message : "停止失败", "err");
        });
      };
      refresh().catch(function () { });
      poll = API.poll(refresh, 800);
    },
    leave: function () {
      if (poll) { poll.stop(); poll = null; }
      currentId = null;
    }
  });
})();
