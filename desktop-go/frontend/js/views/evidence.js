/* ============================================================
 * views/evidence.js — ④ 证据包：任务选择 + 产物清单 + 导出按钮
 * 导出走 GET /api/scans/{id}/evidence（zip 流 → Blob 下载），
 * 下载逻辑复用 App.downloadEvidenceZip（任务列表页同一入口）。
 * 产物清单与详情页同款：客户端分页每页 50 行。
 * 导出按钮按任务终态禁用：待开始/运行中的任务还不能导出（服务端
 * 在任务结束后聚合输出目录内文件），按钮禁用并注明。
 * ============================================================ */
(function () {
  "use strict";

  var PAGE = 50;
  var currentId = null;
  var lastStatus = null;  // 当前选中任务的状态，导出后恢复按钮时用
  var pgArtifacts = 0;    // 产物表页码（0 基），同任务内保持

  function renderMeta(s) {
    var grid = document.getElementById("evMeta");
    grid.textContent = "";
    if (!s) return;
    var rows = [
      ["目标", App.h("span", { class: "mono", text: String(s.target || "-") })],
      ["子命令", App.h("span", { text: String(s.cmd || "-") })],
      ["状态", App.h("span", { class: "chip", "data-s": s.status || "" },
        App.h("span", { class: "dot" }), App.statusLabel(s.status))]
    ];
    rows.forEach(function (r) { grid.appendChild(r[0]); grid.appendChild(r[1]); });
  }

  // 载态：任务选择器返回前，元信息区不放空白
  function renderMetaLoading() {
    var grid = document.getElementById("evMeta");
    grid.textContent = "";
    grid.appendChild(App.h("div", { class: "k", text: "任务信息" }));
    grid.appendChild(App.h("div", { class: "v", text: "正在加载任务信息…" }));
  }

  function renderArtifacts(artifacts) {
    var wrapEl = document.getElementById("evArtifactsWrap");
    var pagerEl = document.getElementById("evArtifactsPager");
    wrapEl.textContent = "";
    pagerEl.textContent = "";
    if (!artifacts || !artifacts.length) {
      wrapEl.appendChild(App.h("div", { class: "empty-hint", text: "该任务暂无产物清单（服务端导出时会聚合输出目录内现有文件）。" }));
      return;
    }
    var info = App.paginate(artifacts.length, pgArtifacts, PAGE);
    pgArtifacts = info.page;
    var slice = artifacts.slice(info.offset, info.offset + info.limit);

    var tbody = App.h("tbody", null, slice.map(function (a) {
      return App.h("tr", null,
        App.h("td", { class: "mono", text: String(a.name || "-") }),
        App.h("td", { class: "num", text: App.fmtSize(a.size) }));
    }));
    wrapEl.appendChild(App.h("table", { class: "data" },
      App.h("caption", { text: "产物清单" }),
      App.h("thead", null,
        App.h("tr", null,
          App.h("th", { scope: "col", text: "产物文件" }),
          App.h("th", { scope: "col", text: "大小" }))), tbody));
    App.renderPager(pagerEl, info, function (p) {
      pgArtifacts = p;
      renderArtifacts(artifacts); // 就地翻页：从已取数据切片，不重新请求
    });
  }

  function showError(msg) {
    var box = document.getElementById("evError");
    if (!msg) { box.classList.add("hidden"); box.textContent = ""; return; }
    box.textContent = msg;
    box.classList.remove("hidden");
  }

  // 待开始/运行中的任务禁用导出，并注明「任务结束后可导出」
  function setExportEnabled(on, busy) {
    document.getElementById("evExport").disabled = !on;
    var note = document.getElementById("evExportNote");
    if (note) {
      note.textContent = "任务运行中，结束后即可导出。";
      note.classList.toggle("hidden", !busy);
    }
  }

  function loadTask(id) {
    showError("");
    document.getElementById("evPathNote").textContent = "";
    pgArtifacts = 0; // 换任务回第一页
    if (!id) {
      lastStatus = null;
      renderMeta(null);
      setExportEnabled(false, false);
      var wrapEl = document.getElementById("evArtifactsWrap");
      wrapEl.textContent = "";
      document.getElementById("evArtifactsPager").textContent = "";
      wrapEl.appendChild(App.h("div", { class: "empty-hint", text: "选择任务后查看产物清单。" }));
      return Promise.resolve();
    }
    return API.getScan(id).then(function (s) {
      lastStatus = s.status || null;
      renderMeta(s);
      renderArtifacts(s.artifacts || []);
      var busy = s.status === "created" || s.status === "running";
      setExportEnabled(!busy, busy);
      var p = s.evidence_path || "";
      document.getElementById("evPathNote").textContent =
        p ? "服务端证据目录：" + p : "（任务结束后导出，服务端聚合输出目录内文件）";
    }).catch(function (err) {
      lastStatus = null;
      renderMeta(null);
      renderArtifacts([]);
      setExportEnabled(false, false);
      showError(err && err.message ? err.message : "任务信息加载失败");
    });
  }

  function exportZip() {
    if (!currentId) { showError("请先选择一个任务。"); return; }
    setExportEnabled(false, false);
    App.downloadEvidenceZip(currentId)
      .catch(function (err) {
        showError(err && err.message ? err.message : "导出失败");
      })
      .then(function () {
        // 导出完成后按任务终态恢复按钮：待开始/运行中仍保持禁用
        var busy = lastStatus === "created" || lastStatus === "running";
        setExportEnabled(!busy, false);
      });
  }

  function fillSelect(selectedId) {
    var sel = document.getElementById("evTaskSelect");
    sel.textContent = "";
    sel.appendChild(App.h("option", { value: "", text: "加载任务列表…" }));
    return API.listScans().then(function (scans) {
      sel.textContent = "";
      if (!scans.length) {
        sel.appendChild(App.h("option", { value: "", text: "（暂无任务）" }));
        return;
      }
      scans.forEach(function (s) {
        sel.appendChild(App.h("option", {
          value: String(s.id),
          selected: selectedId && String(s.id) === String(selectedId),
          text: "#" + App.shortId(s.id) + " " + (s.target || "-") + " · " + (s.cmd || "-") + " · " + App.statusLabel(s.status)
        }));
      });
    }).catch(function () {
      sel.textContent = "";
      sel.appendChild(App.h("option", { value: "", text: "离线：无法获取任务列表，可点其他页后重进本页重试。" }));
    });
  }

  App.registerView("evidence", {
    enter: function (id) {
      currentId = id ? decodeURIComponent(id) : null;
      lastStatus = null;
      pgArtifacts = 0;
      setExportEnabled(!!currentId, false);
      renderMetaLoading();
      document.getElementById("evTaskSelect").onchange = function () {
        currentId = this.value || null;
        loadTask(currentId);
      };
      document.getElementById("evExport").onclick = exportZip;
      fillSelect(currentId).then(function () {
        var sel = document.getElementById("evTaskSelect");
        if (!currentId && sel.value) {
          // 未指定任务时默认选最新一条
          currentId = sel.value;
        }
        loadTask(currentId);
      });
    }
  });
})();
