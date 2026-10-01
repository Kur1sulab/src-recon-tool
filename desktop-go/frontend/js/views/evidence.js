/* ============================================================
 * views/evidence.js — ④ 证据包：任务选择 + 产物清单 + 导出按钮
 * 导出走 GET /api/scans/{id}/evidence（zip 流 → Blob 下载）
 * ============================================================ */
(function () {
  "use strict";

  var currentId = null;

  function metaRow(k, vNode) {
    return [App.h("div", { class: "k", text: k }), App.h("div", { class: "v" }, vNode)];
  }

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

  function renderArtifacts(artifacts) {
    var wrapEl = document.getElementById("evArtifactsWrap");
    wrapEl.textContent = "";
    if (!artifacts || !artifacts.length) {
      wrapEl.appendChild(App.h("div", { class: "empty-hint", text: "该任务暂无产物清单（服务端导出时会聚合输出目录内现有文件）。" }));
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

  function showError(msg) {
    var box = document.getElementById("evError");
    if (!msg) { box.classList.add("hidden"); box.textContent = ""; return; }
    box.textContent = msg;
    box.classList.remove("hidden");
  }

  function loadTask(id) {
    showError("");
    document.getElementById("evPathNote").textContent = "";
    if (!id) {
      renderMeta(null);
      renderArtifacts([]);
      return Promise.resolve();
    }
    return API.getScan(id).then(function (s) {
      renderMeta(s);
      renderArtifacts(s.artifacts || []);
      var p = s.evidence_path || "";
      document.getElementById("evPathNote").textContent =
        p ? "服务端证据目录：" + p : "（任务结束后导出，服务端聚合输出目录内文件）";
    }).catch(function (err) {
      renderMeta(null);
      renderArtifacts([]);
      showError(err && err.message ? err.message : "任务信息加载失败");
    });
  }

  function exportZip() {
    if (!currentId) { showError("请先选择一个任务。"); return; }
    var btn = document.getElementById("evExport");
    btn.disabled = true;
    API.downloadEvidence(currentId).then(function (blob) {
      var name = "evidence-" + App.shortId(currentId) + ".zip";
      var url = URL.createObjectURL(blob);
      var a = document.createElement("a");
      a.href = url;
      a.download = name;
      document.body.appendChild(a);
      a.click();
      a.remove();
      setTimeout(function () { URL.revokeObjectURL(url); }, 4000);
      App.toast("证据包已导出：" + name, "ok");
    }).catch(function (err) {
      showError(err && err.message ? err.message : "导出失败");
    }).then(function () {
      btn.disabled = false;
    });
  }

  function fillSelect(selectedId) {
    var sel = document.getElementById("evTaskSelect");
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
      sel.appendChild(App.h("option", { value: "", text: "（无法连接本地服务）" }));
    });
  }

  App.registerView("evidence", {
    enter: function (id) {
      currentId = id ? decodeURIComponent(id) : null;
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
          loadTask(currentId);
        } else {
          loadTask(currentId);
        }
      });
    }
  });
})();
