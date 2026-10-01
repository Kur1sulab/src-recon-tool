/* ============================================================
 * views/new.js — ② 新建侦察：目标 + 子命令下拉 + 可选参数 + 白名单提示
 * 提交 POST /api/scans → 跳转任务详情
 * ============================================================ */
(function () {
  "use strict";

  var whitelist = [];      // 服务端下发（只读），客户端预检仅作提示，服务端 403 才是权威

  // 从目标串提取 host[:port]：剥掉协议与路径
  function hostOf(target) {
    var s = String(target || "").trim();
    if (!s) return "";
    s = s.replace(/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//, "");
    s = s.split("/")[0];
    return s.toLowerCase();
  }

  function inWhitelist(target) {
    if (!whitelist.length) return true; // 名单未加载时不做本地拦截，交给服务端
    var host = hostOf(target);
    return whitelist.some(function (w) {
      return String(w).toLowerCase() === host;
    });
  }

  function updateHints() {
    var cmd = document.getElementById("newCmd").value;
    var meta = App.CMD_META[cmd] || { kind: "target", hint: "" };
    var hint = document.getElementById("newCmdHint");
    hint.textContent = meta.hint || "";

    var target = document.getElementById("newTarget").value.trim();
    var tHint = document.getElementById("newTargetHint");
    tHint.className = "field-hint";
    if (!target) { tHint.textContent = ""; return; }
    if (meta.kind === "url" && !/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(target)) {
      tHint.textContent = "该模块需要完整 URL（含 http:// 或 https://）。";
      tHint.classList.add("warn");
    } else if (meta.kind === "ip" && !/^\d{1,3}(\.\d{1,3}){3}$/.test(hostOf(target))) {
      tHint.textContent = "该模块的目标应为 IP 地址。";
      tHint.classList.add("warn");
    } else if ((meta.kind === "domain") && /\//.test(target)) {
      tHint.textContent = "该模块的目标应为域名（不含路径）。";
      tHint.classList.add("warn");
    } else if (!inWhitelist(target)) {
      tHint.textContent = "该目标不在授权白名单中，提交将被服务端拒绝。";
      tHint.classList.add("warn");
    } else {
      tHint.textContent = "目标已在授权白名单内。";
    }
  }

  function renderWhitelist(env) {
    var ul = document.getElementById("newWhitelist");
    ul.textContent = "";
    whitelist = (env && Array.isArray(env.whitelist)) ? env.whitelist : [];
    if (!whitelist.length) {
      ul.appendChild(App.h("li", { class: "wl-loading", text: "白名单暂不可用（服务端未返回）" }));
      return;
    }
    whitelist.forEach(function (w) {
      ul.appendChild(App.h("li", {
        text: String(w) + (String(w).indexOf("127.0.0.1") === 0 ? "（本机 mock 靶站）" : "（自有资产）")
      }));
    });
  }

  function loadEnv() {
    return API.env().then(function (env) {
      renderWhitelist(env);
      updateHints();
    }).catch(function () { /* 离线态由全局横幅提示 */ });
  }

  function showError(msg) {
    var box = document.getElementById("newError");
    if (!msg) { box.classList.add("hidden"); box.textContent = ""; return; }
    box.textContent = msg;
    box.classList.remove("hidden");
  }

  function submit(e) {
    e.preventDefault();
    var target = document.getElementById("newTarget").value.trim();
    var cmd = document.getElementById("newCmd").value;
    var args = document.getElementById("newArgs").value.trim();
    showError("");
    if (!target) { showError("请先填写扫描目标。"); return; }
    if (!App.CMD_META[cmd]) { showError("未知的扫描模块。"); return; }

    var btn = document.getElementById("newSubmit");
    btn.disabled = true;
    API.createScan(target, cmd, args).then(function (res) {
      btn.disabled = false;
      var id = res && res.id;
      App.toast("任务已创建（" + App.shortId(id) + "）", "ok");
      document.getElementById("newTarget").value = "";
      document.getElementById("newArgs").value = "";
      updateHints();
      if (id) App.navigate("#/detail/" + encodeURIComponent(id));
    }).catch(function (err) {
      btn.disabled = false;
      showError(err && err.message ? err.message : "创建任务失败");
    });
  }

  App.registerView("new", {
    enter: function () {
      document.getElementById("newCmd").onchange = updateHints;
      document.getElementById("newTarget").oninput = updateHints;
      document.getElementById("newScanForm").onsubmit = submit;
      updateHints();
      loadEnv();
    }
  });
})();
