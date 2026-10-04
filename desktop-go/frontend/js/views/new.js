/* ============================================================
 * views/new.js — ② 新建任务：目标 + 子命令下拉 + 可选参数 + 白名单提示
 * 提交 POST /api/scans → 跳转任务详情。
 * 目标输入支持 ↑/↓ 回填会话内存历史（App.targetHistory，刷新即失，
 * 不用 localStorage）；「重开」经 App.reopenPrefill 跨页预填。
 * ============================================================ */
(function () {
  "use strict";

  var whitelist = [];      // 服务端下发（只读），客户端预检仅作提示，服务端 403 才是权威
  var histIdx = null;      // null=正在编辑草稿；否则指向 targetHistory 下标
  var draft = "";          // 进入历史浏览前的草稿

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

  /* ---------- 目标历史：↑ 回填 / ↓ 前进（会话内存） ---------- */

  function targetKeydown(e) {
    if (e.isComposing || e.ctrlKey || e.metaKey || e.altKey) return;
    var input = e.target;
    if (e.key === "ArrowUp") {
      if (!App.targetHistory.length) return;
      e.preventDefault();
      if (histIdx === null) draft = input.value;
      histIdx = (histIdx === null) ? App.targetHistory.length - 1 : Math.max(0, histIdx - 1);
      input.value = App.targetHistory[histIdx];
      moveCaretEnd(input);
      updateHints();
    } else if (e.key === "ArrowDown") {
      if (histIdx === null) return;
      e.preventDefault();
      histIdx++;
      if (histIdx >= App.targetHistory.length) {
        histIdx = null;
        input.value = draft; // 回到草稿
      } else {
        input.value = App.targetHistory[histIdx];
      }
      moveCaretEnd(input);
      updateHints();
    }
  }

  function moveCaretEnd(input) {
    var n = input.value.length;
    try { input.setSelectionRange(n, n); } catch (e2) { /* 部分类型不支持 */ }
  }

  function targetInput() {
    histIdx = null; // 手动编辑即离开历史浏览
    updateHints();
  }

  /* ---------- 提示与白名单 ---------- */

  function updateHints() {
    var cmd = document.getElementById("newCmd").value;
    var meta = App.CMD_META[cmd] || { kind: "target", hint: "" };
    var hint = document.getElementById("newCmdHint");
    hint.textContent = meta.hint || "";

    var target = document.getElementById("newTarget").value.trim();
    var tHint = document.getElementById("newTargetHint");
    tHint.className = "field-hint";
    if (!target) {
      tHint.textContent = App.targetHistory.length
        ? "按 ↑ 可回填本次会话内用过的目标。"
        : "";
      return;
    }
    if (meta.kind === "url" && !/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(target)) {
      tHint.textContent = "该模块需要完整 URL（含 http:// 或 https://）。";
      tHint.classList.add("warn");
    } else if (meta.kind === "ip" && !/^\d{1,3}(\.\d{1,3}){3}$/.test(hostOf(target))) {
      tHint.textContent = "该模块的目标应为 IP 地址。";
      tHint.classList.add("warn");
    } else if ((meta.kind === "domain") && /\//.test(target)) {
      tHint.textContent = "该模块的目标应为域名（不含路径）。";
      tHint.classList.add("warn");
    } else if (!whitelist.length) {
      // 名单未加载完成时不做语义判断（此前会误报"已在白名单内"），
      // 给中性文案，最终以服务端硬闸为准
      tHint.textContent = "白名单尚未加载完成，提交时以服务端校验为准。";
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

  function renderWhitelistError(err) {
    var ul = document.getElementById("newWhitelist");
    ul.textContent = "";
    var offline = err && err.status === 0;
    ul.appendChild(App.h("li", {
      class: "wl-loading",
      text: offline
        ? "白名单加载失败（离线或服务未启动）；提交时以服务端校验为准。"
        : "白名单加载失败：" + (err && err.message ? err.message : "未知错误") + "；提交时以服务端校验为准。"
    }));
  }

  function loadEnv() {
    return API.env().then(function (env) {
      renderWhitelist(env);
      updateHints();
    }).catch(function (err) {
      renderWhitelistError(err);
    });
  }

  /* ---------- 提交 ---------- */

  function showError(msg) {
    var box = document.getElementById("newError");
    if (!msg) { box.classList.add("hidden"); box.textContent = ""; return; }
    box.textContent = msg;
    box.classList.remove("hidden");
  }

  function applyReopenPrefill() {
    if (!App.reopenPrefill) return;
    var p = App.reopenPrefill;
    App.reopenPrefill = null;
    var targetEl = document.getElementById("newTarget");
    var cmdEl = document.getElementById("newCmd");
    var argsEl = document.getElementById("newArgs");
    targetEl.value = p.target || "";
    if (p.cmd && App.CMD_META[p.cmd]) cmdEl.value = p.cmd;
    argsEl.value = p.args || "";
    showError("");
    App.toast("已按历史任务 #" + App.shortId(p.id) + " 预填，确认后开始扫描", "ok");
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
      App.rememberTarget(target); // 会话内历史：↑ 可回填
      App.toast("任务已创建（" + App.shortId(id) + "）", "ok");
      document.getElementById("newTarget").value = "";
      document.getElementById("newArgs").value = "";
      histIdx = null;
      draft = "";
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
      document.getElementById("newTarget").oninput = targetInput;
      document.getElementById("newTarget").onkeydown = targetKeydown;
      document.getElementById("newScanForm").onsubmit = submit;
      applyReopenPrefill();
      updateHints();
      loadEnv();
    }
  });
})();
