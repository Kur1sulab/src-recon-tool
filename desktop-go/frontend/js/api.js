/* ============================================================
 * api.js — 本地服务六接口封装（数据经 fetch 打 127.0.0.1 本地 API）
 * 契约：
 *   GET  /api/env                → {python:{found,path,version,deps_ok},out_dir,mock_reachable,whitelist}
 *   POST /api/scans              → 403 或 {id,status:'created'}
 *   GET  /api/scans              → {scans:[{id,target,cmd,args,status,created_at,finished_at}]}
 *   GET  /api/scans/{id}         → {id,target,cmd,args,status,exit_code,progress[],artifacts[],log_tail,evidence_path}
 *   POST /api/scans/{id}/stop    → {ok}
 *   DELETE /api/scans/{id}       → {ok}（running/created 拒删 → 409）
 *   GET  /api/scans/{id}/evidence→ zip 流
 * 全局对象：API
 * ============================================================ */
(function () {
  "use strict";

  function ApiError(status, message) {
    this.name = "ApiError";
    this.status = status;
    this.message = message;
  }
  ApiError.prototype = Object.create(Error.prototype);

  var statusListeners = [];
  var offlineState = null; // null=未知 true=离线 false=在线

  function setOffline(v) {
    if (offlineState !== v) {
      offlineState = v;
      statusListeners.forEach(function (cb) { cb(v); });
    }
  }

  function getOffline() { return offlineState === true; }

  /**
   * 底层请求：网络失败记离线态；成功清离线态。
   * 返回解析后的 JSON；isBlob 时返回 Response。
   */
  function request(path, opts, isBlob) {
    opts = opts || {};
    var init = {
      method: opts.method || "GET",
      headers: {}
    };
    if (opts.body !== undefined) {
      init.headers["Content-Type"] = "application/json";
      init.body = JSON.stringify(opts.body);
    }
    return fetch(path, init).then(function (res) {
      setOffline(false);
      if (isBlob) {
        if (!res.ok) return res.text().then(function (t) { throw httpError(res.status, t); });
        return res;
      }
      return res.text().then(function (text) {
        var data = null;
        if (text) {
          try { data = JSON.parse(text); }
          catch (e) { data = null; }
        }
        if (!res.ok) {
          throw httpError(res.status, data && data.error ? data.error : text || "");
        }
        return data;
      });
    }, function (err) {
      // fetch 网络层失败：本地服务不可达
      setOffline(true);
      throw new ApiError(0, "无法连接本地服务（127.0.0.1）");
    });
  }

  function httpError(status, raw) {
    var msg;
    if (status === 403) msg = "目标不在授权白名单，服务端已拒绝（403）";
    else if (status === 404) msg = "任务不存在或已被清理（404）";
    else if (status) msg = "服务端错误 " + status + (raw ? "：" + raw : "");
    else msg = raw || "请求失败";
    return new ApiError(status, msg);
  }

  var API = {
    ApiError: ApiError,
    getOffline: getOffline,
    onStatus: function (cb) { statusListeners.push(cb); },

    /** GET /api/env */
    env: function () { return request("/api/env"); },

    /** POST /api/scans {target,cmd,args?} → {id,status:'created'} */
    createScan: function (target, cmd, args) {
      var body = { target: target, cmd: cmd };
      if (args && String(args).trim()) body.args = String(args).trim();
      return request("/api/scans", { method: "POST", body: body });
    },

    /** GET /api/scans → {scans:[...]} */
    listScans: function () {
      return request("/api/scans").then(function (data) {
        return (data && data.scans) || [];
      });
    },

    /** GET /api/scans/{id} */
    getScan: function (id) { return request("/api/scans/" + encodeURIComponent(id)); },

    /** POST /api/scans/{id}/stop → {ok} */
    stopScan: function (id) {
      return request("/api/scans/" + encodeURIComponent(id) + "/stop", { method: "POST", body: {} });
    },

    /** DELETE /api/scans/{id} → {ok}；running/created 服务端拒删（409） */
    deleteScan: function (id) {
      return request("/api/scans/" + encodeURIComponent(id), { method: "DELETE" });
    },

    /** GET /api/scans/{id}/evidence → Blob（zip） */
    downloadEvidence: function (id) {
      return request("/api/scans/" + encodeURIComponent(id) + "/evidence", {}, true)
        .then(function (res) { return res.blob(); });
    },

    /**
     * 简单轮询：立即执行一次 fn，其后每 ms 重复；
     * fn 返回 false 可终止本轮。返回 {stop()}
     */
    poll: function (fn, ms) {
      var stopped = false;
      var timer = null;
      function tick() {
        if (stopped) return;
        Promise.resolve().then(fn).then(function (again) {
          if (stopped) return;
          if (again === false) return;
          timer = setTimeout(tick, ms);
        }).catch(function () {
          if (stopped) return;
          timer = setTimeout(tick, ms); // 出错也继续轮询（离线态由 request 统一标记）
        });
      }
      tick();
      return { stop: function () { stopped = true; if (timer) clearTimeout(timer); } };
    }
  };

  window.API = API;
})();
