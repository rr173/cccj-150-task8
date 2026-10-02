/* 地籍平台前端：Canvas 地图编辑 + 离线采集 + 争议裁定 + 生命周期 + 证明/血缘。 */
"use strict";

// --------------------------------------------------------------- 工具
const $ = (s) => document.querySelector(s);
const $$ = (s) => Array.from(document.querySelectorAll(s));
const api = async (path, opts = {}) => {
  const r = await fetch(path, {
    headers: opts.body ? { "Content-Type": "application/json" } : {},
    ...opts,
    body: opts.body ? JSON.stringify(opts.body) : undefined,
  });
  const data = await r.json().catch(() => ({}));
  if (!r.ok) {
    // status===0：未拿到任何 HTTP 响应（断网/连接失败），调用方可安全同键重试
    const det = data.detail;
    const msg = det == null ? r.statusText
      : typeof det === "string" ? det
      : (det.message || JSON.stringify(det));
    const err = new Error(msg);
    err.httpStatus = r.status;
    err.detail = det;
    throw err;
  }
  return data;
};
const toast = (msg, kind = "") => {
  const t = $("#toast");
  t.textContent = msg;
  t.className = kind;
  setTimeout(() => t.classList.add("hidden"), 4200);
};
const fmt = (o) => JSON.stringify(o, null, 2);
const closeRing = (r) => r.length ? [...r, r[0]] : r;
const polyArea = (ring) => {
  let s = 0;
  for (let i = 0; i < ring.length; i++) {
    const [x1, y1] = ring[i], [x2, y2] = ring[(i + 1) % ring.length];
    s += x1 * y2 - x2 * y1;
  }
  return Math.abs(s / 2);
};
const dist2 = (a, b) => Math.hypot(a[0] - b[0], a[1] - b[1]);

// --------------------------------------------------------------- 状态
const state = {
  tool: "add",
  draft: [],                 // 编辑中候选环（含点元信息指针）
  draftPoints: {},           // idx -> {accuracy, marker, photos, confirmedBy}
  targetParcel: "",
  confirms: [],
  map: { parcels: [], points: [], disputes: [], certificates: [] },
  view: { scale: 3.2, ox: 120, oy: 520 },
  dragging: null,
  panning: null,
  timeView: null,            // ISO 时间点
  selectedDispute: null,
  revising: false,           // 争议修订模式
  reviseChain: [],
  meta: {},                  // 版本等下拉缓存
  plans: [],                 // 活动计划（来自 /api/map，用于占用叠加）
};

// --------------------------------------------------------------- 视图变换
const canvas = $("#map"), ctx = canvas.getContext("2d");
const w2s = ([x, y]) => [x * state.view.scale + state.view.ox,
                         -y * state.view.scale + state.view.oy];
const s2w = ([sx, sy]) => [(sx - state.view.ox) / state.view.scale,
                           -(sy - state.view.oy) / state.view.scale];

function fitView(pts) {
  if (!pts.length) return;
  const xs = pts.map((p) => p[0]), ys = pts.map((p) => p[1]);
  const minX = Math.min(...xs), maxX = Math.max(...xs);
  const minY = Math.min(...ys), maxY = Math.max(...ys);
  const pad = 60;
  const sx = (canvas.width - pad * 2) / Math.max(maxX - minX, 1);
  const sy = (canvas.height - pad * 2) / Math.max(maxY - minY, 1);
  state.view.scale = Math.min(sx, sy, 8);
  const cx = (minX + maxX) / 2, cy = (minY + maxY) / 2;
  state.view.ox = canvas.width / 2 - cx * state.view.scale;
  state.view.oy = canvas.height / 2 + cy * state.view.scale;
}

// --------------------------------------------------------------- 绘制
const COLORS = {
  current: "#5c8dff", history: "#55647e", draft: "#ffd083",
  base: "#9aa7bd", a: "#ff6b6b", b: "#4dabff", anchor: "#ffef9a",
};

function drawPoly(ring, color, fill = null, width = 2, dash = []) {
  if (ring.length < 2) return;
  const pts = closeRing(ring).map(w2s);
  ctx.beginPath();
  ctx.moveTo(pts[0][0], pts[0][1]);
  pts.slice(1).forEach(([x, y]) => ctx.lineTo(x, y));
  if (fill) { ctx.fillStyle = fill; ctx.fill(); }
  ctx.strokeStyle = color; ctx.lineWidth = width;
  ctx.setLineDash(dash); ctx.stroke(); ctx.setLineDash([]);
}
function drawChain(chain, color, width = 3, dash = []) {
  if (chain.length < 2) return;
  const pts = chain.map(w2s);
  ctx.beginPath();
  ctx.moveTo(pts[0][0], pts[0][1]);
  pts.slice(1).forEach(([x, y]) => ctx.lineTo(x, y));
  ctx.strokeStyle = color; ctx.lineWidth = width; ctx.setLineDash(dash); ctx.stroke();
  ctx.setLineDash([]);
}
function drawVertex(p, color, r = 4, label = "") {
  const [x, y] = w2s(p);
  ctx.beginPath(); ctx.arc(x, y, r, 0, 7); ctx.fillStyle = color; ctx.fill();
  ctx.strokeStyle = "#0b101b"; ctx.lineWidth = 1; ctx.stroke();
  if (label) {
    ctx.fillStyle = "#cdd9f2"; ctx.font = "10px monospace";
    ctx.fillText(label, x + 6, y - 6);
  }
}
function drawGrid() {
  const step = state.view.scale > 5 ? 10 : 25;
  const [wx1, wy2] = s2w([0, 0]), [wx2, wy1] = s2w([canvas.width, canvas.height]);
  ctx.strokeStyle = "#15202f"; ctx.lineWidth = 1;
  ctx.beginPath();
  for (let x = Math.floor(wx1 / step) * step; x <= wx2; x += step) {
    const [sx] = w2s([x, 0]); ctx.moveTo(sx, 0); ctx.lineTo(sx, canvas.height);
  }
  for (let y = Math.floor(wy1 / step) * step; y <= wy2; y += step) {
    const [, sy] = w2s([0, y]); ctx.moveTo(0, sy); ctx.lineTo(canvas.width, sy);
  }
  ctx.stroke();
}

function render() {
  ctx.clearRect(0, 0, canvas.width, canvas.height);
  if ($("#layer-grid").checked) drawGrid();

  // 库内宗地
  for (const p of state.map.parcels) {
    let show = state.timeView ? (state.meta["at_" + p.id] || null) : p.current;
    if ($("#layer-history").checked && !state.timeView) {
      versions.slice(0, -1).forEach((v, i) => {
        if (state.meta.ringCache && state.meta.ringCache[v.id])
          drawPoly(state.meta.ringCache[v.id], COLORS.history, "rgba(90,110,140,.05)", 1, [4, 4]);
      });
    }
    if (show && show.ring) {
      drawPoly(show.ring, state.timeView ? "#7be0a3" : COLORS.current,
               "rgba(92,141,255,.08)", 2);
      const area = show.area != null ? show.area : polyArea(show.ring);
      const [cx, cy] = w2s(centroid(show.ring));
      ctx.fillStyle = "#9fc1ff"; ctx.font = "bold 12px sans-serif";
      ctx.fillText(`${p.label || p.id}  ${Math.round(area)} m²`, cx - 40, cy);
      if (show.version_no != null) {
        ctx.fillStyle = "#7389b0"; ctx.font = "10px monospace";
        ctx.fillText(`v${show.version_no}${state.timeView ? " @ " + state.timeView.slice(0, 10) : ""}`, cx - 20, cy + 15);
      }
    }
  }

  // 选中更正草案的预演几何（虚线琥珀色，明确区别于在版版本）
  const dp = draftState.detail;
  if (dp && dp.preview && state.timeView === null) {
    for (const n of dp.preview.nodes) {
      if (!n.new_ring) continue;
      const isTarget = n.op_type === "TARGET";
      drawPoly(n.new_ring, isTarget ? "rgba(255,208,131,.10)" : "rgba(255,208,131,.05)");
      ctx.strokeStyle = isTarget ? "#ffcf6b" : "rgba(255,207,107,.55)";
      ctx.lineWidth = isTarget ? 2 : 1;
      ctx.setLineDash(isTarget ? [7, 5] : [3, 4]);
      ctx.stroke();
      ctx.setLineDash([]);
      const a = w2s(n.new_ring[isTarget ? 0 : Math.max(0, Math.floor(n.new_ring.length / 2))]);
      ctx.fillStyle = "#ffcf6b";
      ctx.font = "10px monospace";
      ctx.fillText(isTarget ? "草案(未生效)" : `预演 ${n.parcel_id.slice(6)}`,
                   a[0] + 3, a[1] - 4);
    }
  }

  // 生效计划对地块的互斥占用（紫/品红描边；选中计划高亮）
  if ($("#layer-plan") && $("#layer-plan").checked && !state.timeView) {
    const occSet = new Map(); // parcel_id -> plan statuses
    for (const pl of (state.map.effect_plans || [])) {
      for (const o of (pl.occupancy || [])) {
        if (!occSet.has(o.parcel_id)) occSet.set(o.parcel_id, []);
        occSet.get(o.parcel_id).push(pl);
      }
    }
    for (const [pid, pls] of occSet) {
      const parcel = state.map.parcels.find((p) => p.id === pid);
      const ring = parcel && parcel.current && parcel.current.ring;
      if (!ring) continue;
      const selected = pls.some((p) => p.id === planState.selectedId);
      drawPoly(ring, selected ? "#e08cff" : "rgba(200,120,230,.55)",
               selected ? "rgba(190,110,255,.10)" : "rgba(160,90,220,.04)",
               selected ? 3 : 1.5, [8, 5]);
    }
  }

  // 争议几何
  if ($("#layer-disp").checked) {
    for (const d of state.map.disputes) {
      const active = state.selectedDispute === d.id;
      drawChain(d.base_chain, COLORS.base, active ? 3 : 2, [6, 4]);
      drawChain(d.geom_a, COLORS.a, active ? 4 : 2);
      drawChain(d.geom_b, COLORS.b, active ? 4 : 2);
      drawVertex(d.base_chain[0], COLORS.anchor, 6, "锚");
      drawVertex(d.base_chain[d.base_chain.length - 1], COLORS.anchor, 6);
    }
  }

  // 修订中折线
  if (state.revising && state.reviseChain.length > 1) {
    drawChain(state.reviseChain, "#ffef9a", 3, [2, 3]);
    state.reviseChain.forEach((p) => drawVertex(p, "#ffef9a", 4));
  }

  // 编辑中草稿
  if (state.draft.length) {
    drawPoly(state.draft, COLORS.draft, "rgba(255,208,131,.10)", 2, state.tool === "new" ? [] : [6, 4]);
    state.draft.forEach((p, i) => {
      const meta = state.draftPoints[i];
      drawVertex(p, meta && meta.photos && meta.photos.length ? "#ff9a4d" : COLORS.draft, 5,
                 String(i + 1));
    });
    const a = Math.round(polyArea(state.draft));
    $("#draft-area").textContent = state.draft.length >= 3 ? a.toLocaleString() : "—";
  } else {
    $("#draft-area").textContent = "—";
  }

  const [mx, my] = state.mouseWorld || [0, 0];
  $("#map-status").textContent =
    `坐标 ${mx.toFixed(2)}, ${my.toFixed(2)} | 工具：${{pan:"平移",add:"加点",drag:"拖点",new:"新宗地"}[state.tool]
     } | 点 ${state.draft.length} | 滚轮缩放 / 右键或中键拖拽平移`;
}
function centroid(r) {
  let x = 0, y = 0;
  r.forEach((p) => { x += p[0]; y += p[1]; });
  return [x / r.length, y / r.length];
}

// --------------------------------------------------------------- 画布交互
canvas.addEventListener("mousemove", (e) => {
  const rect = canvas.getBoundingClientRect();
  const sx = (e.clientX - rect.left) * canvas.width / rect.width;
  const sy = (e.clientY - rect.top) * canvas.height / rect.height;
  state.mouseWorld = s2w([sx, sy]);
  if (state.panning) {
    state.view.ox += sx - state.panning[0];
    state.view.oy += sy - state.panning[1];
    state.panning = [sx, sy];
  }
  if (state.dragging) {
    const [wx, wy] = state.mouseWorld;
    const g = 0.5; // 0.5m 网格吸附
    state.draft[state.dragging] = [Math.round(wx / g) * g, Math.round(wy / g) * g];
    syncPointsTable();
  }
  render();
});
canvas.addEventListener("mousedown", (e) => {
  const rect = canvas.getBoundingClientRect();
  const sx = (e.clientX - rect.left) * canvas.width / rect.width;
  const sy = (e.clientY - rect.top) * canvas.height / rect.height;
  if (e.button === 2 || e.button === 1 || state.tool === "pan") {
    state.panning = [sx, sy]; e.preventDefault(); return;
  }
  const [wx, wy] = s2w([sx, sy]);
  if (state.tool === "drag") {
    let best = -1, bd = 6 / state.view.scale;
    state.draft.forEach((p, i) => {
      const d = dist2(p, [wx, wy]);
      if (d < bd) { bd = d; best = i; }
    });
    state.dragging = best >= 0 ? best : null;
    return;
  }
  if (state.tool === "add" || state.tool === "new") {
    if (state.revising) { addRevisePoint([wx, wy]); return; }
    const g = 0.5;
    const p = [Math.round(wx / g) * g, Math.round(wy / g) * g];
    // 回到首点 0.3m 内自动闭合
    if (state.tool === "add" && state.draft.length >= 3 &&
        dist2(p, state.draft[0]) <= 0.3) {
      toast("已闭合（回到首点）", "ok");
    } else {
      state.draft.push(p);
      state.draftPoints[state.draft.length - 1] = { accuracy: null, marker: "钢钉", photos: [], confirmedBy: [] };
      syncPointsTable();
    }
  }
});
window.addEventListener("mouseup", () => { state.dragging = null; state.panning = null; });
canvas.addEventListener("contextmenu", (e) => e.preventDefault());
canvas.addEventListener("wheel", (e) => {
  e.preventDefault();
  const rect = canvas.getBoundingClientRect();
  const sx = (e.clientX - rect.left) * canvas.width / rect.width;
  const sy = (e.clientY - rect.top) * canvas.height / rect.height;
  const before = s2w([sx, sy]);
  const f = e.deltaY < 0 ? 1.12 : 0.89;
  state.view.scale = Math.max(0.4, Math.min(40, state.view.scale * f));
  const after = s2w([sx, sy]);
  state.view.ox += (after[0] - before[0]) * state.view.scale;
  state.view.oy -= (after[1] - before[1]) * state.view.scale;
  render();
}, { passive: false });

$$(".toolbar button[data-tool]").forEach((b) => b.addEventListener("click", () => {
  state.tool = b.dataset.tool;
  $$(".toolbar button[data-tool]").forEach((x) => x.classList.toggle("active", x === b));
  if (state.tool === "new") { state.draft = []; state.draftPoints = {}; syncPointsTable(); }
}));
$("#btn-undo").onclick = () => {
  const i = state.draft.pop();
  if (i != null) delete state.draftPoints[state.draft.length];
  syncPointsTable(); render();
};
$("#btn-clear").onclick = () => {
  state.draft = []; state.draftPoints = {}; state.reviseChain = [];
  syncPointsTable(); render();
};
$("#btn-snap").onclick = () => {
  if (state.draft.length >= 3) toast(`环已按约定闭合，共 ${state.draft.length} 个界址点`, "ok");
};

// --------------------------------------------------------------- 采集点表
function syncPointsTable() {
  const tb = $("#points-table tbody");
  tb.innerHTML = "";
  state.draft.forEach((p, i) => {
    const m = state.draftPoints[i] || (state.draftPoints[i] = {});
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${i + 1}</td>
      <td>${p[0].toFixed(2)}</td><td>${p[1].toFixed(2)}</td>
      <td><input type="number" step="0.01" value="${m.accuracy ?? ""}" data-k="accuracy"></td>
      <td><select data-k="marker">
        <option${m.marker === "钢钉" ? " selected" : ""}>钢钉</option>
        <option${m.marker === "石桩" ? " selected" : ""}>石桩</option>
        <option${m.marker === "刻字" ? " selected" : ""}>刻字</option>
        <option${m.marker === "瓷标志" ? " selected" : ""}>瓷标志</option></select></td>
      <td><input type="file" accept="image/*" capture="environment" multiple>
          <small>${(m.photos || []).length} 张</small></td>
      <td><small>${(m.confirmedBy || []).join("、") || "—"}</small></td>
      <td><button data-act="del">×</button></td>`;
    tr.querySelectorAll("[data-k]").forEach((el) => el.addEventListener("change", () => {
      m[el.dataset.k] = el.value === "" ? null : parseFloat(el.value) || el.value;
    }));
    const file = tr.querySelector('input[type=file]');
    file.addEventListener("change", async () => {
      m.photos = m.photos || [];
      const jid = $("#submit-job").value.trim();
      if (!jid) { toast("请先下载离线包取得作业单号，再传照片", "err"); file.value = ""; return; }
      for (const f of file.files) {
        const fd = new FormData();
        fd.append("file", f);
        fd.append("point_ref", `P${i + 1}`);
        const r = await fetch(`/api/sync/jobs/${jid}/media`, { method: "POST", body: fd });
        if (r.ok) { const d = await r.json(); m.photos.push(d.media_id); toast(`照片已传 ${d.media_id}`, "ok"); }
        else toast("照片上传失败", "err");
      }
      file.value = ""; syncPointsTable(); render();
    });
    tr.querySelector('[data-act=del]').onclick = () => {
      state.draft.splice(i, 1); delete state.draftPoints[i]; syncPointsTable(); render();
    };
    tb.appendChild(tr);
  });
}

// --------------------------------------------------------------- 数据加载
async function loadMap() {
  state.map = await api("/api/map");
  // 预取所有版本环用于历史图层与血缘
  state.meta.ringCache = state.meta.ringCache || {};
  for (const p of state.map.parcels) {
    const vs = await api(`/api/parcels/${p.id}/versions`);
    p.versions = vs;
    vs.forEach((v) => { state.meta.ringCache[v.id] = v.ring; });
  }
  const allPts = state.map.parcels.flatMap((p) =>
    (state.meta.ringCache[p.current?.id] || []).map(([x, y]) => [x, y]));
  if (!state.meta.fitted) { fitView(allPts); state.meta.fitted = true; }
  $("#disp-badge").textContent = state.map.disputes.length;
  $("#disp-badge").classList.toggle("hidden", !state.map.disputes.length);
  state.plans = state.map.effect_plans || [];
  const activePlanCount = state.plans.length;
  $("#plan-badge").textContent = activePlanCount;
  $("#plan-badge").classList.toggle("hidden", !activePlanCount);
  fillParcelSelects();
  renderDisputeList();
  renderCertList();
  renderOps();
  if (planState.loaded) {
    renderPlanList();
    renderTimeline();
    // 后台执行器可能刚把等待计划落账/暂停：同步刷新选中详情
    if (planState.selectedId && document.getElementById("tab-plans").classList.contains("active"))
      selectPlan(planState.selectedId).catch(() => {});
  }
  render();
}
function fillParcelSelects() {
  const opts = state.map.parcels.map((p) =>
    `<option value="${p.id}">${p.label || p.id}</option>`).join("");
  $("#bundle-parcels").innerHTML = opts;
  $("#target-parcel").innerHTML = `<option value="">（新宗地）</option>` + opts;
  $("#confirm-neighbor").innerHTML = opts;
  $("#lineage-parcel").innerHTML = opts;
  $("#snap-parcels").innerHTML = opts;
  const verOpts = state.map.parcels.flatMap((p) => p.versions.map((v) =>
    `<option value="${v.id}">${p.label || p.id} v${v.version_no} · ${v.status}</option>`)).join("");
  $("#cert-version").innerHTML = verOpts;
  $("#correct-version").innerHTML = verOpts;
  $("#split-parent").innerHTML = verOpts;
  $("#merge-parents").innerHTML = verOpts;
}

// --------------------------------------------------------------- Tab 切换
$$("nav button[data-tab]").forEach((b) => b.addEventListener("click", () => {
  $$("nav button[data-tab]").forEach((x) => x.classList.toggle("active", x === b));
  $$(".tab").forEach((t) => t.classList.toggle("active", t.id === "tab-" + b.dataset.tab));
  loadMap();
  if (b.dataset.tab === "drafts") loadDrafts(draftState.selectedId);
  if (b.dataset.tab === "plans") loadPlans(planState.selectedId);
  if (b.dataset.tab === "snapshots") loadSnapSessions(
    snapState.session && snapState.session.package_id);
}));

// --------------------------------------------------------------- 离线同步
$("#btn-bundle").onclick = async () => {
  const parcel_ids = $$("#bundle-parcels option:checked").map((o) => o.value);
  const d = await api("/api/sync/bundle", {
    method: "POST",
    body: { parcel_ids, surveyor: $("#bundle-surveyor").value || "外业组" },
  });
  $("#submit-job").value = d.job_id;
  $("#bundle-out").textContent =
    `作业单 ${d.job_id}\n基线版本：${fmt(d.bundle.basis)}\n容差：${fmt(d.bundle.tolerance)}\n邻宗 ${d.bundle.neighbors.length} 宗`;
  // 将底图首宗环载入画布，便于离线增删点
  if (d.bundle.parcels[0]) {
    state.draft = d.bundle.parcels[0].ring.map((p) => p.map((v) => +v.toFixed(2)));
    state.draft.forEach((_, i) => state.draftPoints[i] = { accuracy: null, marker: "钢钉", photos: [], confirmedBy: [] });
    state.targetParcel = d.bundle.parcels[0].parcel_id;
    $("#target-parcel").value = state.targetParcel;
    fitView(state.draft); syncPointsTable(); render();
  }
  toast("离线包已下载，可断网采集", "ok");
};
$("#target-parcel").onchange = (e) => { state.targetParcel = e.target.value; };
$("#btn-add-confirmation").onclick = () => {
  const pid = $("#confirm-neighbor").value;
  const name = $("#confirm-owner").value.trim();
  if (!pid || !name) return toast("选择相邻宗地并填写权利人", "err");
  state.confirms.push({ parcel_id: pid, owner_name: name, confirmed: true });
  $("#confirm-owner").value = "";
  $("#confirm-list").innerHTML = state.confirms.map((c) =>
    `<li>邻宗 <b>${c.parcel_id.slice(0, 8)}</b> 权利人 ${c.owner_name} ✓ 已确认</li>`).join("");
};

function buildPoints() {
  return state.draft.map((p, i) => {
    const m = state.draftPoints[i] || {};
    return {
      local_id: `DEV-P${i + 1}`, x: p[0], y: p[1], kind: "corner",
      accuracy_m: m.accuracy, marker_type: m.marker || "钢钉",
      photo_ids: m.photos || [], confirmed_by: m.confirmedBy || [],
    };
  });
}
$("#btn-validate").onclick = async () => {
  const body = {
    job_id: $("#submit-job").value || null,
    device_id: "web-device", surveyor: $("#bundle-surveyor").value || "外业组",
    candidates: [{
      parcel_id: state.targetParcel || null,
      label: state.targetParcel ? "" : "新宗地",
      ring: state.draft, points: buildPoints(),
      declared_area: parseFloat($("#declared-area").value) || null,
    }],
    confirmations: state.confirms,
  };
  const d = await api("/api/sync/validate", { method: "POST", body });
  $("#submit-out").textContent = d.valid
    ? `✓ 预检通过，面积 ${d.normalized[0].area.toFixed(2)} m²`
    : fmt(d.errors);
  if (!d.valid) toast("预检发现问题", "err");
};
$("#btn-submit").onclick = async () => {
  if (state.draft.length < 3) return toast("至少采集 3 个界址点", "err");
  const body = {
    job_id: $("#submit-job").value || null,
    idem_key: $("#idem-key").value || null,
    device_id: "web-device", surveyor: $("#bundle-surveyor").value || "外业组",
    candidates: [{
      parcel_id: state.targetParcel || null,
      ring: state.draft, points: buildPoints(),
      declared_area: parseFloat($("#declared-area").value) || null,
    }],
    confirmations: state.confirms,
  };
  try {
    const d = await api("/api/sync/submit", { method: "POST", body });
    $("#submit-out").textContent = fmt(d);
    if (d.status === "COMMITTED") { toast("✓ 候选边界已提交并落版本", "ok"); await loadMap(); }
    else if (d.status === "DISPUTED") { toast("⚠ 与另一组测量存在共享边争议，已形成争议版本", "err"); await loadMap(); }
    else toast("提交被拒绝，请查看错误", "err");
  } catch (e) { toast(e.message, "err"); }
};
$("#btn-job-query").onclick = async () => {
  const d = await api(`/api/sync/jobs/${$("#job-query").value.trim()}`);
  $("#job-out").textContent = `状态：${d.status}\n候选：${fmt(d.candidates)}`;
};

// --------------------------------------------------------------- 时间点
$("#btn-query-at").onclick = async () => {
  const v = $("#as-of").value;
  if (!v) return;
  const iso = new Date(v).toISOString();
  state.timeView = iso;
  // 逐宗取时点环
  for (const p of state.map.parcels) {
    const r = await fetch(`/api/parcels/${p.id}?at=${iso}`);
    state.meta["at_" + p.id] = r.ok ? (await r.json()).version : null;
  }
  render();
  toast(`显示 ${iso.slice(0, 16).replace("T", " ")} 的宗地状态`, "ok");
};
$("#btn-query-now").onclick = () => { state.timeView = null; render(); };

// --------------------------------------------------------------- 争议
function renderDisputeList() {
  const box = $("#dispute-list");
  const open = state.map.disputes;
  box.innerHTML = open.length ? "" : `<p class="hint">当前无未决争议。</p>`;
  open.forEach((d) => {
    const card = document.createElement("div");
    card.className = "disp-card" + (state.selectedDispute === d.id ? " active" : "");
    card.innerHTML = `<h4>争议 ${d.id.slice(5, 11)}</h4>
      <small>${d.parcel_a.slice(0, 10)} ⇄ ${d.parcel_b.slice(0, 10)}</small><br>
      <small>锚点 ${JSON.stringify(d.base_chain[0])} → ${JSON.stringify(d.base_chain[d.base_chain.length - 1])}</small>`;
    card.onclick = () => openDispute(d.id);
    box.appendChild(card);
  });
}
async function openDispute(id) {
  state.selectedDispute = id;
  const d = await api(`/api/disputes/${id}`);
  state.reviseChain = [];
  fitView([...d.base_chain, ...d.geom_a, ...d.geom_b]);
  const box = $("#dispute-detail");
  box.innerHTML = `
    <p>争议 <b>${d.id}</b>｜状态 ${d.status}｜${d.parcel_a} ⇄ ${d.parcel_b}</p>
    <p class="hint">A 方案（作业 ${d.job_a.slice(5, 11)}，${d.candidate_a.surveyor || ""}）
      与 B 方案（作业 ${d.job_b.slice(5, 11)}，${d.candidate_b.surveyor || ""}）不一致；
      两者都基于同一条基线测量，系统未按后提交覆盖。</p>
    <div class="row">
      <button id="adj-a" class="danger">采用 A 方案</button>
      <button id="adj-b" class="primary">采用 B 方案</button>
      <button id="adj-revise" class="secondary">修订争议片段</button>
    </div>
    <p id="revise-help" class="hint hidden">在地图上沿锚点依次点击：先点 <b>${JSON.stringify(d.base_chain[0])}</b>
      附近，末点须落在 <b>${JSON.stringify(d.base_chain[d.base_chain.length - 1])}</b>，然后：</p>
    <div class="row hidden" id="revise-actions">
      <button id="revise-undo">撤销修订点</button>
      <button id="revise-submit" class="primary">提交修订裁定</button>
      <button id="revise-cancel" class="secondary">取消</button>
    </div>`;
  $("#adj-a").onclick = () => adjudicate(d.id, { decision: "A" });
  $("#adj-b").onclick = () => adjudicate(d.id, { decision: "B" });
  $("#adj-revise").onclick = () => {
    state.revising = true; state.reviseChain = [];
    $("#revise-help").classList.remove("hidden");
    $("#revise-actions").classList.remove("hidden");
    state.tool = "add";
    $$(".toolbar button[data-tool]").forEach((x) =>
      x.classList.toggle("active", x.id === "tool-add"));
    toast("请在地图上只修订两个锚点之间的片段", "ok");
  };
  $("#revise-undo").onclick = () => { state.reviseChain.pop(); render(); };
  $("#revise-cancel").onclick = () => { state.revising = false; state.reviseChain = [];
    $("#revise-help,#revise-actions").forEach((e) => e.classList.add("hidden")); render(); };
  $("#revise-submit").onclick = async () => {
    const start = d.base_chain[0], end = d.base_chain[d.base_chain.length - 1];
    const ch = state.reviseChain;
    if (ch.length < 2) return toast("修订链至少 2 个点", "err");
    if (dist2(ch[0], start) > 0.15 || dist2(ch[ch.length - 1], end) > 0.15)
      return toast("修订链端点必须固定在两个锚点（0.15m 内）", "err");
    ch[0] = start; ch[ch.length - 1] = end;
    await adjudicate(d.id, { decision: "REVISED", chain_a: ch });
    state.revising = false; state.reviseChain = [];
  };
  renderDisputeList();
  render();
}
function addRevisePoint(p) {
  const d = state.map.disputes.find((x) => x.id === state.selectedDispute);
  if (!d) return;
  const start = d.base_chain[0], end = d.base_chain[d.base_chain.length - 1];
  if (!state.reviseChain.length) p = start;
  // 靠近终点锚点时吸附
  if (dist2(p, end) <= 0.3) p = end;
  state.reviseChain.push(p.map((v) => +v.toFixed(3)));
  render();
}
async function adjudicate(did, item) {
  try {
    const r = await api("/api/disputes/adjudicate", {
      method: "POST",
      body: [{ dispute_id: did, decided_by: "值班仲裁员", ...item }],
    });
    toast("✓ 裁定完成（未争议边界未改动）", "ok");
    $("#cert-out").textContent = fmt(r);
    await loadMap();
    state.selectedDispute = null;
    $("#dispute-detail").innerHTML = `<p class="hint">争议已裁定。</p>`;
  } catch (e) { toast("裁定被拒绝：" + e.message, "err"); }
}

// --------------------------------------------------------------- 分割 / 合并 / 更正
$("#btn-split").onclick = async () => {
  const pv = $("#split-parent").value;
  let child2;
  try { child2 = JSON.parse($("#split-child2").value); }
  catch { return toast("子宗2 JSON 解析失败", "err"); }
  const d = await api("/api/ops/split", {
    method: "POST",
    body: { parent_version_id: pv, children: [
      { ring: state.draft }, { ring: child2 }] },
  }).catch((e) => ({ error: e.message }));
  $("#split-out").textContent = fmt(d);
  if (d.status === "COMMITTED") { toast("✓ 分割完成，面积守恒", "ok"); await loadMap(); }
};
$("#btn-merge").onclick = async () => {
  const parents = $$("#merge-parents option:checked").map((o) => o.value);
  if (parents.length < 2) return toast("至少选 2 个父版本", "err");
  const d = await api("/api/ops/merge", {
    method: "POST",
    body: { parent_version_ids: parents, result: { ring: state.draft } } },
  ).catch((e) => ({ error: e.message }));
  $("#merge-out").textContent = fmt(d);
  if (d.status === "COMMITTED") { toast("✓ 合并完成", "ok"); await loadMap(); }
};
// 历史更正升级为二阶段"更正草案"（见 #tab-drafts）。
$("#btn-correct-draft").onclick = async () => {
  if (state.draft.length < 3) return toast("更正后环至少 3 个界址点");
  const d = await api("/api/correction-drafts", {
    method: "POST",
    body: { version_id: $("#correct-version").value,
      reason: $("#correct-reason").value || "历史更正草案",
      corrected: { ring: state.draft } } },
  ).catch((e) => ({ error: e.message }));
  $("#correct-out").textContent = fmt(d.error ? d : {
    draft_id: d.draft_id, status: d.status, releasable: d.releasable,
    affected: d.preview.affected_parcels,
    nodes: d.preview.nodes.map((n) => ({
      parcel: n.parcel_id, op: n.op_type,
      old_area: n.old_area, new_area: n.new_area,
      area_delta: n.area_delta, errors: n.errors })) });
  if (d.draft_id) {
    toast(d.releasable
      ? `草案已建（${d.preview.nodes.length} 个受影响版本），请到「更正草案」批准`
      : "草案已建，但预演有错误，暂不可发布", d.releasable ? "ok" : "err");
    await loadDrafts();
    selectDraft(d.draft_id);
    document.querySelector('[data-tab="drafts"]').click();
  }
};

// =============================================================== 更正草案
let draftState = { list: [], selectedId: null, detail: null };

async function loadDrafts(selectId) {
  draftState.list = await api("/api/correction-drafts");
  const sel = $("#draft-list");
  sel.innerHTML = draftState.list.map((d) =>
    `<option value="${d.id}" ${d.id === selectId ? "selected" : ""}>` +
    `[${d.status}] ${d.id.slice(6)} 目标 ${d.target_version_id.slice(6)} ` +
    `${(d.reason || "").slice(0, 12)}</option>`).join("");
  if (!selectId && sel.value) selectId = sel.value;
  if (selectId) await selectDraft(selectId); else clearDraftPanel();
}

function clearDraftPanel() {
  draftState.detail = null;
  $("#draft-impact").innerHTML = "";
  $("#draft-drift").textContent = "";
  $("#draft-status").textContent = "";
  render();
}

async function selectDraft(id) {
  draftState.selectedId = id;
  draftState.detail = await api(`/api/correction-drafts/${id}`);
  renderDraftPanel();
}

$("#draft-list").onchange = (e) => selectDraft(e.target.value);
$("#btn-draft-refresh").onclick = () => loadDrafts(draftState.selectedId);

$("#btn-draft-rehearse").onclick = async () => {
  if (!draftState.selectedId) return;
  await api(`/api/correction-drafts/${draftState.selectedId}/rehearse`,
            { method: "POST" });
  toast("已按当前世界状态重新预演", "ok");
  await loadDrafts(draftState.selectedId);
};

$("#btn-draft-publish").onclick = async () => {
  if (!draftState.selectedId) return;
  const r = await api(`/api/correction-drafts/${draftState.selectedId}/publish`,
    { method: "POST", body: {} }).catch((e) => ({ error: e.message }));
  if (r.status === "PUBLISHED") {
    toast(`✓ 已原子发布 ${r.new_versions.length} 个新版本（旧链保留）`, "ok");
  } else if (r.status === "DRIFTED") {
    toast("✗ 基线漂移，未发布；已标出漂移节点，请重新预演", "err");
  } else if (r.error) { toast(r.error, "err"); }
  await loadDrafts(draftState.selectedId);
  await loadMap();
};

$("#btn-draft-cancel").onclick = async () => {
  if (!draftState.selectedId) return;
  const r = await api(`/api/correction-drafts/${draftState.selectedId}/cancel`,
    { method: "POST" }).catch((e) => ({ error: e.message }));
  if (r.status === "CANCELLED") toast("草案已撤销（无半成品版本）", "ok");
  else if (r.error) toast(r.error, "err");
  await loadDrafts();
};

function statusBadge(s) {
  const color = { OPEN: "#3a8", DRIFTED: "#e07b4a", PUBLISHED: "#5c8dff",
                  CANCELLED: "#888" }[s] || "#888";
  return `<span style="color:${color};font-weight:bold">${s}</span>`;
}

function renderDraftPanel() {
  const d = draftState.detail;
  if (!d) return;
  const p = d.preview || {};
  $("#draft-status").innerHTML =
    `草案 ${d.id} 状态 ${statusBadge(d.status)} · 目标 ${d.target_version_id}` +
    (d.live_drift && d.live_drift.length
      ? ` · <span style="color:#e07b4a">实时检测到 ${d.live_drift.length} 个漂移</span>` : "");

  // 漂移节点
  const drift = d.live_drift || [];
  $("#draft-drift").textContent = drift.length
    ? fmt(drift.map((x) => ({ kind: x.kind, message: x.message,
        parcel: x.parcel_id, version: x.version_id, dispute: x.dispute_id,
        cert: x.cert_id })))
    : "（无）";

  // 预演影响节点
  const nodes = p.nodes || [];
  $("#draft-impact").innerHTML = nodes.map((n) => {
    const color = n.changed ? "#ffd083" : "#aaa";
    const errs = (n.errors || []).map((e) =>
      `<div class="drift-node">⚠ ${e.code}: ${e.message}</div>`).join("");
    return `<div class="draft-node" data-vid="${n.version_id}" style="border-left-color:${color}">
      <b>${n.parcel_id}</b> · ${n.op_type} · 深度 ${n.depth} · v${n.version_no}
      <br><span class="hint">面积 ${Math.round(n.old_area)} → ${
        n.new_area == null ? "—" : Math.round(n.new_area)} m² （Δ ${
        n.area_delta == null ? "—" : Math.round(n.area_delta)}）${
        n.changed ? " · 几何变更" : " · 几何不变"}</span>
      ${n.lineage ? `<br><span class="hint">血缘：${n.lineage.op_type} 父 [${
        n.lineage.parent_versions.map((x) => x.slice(6)).join(", ")}]</span>` : ""}
      ${errs}</div>`;
  }).join("") || "<p class='hint'>无预演数据</p>";

  // 登记生效计划区：只有 releasable 的 OPEN/DRIFTED 草案可登记
  const canRegister = (p.releasable && (d.status === "OPEN" || d.status === "DRIFTED"));
  $("#btn-register-plan").disabled = !canRegister;
  $("#plan-register-out").dataset.draftId = d.id;
  if (!$("#plan-req-key").dataset.touched)
    $("#plan-req-key").value = canRegister ? `plan-${did}-${d.target_version_id.slice(-6)}` : "";
  if (!canRegister) {
    $("#plan-register-out").textContent =
      d.status === "PUBLISHED" ? "草案已发布，无需登记计划。"
      : d.status === "CANCELLED" ? "草案已撤销。"
      : "预演存在错误，需修正后才可登记生效计划。";
  }
  render();
}

// --------------------------------------------------------------- 生效计划登记
$("#btn-register-plan").onclick = async () => {
  const did = draftState.selectedId;
  if (!did) return toast("请先选择一个已预演的更正草案", "err");
  const atVal = $("#plan-exec-at").value;
  if (!atVal) return toast("请选择未来的生效时间", "err");
  const executeAt = new Date(atVal).toISOString();
  if (new Date(executeAt) <= new Date()) return toast("生效时间必须在未来", "err");
  const reqKey = $("#plan-req-key").value.trim();
  if (!reqKey) return toast("请填写 request_key（相同请求只生成一条计划）", "err");
  const out = $("#plan-register-out");
  try {
    const r = await api("/api/effect-plans", {
      method: "POST",
      body: { draft_id: did, execute_at: executeAt, request_key: reqKey } });
    if (r.status === "CONFLICT") {
      out.textContent =
        `✗ 占用冲突：${r.conflicts.length} 条计划已占用目标地块\n` +
        r.conflicts.map((c) =>
          `  · ${c.plan_id} [${c.status}] ${c.request_key} @ ${c.execute_at.slice(0, 16)}\n` +
          `    交集：${c.overlap_parcels.join(", ")}`).join("\n");
      toast("✗ 地块占用冲突，未登记", "err");
    } else {
      out.textContent =
        `✓ 计划 ${r.plan.id}\n状态 ${r.plan.status}｜生效 ${r.plan.execute_at}\n` +
        `完成令牌 ${r.plan.completion_token}\n占用地块 ${r.plan.occupancy.map((o) => o.label || o.parcel_id).join("、")}`;
      toast(r.replayed ? "相同请求已登记（返回原计划）" : "✓ 生效计划已登记并建立占用", "ok");
      await loadMap();
      await loadPlans(r.plan.id);
    }
  } catch (e) { out.textContent = "✗ " + e.message; toast(e.message, "err"); }
};
$("#btn-goto-plans").onclick = () => document.querySelector('[data-tab="plans"]').click();
$("#plan-req-key").addEventListener("input", (e) => { e.target.dataset.touched = "1"; });

// --------------------------------------------------------------- 证明
$("#btn-issue-cert").onclick = async () => {
  const d = await api("/api/certificates", {
    method: "POST", body: { version_id: $("#cert-version").value } });
  $("#cert-out").textContent = fmt(d);
  toast("证明已签发：" + d.cert_id, "ok"); loadMap();
};
$("#btn-verify-cert").onclick = async () => {
  const d = await api(`/api/certificates/${$("#verify-cert-id").value.trim()}/verify`);
  $("#cert-out").textContent = fmt(d);
  toast(d.valid ? "✓ 证明真实有效" : "✗ 证明校验失败", d.valid ? "ok" : "err");
};
function renderCertList() {
  $("#cert-list").innerHTML = state.map.certificates.map((c) =>
    `<div class="cert-item" data-id="${c.id}"><b>${c.id}</b><br>
     ${c.parcel_id.slice(0, 10)} · ${Math.round(c.area)}m² · ${c.issued_at.slice(0, 10)}
     ${c.revoked ? "·已吊销" : ""}</div>`).join("");
  $$("#cert-list .cert-item").forEach((el) => el.onclick = async () => {
    const d = await api(`/api/certificates/${el.dataset.id}`);
    $("#cert-out").textContent = fmt(d);
  });
}

// --------------------------------------------------------------- 血缘图
async function renderOps() {
  const ops = await api("/api/ops");
  $("#ops-list").innerHTML = ops.map((o) =>
    `<div class="op-item ${o.type}"><b>${o.type}</b> ${o.id.slice(3, 9)}<br>
     父 [${o.parent_versions.map((v) => v.slice(3, 9)).join(", ")}] →
     子 [${o.child_versions.map((v) => v.slice(3, 9)).join(", ")}]<br>
     <small>${o.created_at.slice(0, 19).replace("T", " ")}</small></div>`).join("");
  drawLineage(ops);
}
function drawLineage(ops) {
  const c = $("#lineage-canvas"), g = c.getContext("2d");
  g.clearRect(0, 0, c.width, c.height);
  const pid = $("#lineage-parcel").value;
  const parcel = state.map.parcels.find((p) => p.id === pid);
  if (!parcel) return;
  const vs = parcel.versions;
  const x0 = 70, gapX = 190, y = 160;
  vs.forEach((v, i) => {
    const x = x0 + i * gapX;
    const color = { COMMITTED: "#5c8dff", ADJUDICATED: "#d85b9e",
      SUPERSEDED: "#55647e", ANNULLED: "#e07b4a", PROPOSED: "#e0b34a" }[v.status] || "#888";
    g.fillStyle = "#131c2c"; g.strokeStyle = color; g.lineWidth = 2;
    g.beginPath(); g.roundRect(x - 8, y - 34, 150, 68, 8); g.fill(); g.stroke();
    g.fillStyle = color; g.font = "bold 12px sans-serif";
    g.fillText(`v${v.version_no} ${v.status}`, x, y - 12);
    g.fillStyle = "#cdd9f2"; g.font = "10px monospace";
    g.fillText(v.id.slice(0, 13), x, y + 4);
    g.fillText(`${Math.round(v.area)} m²`, x, y + 18);
    g.fillStyle = "#7389b0";
    g.fillText(v.valid_from.slice(0, 10), x, y + 30)
    if (i > 0) {
      g.strokeStyle = "#3a4c6e"; g.beginPath();
      g.moveTo(x - 48, y); g.lineTo(x - 10, y); g.stroke();
      g.fillStyle = "#3a4c6e"; g.fillText("▲", x - 26, y - 4);
    }
  });
  // 操作血缘注解
  let yy = 300;
  g.fillStyle = "#9fc1ff"; g.font = "bold 12px sans-serif";
  g.fillText("跨宗地操作血缘（SPLIT / MERGE / CORRECTION / ADJUDICATION）", x0, yy - 12);
  ops.filter((o) => o.type !== "SURVEY").forEach((o) => {
    g.fillStyle = "#b8c7e2"; g.font = "11px monospace";
    g.fillText(`${o.type}: ${o.parent_versions.map((v) => v.slice(3, 9)).join("+") || "∅"} → ${o.child_versions.map((v) => v.slice(3, 9)).join(",")}`, x0, yy);
    yy += 20;
  });
}
$("#lineage-parcel").onchange = () => renderOps();

// 图层开关即时重绘
$$('fieldset input[type=checkbox][id^="layer-"]').forEach((el) =>
  el.addEventListener("change", () => render()));

// 计划生效时间默认 +2 小时；请求键留空时用草案 id 兜底建议
(function initPlanInputs() {
  const d = new Date(Date.now() + 2 * 3600 * 1000), p = (n) => String(n).padStart(2, "0");
  $("#plan-exec-at").value =
    `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}T${p(d.getHours())}:${p(d.getMinutes())}`;
})();

// =============================================================== 生效计划
let planState = { list: [], selectedId: null, detail: null, filter: "ALL", loaded: false };
const PLAN_STATUS_TEXT = { WAITING: "等待", PAUSED: "暂停", COMPLETED: "完成", CANCELLED: "取消" };

async function loadPlans(selectId) {
  planState.loaded = true;
  planState.list = await api("/api/effect-plans");
  if (selectId) planState.selectedId = selectId;
  renderPlanList();
  renderTimeline();
  if (planState.selectedId) {
    const exists = planState.list.find((p) => p.id === planState.selectedId);
    if (exists) await selectPlan(planState.selectedId);
    else { planState.selectedId = null; clearPlanDetail(); }
  }
}

function renderPlanList() {
  const box = $("#plan-list");
  const f = planState.filter;
  const items = planState.list.filter((p) => f === "ALL" || p.status === f)
    .sort((a, b) => a.execute_at.localeCompare(b.execute_at));
  if (!items.length) {
    box.innerHTML = `<p class="hint">${f === "ALL" ? "暂无生效计划。" : `没有「${PLAN_STATUS_TEXT[f]}」状态的计划。`}</p>`;
    return;
  }
  box.innerHTML = items.map((p) => {
    const labels = (p.occupancy || []).map((o) => o.label || o.parcel_id.slice(-6)).join("、");
    return `<div class="plan-card ${p.status} ${p.id === planState.selectedId ? "active" : ""}" data-id="${p.id}">
      <h4><span>${p.id.slice(5)}</span><span class="pill ${p.status}">${PLAN_STATUS_TEXT[p.status]}</span></h4>
      <small>生效 ${p.execute_at.slice(0, 19).replace("T", " ")}</small><br>
      <small>占用 ${(p.occupancy || []).length} 块：${labels}</small>
      ${p.pause_reason ? `<br><small style="color:#f0bd63">⚠ ${p.pause_reason}</small>` : ""}
    </div>`;
  }).join("");
  box.querySelectorAll(".plan-card").forEach((el) =>
    el.onclick = () => selectPlan(el.dataset.id));
}

function renderTimeline() {
  const box = $("#plan-timeline");
  const items = planState.list.slice().sort((a, b) => a.execute_at.localeCompare(b.execute_at));
  if (!items.length) { box.innerHTML = `<div class="tl-empty">暂无计划。</div>`; return; }
  const times = items.map((p) => new Date(p.execute_at).getTime());
  const now = Date.now();
  let t0 = Math.min(...times, now), t1 = Math.max(...times, now);
  if (t1 - t0 < 60000) { t0 -= 60000; t1 += 60000; }
  const span = t1 - t0;
  const pos = (iso) => ((new Date(iso).getTime() - t0) / span) * 100;
  const nowPos = ((now - t0) / span) * 100;
  const icon = { WAITING: "⏳", PAUSED: "⏸", COMPLETED: "✓", CANCELLED: "✕" };
  box.innerHTML = `
    <div class="tl-track">
      <div class="tl-now" style="left:${nowPos}%"><span>现在</span></div>
      ${items.map((p) => `
        <div class="tl-node ${p.status} ${p.id === planState.selectedId ? "selected" : ""}"
             data-id="${p.id}" style="left:${pos(p.execute_at)}%">
          <div class="tl-dot">${icon[p.status] || "•"}</div>
          <div class="tl-label">${p.execute_at.slice(5, 16).replace("T", " ")}<br>${p.id.slice(5)}</div>
        </div>`).join("")}
    </div>`;
  box.querySelectorAll(".tl-node").forEach((el) =>
    el.onclick = () => selectPlan(el.dataset.id));
}

async function selectPlan(id) {
  planState.selectedId = id;
  planState.detail = await api(`/api/effect-plans/${id}`);
  renderPlanList();
  renderTimeline();
  renderPlanDetail();
  render();
}

function clearPlanDetail() {
  $("#plan-detail").innerHTML =
    `<p class="hint">从左侧选择一条计划，或在「更正草案」页登记新的生效计划。</p>`;
  render();
}

function renderPlanDetail() {
  const d = planState.detail;
  if (!d) return clearPlanDetail();
  const f = (v) => v ? v.replace("T", " ").slice(0, 19) : "—";
  const occ = (d.occupancy || []).map((o) =>
    `<span class="occ-chip">${o.label || o.parcel_id} <small>${o.parcel_id.slice(-6)}</small></span>`).join("");
  const drift = (d.live_drift || []);
  let pauseHtml = "";
  if (d.status === "PAUSED") {
    const nodes = (d.pause_detail && d.pause_detail.drift_nodes) || [];
    const errs = (d.pause_detail && d.pause_detail.live_errors) || [];
    pauseHtml = `
      <div class="conflict-box">
        <b>计划已暂停：${d.pause_reason || "基线变化"}</b>（${f(d.paused_at)}）<br>
        ${nodes.slice(0, 8).map((x) => `<div class="drift-line">• ${x.kind}：${x.message}</div>`).join("")}
        ${errs.length ? errs.slice(0, 5).map((e) =>
          `<div class="drift-line">• ${(e.version_id ? e.parcel_id + " " : "")}${JSON.stringify(e.errors || e).slice(0, 120)}</div>`).join("") : ""}
        <div class="hint">宗地数据库保持原样、占用未释放。请刷新基线后「恢复」或改期/取消。</div>
      </div>`;
  }
  if (drift.length && d.status === "WAITING") {
    pauseHtml = `<div class="conflict-box"><b>实时检测到 ${drift.length} 个基线漂移</b>，
      将在执行时自动暂停：<br>${drift.slice(0, 5).map((x) =>
        `<div class="drift-line">• ${x.kind}：${x.message}</div>`).join("")}</div>`;
  }
  const actions = [];
  if (d.status === "WAITING" || d.status === "PAUSED") {
    actions.push(
      `<label style="max-width:240px">改期到 <input type="datetime-local" id="plan-rs-at" step="1" value="${toLocalInput(d.execute_at)}"></label>`,
      `<button id="btn-plan-rs" class="secondary">改期</button>`,
    );
    if (d.status === "PAUSED")
      actions.push(`<button id="btn-plan-resume" class="primary">恢复基线</button>`);
    actions.push(`<button id="btn-plan-cancel" class="danger">取消并释放占用</button>`);
  }
  $("#plan-detail").innerHTML = `
    <div class="row" style="justify-content:space-between">
      <div><b>${d.id}</b> <span class="pill ${d.status}">${PLAN_STATUS_TEXT[d.status]}</span></div>
      <small class="hint">request_key: <b>${d.request_key}</b></small>
    </div>
    <div class="kv">
      草案：<b>${d.draft_id}</b>（草案状态 ${d.draft.status}）<br>
      登记于 <b>${f(d.registered_at)}</b> ｜ 计划生效 <b>${f(d.execute_at)}</b><br>
      完成于 <b>${f(d.completed_at)}</b> ｜ 取消于 <b>${f(d.cancelled_at)}</b><br>
      完成令牌 <b>${d.completion_token || "—"}</b> ｜ 尝试次数 ${d.attempts}
      ${d.lease_owner ? ` ｜ 租约 ${d.lease_owner}@${f(d.lease_at)}` : ""}
    </div>
    ${pauseHtml}
    <h4 style="color:#d7b8ff;margin:10px 0 2px">互斥占用对象（${(d.occupancy || []).length}）</h4>
    <div class="occ-grid">${occ || '<span class="hint">（已释放）</span>'}</div>
    ${d.result ? `<h4>落账结果</h4><pre class="code">${fmt({
      op_id: d.result.op_id, new_versions: d.result.new_versions,
      chains_forked: d.result.chains_forked, external: d.result.external })}</pre>` : ""}
    <div class="row">${actions.join("")}</div>`;

  $("#btn-plan-rs") && ($("#btn-plan-rs").onclick = async () => {
    const v = $("#plan-rs-at").value;
    if (!v) return toast("请选择新的生效时间", "err");
    try {
      const r = await api(`/api/effect-plans/${d.id}/reschedule`,
        { method: "POST", body: { execute_at: new Date(v).toISOString() } });
      toast(`已改期，计划状态：${PLAN_STATUS_TEXT[r.status]}`, "ok");
      await loadPlans(d.id); await loadMap();
    } catch (e) { toast(e.message, "err"); }
  });
  $("#btn-plan-resume") && ($("#btn-plan-resume").onclick = async () => {
    try {
      const r = await api(`/api/effect-plans/${d.id}/resume`, { method: "POST" });
      if (r.status === "WAITING") toast("✓ 基线已刷新，计划恢复等待", "ok");
      else toast(`仍无法恢复：${r.reason || "基线/占用问题"}`, "err");
      await loadPlans(d.id); await loadMap();
    } catch (e) { toast(e.message, "err"); }
  });
  $("#btn-plan-cancel") && ($("#btn-plan-cancel").onclick = async () => {
    if (!confirm("取消该计划并释放全部地块占用？")) return;
    try {
      const r = await api(`/api/effect-plans/${d.id}/cancel`, { method: "POST" });
      toast(`计划已${PLAN_STATUS_TEXT[r.status]}，占用已释放，request_key 可重新登记`, "ok");
      await loadPlans(d.id); await loadMap();
    } catch (e) { toast(e.message, "err"); }
  });
}

function toLocalInput(iso) {
  // ISO(...Z) → datetime-local 所需的本地 YYYY-MM-DDTHH:mm:ss
  const dt = new Date(iso), p = (n) => String(n).padStart(2, "0");
  return `${dt.getFullYear()}-${p(dt.getMonth() + 1)}-${p(dt.getDate())}T` +
         `${p(dt.getHours())}:${p(dt.getMinutes())}:${p(dt.getSeconds())}`;
}

// =============================================================== 地籍快照交换包
const snapState = { pkg: null, manifest: null, session: null, sessions: [], events: [],
  // 管理动作进行中（防连续点击/网络重试重复发新操作标识）；各动作"待决操作标识"
  // 在首次判定返回前被网络重试复用；终局拒绝后必须显式换新标识
  busy: false, pendingKey: {}, terminalReject: null };

const SNAP_STATUS_TEXT = {
  UPLOADING: "上传中", READY: "待导入", CONFLICT: "冲突",
  FROZEN: "已冻结", IMPORTED: "已导入" };
const SNAP_FREEZE_TEXT = {
  EXPIRED: "到期冻结", MANUAL: "人工冻结", REOPEN_MISMATCH: "重开重验失败" };

function fmtRemaining(sec) {
  if (sec === null || sec === undefined) return "不限期";
  if (sec <= 0) return "已过期";
  const d = Math.floor(sec / 86400), h = Math.floor((sec % 86400) / 3600),
        m = Math.floor((sec % 3600) / 60);
  return (d ? `${d}天` : "") + (h ? `${h}小时` : "") +
         (!d && m ? `${m}分` : "") || `${sec}秒`;
}

function snapActor() { return ($("#snap-actor").value || "").trim(); }
function snapReqKey(prefix) {
  return `${prefix}-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;
}

(async function initSnapAt() {
  const d = new Date(), p = (n) => String(n).padStart(2, "0");
  $("#snap-at").value =
    `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}T${p(d.getHours())}:${p(d.getMinutes())}`;
})();

async function loadSnapSessions(selectId) {
  snapState.sessions = await api("/api/snapshots/imports");
  const box = $("#snap-session-list");
  if (!snapState.sessions.length) {
    box.innerHTML = `<p class="hint">暂无导入会话。</p>`;
    return;
  }
  box.innerHTML = snapState.sessions.map((s) => {
    const frozen = s.frozen || s.status === "FROZEN";
    const late = !frozen && s.remaining_seconds !== null &&
                 s.remaining_seconds !== undefined && s.remaining_seconds <= 0;
    const cls = frozen ? "FROZEN" : late ? "LATE" : s.status;
    const ttl = s.valid_until
      ? `剩余 <b class="${late || frozen ? "ttl-late" : "ttl-ok"}">${
          fmtRemaining(s.remaining_seconds)}</b>（至 ${String(s.valid_until).slice(0, 16).replace("T", " ")}）`
      : "窗口不限期";
    return `
    <div class="snap-session ${cls} ${s.package_id === selectId ? "active" : ""}"
         data-id="${s.package_id}">
      <b>${s.package_id}</b>
      <span class="pill ${s.status}">${SNAP_STATUS_TEXT[s.status] || s.status}</span>
      <br><small>${s.chunk_count} 块 · ${(s.created_at || "").slice(0, 19).replace("T", " ")} · v${s.version}</small>
      <div class="snap-meta">
        负责人：<b>${s.owner ? escapeHtml(s.owner) : "（未指定）"}</b><br>
        ${ttl}
        ${frozen ? `<br><span class="freeze-why">⛔ ${SNAP_FREEZE_TEXT[s.frozen_reason] || s.frozen_reason || "冻结"}
          ${s.frozen_at ? "· " + String(s.frozen_at).slice(0, 16).replace("T", " ") : ""}</span>` : ""}
        ${s.imported ? `<br><span class="imported-ok">✓ 已导入（受保护，不可重开/清理）</span>` : ""}
      </div>
    </div>`;
  }).join("");
  box.querySelectorAll(".snap-session").forEach((el) =>
    el.onclick = () => selectSnapSession(el.dataset.id));
}

function escapeHtml(x) {
  return String(x ?? "").replace(/[&<>"]/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
}

$("#btn-snap-refresh").onclick = () =>
  loadSnapSessions(snapState.session && snapState.session.package_id);

$("#btn-snap-cleanup").onclick = async () => {
  try {
    const d = await api("/api/snapshots/imports-cleanup",
                        { method: "POST", body: {} });
    toast(`保留期清理：移除 ${d.removed_count} 个过期冻结会话（已导入保留 ${d.protected_imported}）`,
          d.removed_count ? "ok" : "");
    await loadSnapSessions();
    $("#snap-import-out").textContent = fmt(d);
  } catch (e) { toast(e.message, "err"); }
};

// ---------------- 导出
$("#btn-snap-export").onclick = async () => {
  const parcel_ids = $$("#snap-parcels option:checked").map((o) => o.value);
  if (!parcel_ids.length) return toast("至少选择一宗地", "err");
  const at = $("#snap-at").value;
  if (!at) return toast("选择来源时间点", "err");
  try {
    const d = await api("/api/snapshots/export", { method: "POST", body: {
      parcel_ids, at: new Date(at).toISOString(),
      chunk_size: parseInt($("#snap-chunk-size").value, 10) || 16384 } });
    snapState.pkg = d;
    snapState.manifest = d.manifest;
    $("#btn-snap-download").disabled = false;
    $("#snap-export-out").textContent =
      `包标识 ${d.package_id}\n来源时间点 ${d.source_at}\n载荷 SHA-256 ${d.payload_sha256}\n` +
      `分块 ${d.chunk_count} × ${d.chunk_size} 字节\n闭包：${fmt(d.counts)}\n签章 ${d.signature.slice(0, 24)}…`;
    toast(`✓ 已导出 ${d.chunk_count} 个分块，可离线交付`, "ok");
  } catch (e) { $("#snap-export-out").textContent = "✗ " + e.message; toast(e.message, "err"); }
};

$("#btn-snap-download").onclick = () => {
  if (!snapState.pkg) return;
  const blob = new Blob([JSON.stringify(snapState.pkg, null, 2)],
                       { type: "application/json" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = `${snapState.pkg.package_id}.pkg.json`;
  a.click();
};

// ---------------- 载入清单/整包文件
$("#snap-file").addEventListener("change", async () => {
  const f = $("#snap-file").files[0];
  if (!f) return;
  try {
    const obj = JSON.parse(await f.text());
    // 允许整包 {manifest, chunks} 或单独清单
    if (obj.manifest && obj.chunks) {
      snapState.pkg = obj; snapState.manifest = obj.manifest;
    } else {
      snapState.manifest = obj;
      snapState.pkg = { manifest: obj, chunks: [] };
    }
    $("#snap-resume-id").value = snapState.manifest.package_id || "";
    $("#snap-import-out").textContent =
      `已载入包 ${snapState.manifest.package_id}（${snapState.manifest.chunk_count} 块）`;
    toast("清单/整包已载入，可先离线预检", "ok");
  } catch (e) { toast("JSON 解析失败: " + e.message, "err"); }
  $("#snap-file").value = "";
});

// ---------------- 离线预检
$("#btn-snap-precheck").onclick = async () => {
  if (!snapState.manifest) return toast("请先选择清单/整包文件", "err");
  try {
    const d = await api("/api/snapshots/precheck", { method: "POST", body: {
      manifest: snapState.manifest,
      chunks: snapState.pkg && snapState.pkg.chunks ? snapState.pkg.chunks : [],
      local: true } });
    const lines = [
      `清单签章：${d.manifest_signature_valid ? "✓ 有效" : "✗ 无效"}`,
      d.chunks ? `分块：提供 ${d.chunks.provided}/${d.chunks.expected}` +
        (d.chunks.missing.length ? `，缺失 ${fmt(d.chunks.missing)}` : "，齐备")
        : "分块：未提供（仅清单层核验）",
      `载荷解析：${d.payload_ok ? "✓" : "✗"}`,
      `内部闭包冲突：${d.internal_conflicts.length}`,
      `本地库冲突：${d.local_conflicts ? d.local_conflicts.length : "（未比对）"}`,
    ];
    d.internal_conflicts.slice(0, 20).forEach((x) =>
      lines.push(`  ⚠ [${x.code}] ${x.entity || ""} ${x.id ?? ""} ${x.message}`));
    (d.local_conflicts || []).slice(0, 20).forEach((x) =>
      lines.push(`  ⚠ [${x.code}] ${x.entity || ""} ${x.id ?? ""} ${x.message}`));
    lines.push(`\n结论：${d.ready ? "✓ 预检通过，可上传导入" : "✗ 预检未通过"}`);
    $("#snap-import-out").textContent = lines.join("\n");
    toast(d.ready ? "✓ 预检通过" : "✗ 预检发现冲突", d.ready ? "ok" : "err");
  } catch (e) { toast(e.message, "err"); }
};

// ---------------- 建会话
$("#btn-snap-create").onclick = async () => {
  if (!snapState.manifest) return toast("请先选择清单/整包文件", "err");
  const actor = snapActor();
  const owner0 = ($("#snap-owner").value || "").trim();
  const ttl = parseFloat($("#snap-ttl").value);
  const body = {
    manifest: snapState.manifest,
    owner: owner0 || actor || null,
    ttl_minutes: Number.isFinite(ttl) && ttl > 0 ? ttl : null,
  };
  try {
    const d = await api("/api/snapshots/imports", { method: "POST", body });
    toast(d.replayed ? "会话已存在（恢复/续传）" :
         `✓ 导入会话已建立（负责人 ${d.session.owner || "不限"}，${
           d.session.valid_until ? "有效期至 " + d.session.valid_until.slice(0, 16) : "窗口不限期"}）`,
         "ok");
    await selectSnapSession(d.package_id);
    await loadSnapSessions(d.package_id);
  } catch (e) {
    if (e && e.detail) $("#snap-import-out").textContent = "✗ " + fmt(e.detail);
    toast(e.message, "err");
  }
};

$("#btn-snap-resume").onclick = () => selectSnapSession($("#snap-resume-id").value.trim());

async function selectSnapSession(id) {
  if (!id) return;
  try {
    snapState.terminalReject = null;   // 切换会话：清掉上一个会话的终局拒绝提示
    snapState.pendingKey = {};
    snapState.session = await api(`/api/snapshots/imports/${id}`);
    snapState.events = await api(`/api/snapshots/imports/${id}/events`);
    $("#snap-resume-id").value = id;
    renderSnapDetail();
    await loadSnapSessions(id);
  } catch (e) { toast(e.message, "err"); }
}

// ---------------- 分块上传
$("#btn-snap-upload-one").onclick = async () => {
  if (!snapState.session) return toast("请先建立或载入会话", "err");
  const f = $("#snap-chunk-file").files[0];
  const seq = parseInt($("#snap-chunk-seq").value, 10);
  if (!f) return toast("选择分块文件", "err");
  const fd = new FormData();
  fd.append("file", f);
  fd.append("actor", snapActor());
  const r = await fetch(`/api/snapshots/imports/${snapState.session.package_id}/chunks/${seq}`,
                        { method: "PUT", body: fd });
  const d = await r.json();
  if (!r.ok) return snapReportError(r, d);
  if (d.conflict) toast("✗ 同序号内容不匹配（已保留正确块）", "err");
  else toast(d.duplicate ? "重复分块，幂等忽略" : `✓ 分块 ${seq} 已接收`, "ok");
  await selectSnapSession(snapState.session.package_id);
};

$("#btn-snap-upload-all").onclick = async () => {
  if (!snapState.session || !snapState.pkg || !snapState.pkg.chunks ||
      !snapState.pkg.chunks.length)
    return toast("需要先载入整包（含分块）并建立会话", "err");
  const pid = snapState.session.package_id;
  // 逆序 + 中间插入重复，模拟乱序/重复上传
  const n = snapState.pkg.chunks.length;
  const order = [...Array(n).keys()].reverse();
  for (let k = 0; k < order.length; k++) {
    const seq = order[k];
    const fd = new FormData();
    fd.append("data", snapState.pkg.chunks[seq]);
    fd.append("actor", snapActor());
    const r = await fetch(`/api/snapshots/imports/${pid}/chunks/${seq}`,
                          { method: "PUT", body: fd });
    const d = await r.json();
    if (!r.ok) { snapReportError(r, d); return; }
    if (d.conflict) return toast(`分块 ${seq} 失败`, "err");
    if (k === 0) { // 重复传一次
      const fd2 = new FormData();
      fd2.append("data", snapState.pkg.chunks[seq]);
      fd2.append("actor", snapActor());
      await fetch(`/api/snapshots/imports/${pid}/chunks/${seq}`,
                  { method: "PUT", body: fd2 });
    }
    await selectSnapSession(pid);
    await new Promise((res) => setTimeout(res, 15));
  }
  toast("✓ 全部分块已按乱序上传（含一次重复）", "ok");
};

function snapErrorDetail(r, d) {
  const det = d && d.detail;
  if (det && typeof det === "object" && det.code) return det;
  return null;
}

// 终局拒绝重放（原操作标识首次判定被拒，重放只回放这次拒绝）的界面反馈
function snapReopenTerminalHint(det) {
  const mm = (det.conflicts || []).slice(0, 20).map((c) =>
    `[${c.code}] ${c.entity || ""} ${c.id ?? ""}: ${c.message}`).join("\n");
  return "⛔ 该操作标识（request_key）的首次重开校验已被拒绝——判定为终局结果。\n" +
         "即使后台分块/文件已修复，原操作标识也不会再重新校验或产生状态变更。\n" +
         "请在确认文件已修复后，用【新操作标识重验】（自动携带最新会话版本号）。\n" +
         (mm ? `\n首次拒绝的失配明细：\n${mm}` : "");
}

function snapReportError(r, d) {
  const det = snapErrorDetail(r, d);
  if (det) {
    const why = det.reason ? `（${SNAP_FREEZE_TEXT[det.reason] || det.reason}）` : "";
    // 终局拒绝重放：醒目标识，提示必须换新操作标识 + 最新版本号
    if (det.replayed) {
      toast("⛔ 原操作标识的首次判定被拒：这是终局结果重放，请用「新操作标识重验」", "err");
      $("#snap-import-out").textContent = snapReopenTerminalHint(det) +
        `\n\n完整响应：\n${fmt(det)}`;
      snapState.terminalReject = det;
    } else {
      // 首次拒绝：记下本次操作标识，连续点击/网络重试只会回放这条拒绝
      if (det.code === "REOPEN_MISMATCH") snapState.terminalReject = det;
      toast(`✗ ${det.message || r.status} ${why}`, "err");
      $("#snap-import-out").textContent = fmt(det);
    }
    if (det.session) {
      snapState.session = det.session;
      renderSnapDetail();
    }
    return;
  }
  toast("操作失败：" + ((d && d.detail) || r.status), "err");
}

// ---------------- 终检导入
$("#btn-snap-finalize").onclick = async () => {
  if (!snapState.session) return toast("请先建立或载入会话", "err");
  try {
    const d = await api(`/api/snapshots/imports/${snapState.session.package_id}/finalize`,
                        { method: "POST", body: { actor: snapActor() } });
    await selectSnapSession(snapState.session.package_id);
    await loadSnapSessions(snapState.session.package_id);
    if (d.status === "IMPORTED") {
      toast(d.replayed ? "相同包：返回首次导入结果" : "✓ 一次性导入成功", "ok");
      await loadMap();
    } else if (d.status === "MISSING_CHUNKS") {
      toast(`缺块 ${d.missing_seqs.length} 个，补传后可继续`, "err");
    } else {
      toast(`✗ 终检冲突 ${(d.internal_conflicts || []).length +
        (d.local_conflicts || []).length} 项，数据库原样`, "err");
    }
  } catch (e) {
    if (e && e.detail && typeof e.detail === "object" && e.detail.code) {
      snapReportError({ status: e.httpStatus || 0 }, { detail: e.detail });
    } else toast(e.message, "err");
    await selectSnapSession(snapState.session.package_id);
  }
};

// ---------------- 接收窗口：移交 / 续期 / 冻结 / 重开
async function snapAction(path, body, okMsg, opts = {}) {
  const s = snapState.session;
  if (!s) return toast("请先载入会话", "err");
  // 连续点击防护：同一动作判定未返回前，忽略后续点击（不生成新操作标识）
  if (snapState.busy) return toast("上一操作尚未完成，已忽略重复点击", "");
  const keyTag = path.toUpperCase();
  snapState.busy = true;
  document.body.classList.add("snap-busy");
  try {
    // 待决操作标识的网络重试：request_key 与首次携带的 version 都必须原样复用
    // （同键不同版本会被服务端拒绝）；只有首次发起/显式换新标识时才拉取
    // **最新会话版本号**（过期版本会被 VERSION_CONFLICT 拦截）
    let pending = snapState.pendingKey[keyTag];
    if (!pending || opts.freshKey) {
      const cur = await api(`/api/snapshots/imports/${s.package_id}`);
      snapState.session = cur;
      if (opts.requireFrozen && !(cur.frozen || cur.status === "FROZEN")) {
        return toast("会话当前不是冻结状态，无需重开（请刷新会话状态）", "err");
      }
      pending = { key: snapReqKey(path.slice(0, 2)), version: cur.version };
      snapState.pendingKey[keyTag] = pending;
    }
    const reqBody = { ...body, version: pending.version, request_key: pending.key };
    let d;
    try {
      d = await api(`/api/snapshots/imports/${s.package_id}/${path}`,
                    { method: "POST", body: reqBody });
    } catch (e) {
      // 拿到了 HTTP 错误响应 = 服务端已作出判定：待决键使命结束。
      // 终局拒绝后该键再发只会回放（留着也不会绕过）；VERSION_CONFLICT 等
      // 未消费键的失败，刷新后由重新点击/「新操作标识重验」生成新判定。
      // 只有真正的**网络中断**（httpStatus===0，无响应）才保留 pending，
      // 允许同键重试、由服务端按首次判定去重。
      if (e.httpStatus !== 0) delete snapState.pendingKey[keyTag];
      throw e;
    }
    // 成功/成功重放：该动作的待决标识消费完毕
    delete snapState.pendingKey[keyTag];
    if (d.replayed) toast("重复请求：幂等返回首次结果", "ok");
    else toast(okMsg, "ok");
    await selectSnapSession(s.package_id);
    await loadSnapSessions(s.package_id);
    return d;
  } catch (e) {
    if (e && e.detail && typeof e.detail === "object" && e.detail.code) {
      snapReportError({ status: e.httpStatus || 0 }, { detail: e.detail });
    } else if (e && e.httpStatus === 0) {
      toast("网络中断，请求未送达：可再次点击，将复用同一操作标识重试", "err");
    } else toast(e.message, "err");
    await selectSnapSession(s.package_id).catch(() => {});
  } finally {
    snapState.busy = false;
    document.body.classList.remove("snap-busy");
  }
}

window.snapHandover = async function () {
  const s = snapState.session;
  const next = prompt("移交给新负责人（标识）：", "");
  if (!next || !next.trim()) return;
  await snapAction("handover", {
    new_owner: next.trim(), actor: snapActor(),
  }, `✓ 负责人已移交：${s.owner || "（未指定）"} → ${next.trim()}`);
};

window.snapRenew = async function () {
  const mins = prompt("续期多少分钟？", "1440");
  const ttl = parseFloat(mins);
  if (!Number.isFinite(ttl) || ttl <= 0) return;
  await snapAction("renew", {
    ttl_minutes: ttl, actor: snapActor(),
  }, `✓ 已续期 ${ttl} 分钟`);
};

window.snapFreeze = async function () {
  if (!confirm("人工冻结该会话？已验真分块、缺块与冲突将保留，但拒绝继续写入。")) return;
  await snapAction("freeze", { actor: snapActor() }, "✓ 会话已人工冻结");
};

window.snapReopen = async function (freshKey) {
  const s = snapState.session;
  const mins = prompt("重新开启并给予新的接收窗口（分钟，可填 1440）：", "1440");
  const ttl = parseFloat(mins);
  if (!Number.isFinite(ttl) || ttl <= 0) return;
  // freshKey=true：原操作标识已被终局拒绝（或操作者主动要求换标识），
  // 生成新 request_key；否则网络重试/连续点击复用待决标识由 snapAction 处理
  await snapAction("reopen", { ttl_minutes: ttl, actor: snapActor() },
    "✓ 重验通过，会话已重新开启", { requireFrozen: true, freshKey: !!freshKey });
};

// ---------------- 详情渲染（缺块/冲突/来源时间点/新旧版本）
function chunkDotsHtml(s) {
  const got = new Set(s.received_seqs);
  const badSeqs = new Set((s.chunk_conflicts || []).map((c) => c.seq));
  let html = "";
  for (let i = 0; i < s.chunk_count; i++) {
    const cls = badSeqs.has(i) ? "bad" : got.has(i) ? "got" : "";
    html += `<span class="chunk-dot ${cls}" title="块 ${i}${
      badSeqs.has(i) ? " 内容冲突" : got.has(i) ? " 已收" : " 缺失"}">${i}</span>`;
  }
  return `<div class="chunk-dots">${html}</div>`;
}

function renderSnapDetail() {
  const s = snapState.session;
  if (!s) return;
  const box = $("#snap-detail");
  const frozen = s.frozen || s.status === "FROZEN";
  const imported = !!s.result || s.status === "IMPORTED";
  const statusText = { UPLOADING: "上传中（可续传）", READY: "全块齐备，可导入",
    CONFLICT: "终检冲突（数据库原样）", FROZEN: "已冻结（保留分块/冲突，拒绝写入）",
    IMPORTED: "已导入（结果受保护）" }[s.status] || s.status;
  const conflicts = s.chunk_conflicts || [];
  const verify = s.verify_conflicts || null;
  const result = s.result;
  const late = !frozen && s.remaining_seconds !== null &&
               s.remaining_seconds !== undefined && s.remaining_seconds <= 0;

  let html = `
    <div class="kv">
      <b>${s.package_id}</b> <span class="pill ${s.status}">${statusText}</span>
      <span class="hint">会话版本 v${s.version}</span><br>
      来源时间点：<b>${s.source_at || "—"}</b><br>
      分块：<b>${s.received_count}/${s.chunk_count}</b> 已收
      ｜ 缺失 ${s.missing_seqs.length} ｜ 同序号异内容 ${conflicts.length}<br>
      创建：${(s.created_at || "").slice(0, 19).replace("T", " ")}
      ｜ 最近更新：${(s.updated_at || "").slice(0, 19).replace("T", " ")}
      ｜ 导出方：${(s.manifest_summary && s.manifest_summary.created_by) || "—"}
    </div>
    <h4>接收窗口与负责人</h4>
    <div class="kv window-box${frozen ? " frozen" : late ? " late" : ""}">
      当前负责人：<b>${escapeHtml(s.owner) || "（未指定，不限制写入）"}</b><br>
      有效期至：<b>${s.valid_until ? String(s.valid_until).slice(0, 19).replace("T", " ") : "不限期"}</b>
      ｜ 剩余：<b>${fmtRemaining(s.remaining_seconds)}</b><br>
      ${frozen ? `冻结状态：<span class="freeze-why">⛔ ${SNAP_FREEZE_TEXT[s.frozen_reason] || s.frozen_reason}
        ${s.frozen_at ? "（" + String(s.frozen_at).slice(0, 19).replace("T", " ") + "）" : ""}</span><br>` : ""}
      ${s.reopened_at ? `最近重开：${String(s.reopened_at).slice(0, 19).replace("T", " ")}<br>` : ""}
    </div>
    <div class="row snap-actions">
      <button class="secondary" onclick="snapHandover()" ${imported ? "disabled" : ""}>移交负责人</button>
      <button class="secondary" onclick="snapRenew()" ${frozen || imported ? "disabled" : ""}>续期</button>
      <button class="danger" onclick="snapFreeze()" ${frozen || imported ? "disabled" : ""}>人工冻结</button>
      <button class="primary" onclick="snapReopen(false)" ${frozen && !imported ? "" : "disabled"}>重开（重验）</button>
      ${frozen && !imported && s.frozen_reason === "REOPEN_MISMATCH"
        ? `<button class="primary snap-newkey-btn" onclick="snapReopen(true)">新操作标识重验（文件已修复）</button>`
        : ""}
    </div>
    ${frozen && s.frozen_reason === "REOPEN_MISMATCH" ? `<div class="hint terminal-note">
      ⚠ 重开校验曾被拒绝：该拒绝对原操作标识是<b>终局结果</b>——连续点击或网络重试只会
      重放首次拒绝，不会重新校验；后台文件修复后须点击【新操作标识重验】（自动使用
      最新会话版本号 v${s.version}）。</div>` : ""}
    ${imported ? `<div class="hint imported-ok">✓ 已导入：不得移交/续期/冻结/重开；保留期清理也不会删除该会话与导入结果。</div>` : ""}`;

  if (frozen && s.frozen_detail) {
    const mm = s.frozen_detail.mismatches || [];
    html += `<div class="conflict-box"><b>冻结原因（可定位）：${escapeHtml(s.frozen_detail.message || "")}</b>`;
    if (s.frozen_detail.mismatch_count) {
      html += `<div class="hint">失配 ${s.frozen_detail.mismatch_count} 项：</div>`;
      mm.slice(0, 20).map((c) => {
        html += `<div class="conflict-line">[${c.code}] ${c.entity || ""} ${c.id ?? ""}: ${escapeHtml(c.message)}</div>`;
      });
    }
    html += `</div>`;
  }

  html += `
    <h4>缺块 / 分块状态（绿=已收，红=内容冲突，灰=缺失）</h4>
    ${chunkDotsHtml(s)}
    ${s.missing_seqs.length ? `<div class="hint">缺失序号：${s.missing_seqs.join(", ")}</div>` : ""}`;

  if (conflicts.length) {
    html += `<h4 style="color:#ff9a9a">同序号不同内容（重传正确分块即清除；冻结期间保留）</h4>` +
      conflicts.map((c) => `<div class="conflict-line">[${c.code}] 块 ${c.seq}: ${escapeHtml(c.message)}</div>`).join("");
  }
  if (verify && ((verify.internal_conflicts || []).length || (verify.local_conflicts || []).length)) {
    const ic = verify.internal_conflicts || [], lc = verify.local_conflicts || [];
    html += `<div class="conflict-box"><b>终检冲突 ${ic.length + lc.length} 项（可定位，未写库）</b>` +
      [...ic, ...lc].slice(0, 30).map((c) =>
        `<div class="conflict-line">[${c.code}] ${c.entity || ""} ${c.id ?? ""}: ${escapeHtml(c.message)}</div>`
      ).join("") + `</div>`;
  }

  if (result) {
    const v = result.versions || [];
    const newN = v.filter((x) => x.state === "NEW").length;
    html += `<h4 style="color:#7be0a3">导入结果（导入于 ${(result.imported_at || "").slice(0, 19).replace("T", " ")}）</h4>
      <div class="kv">来源时间点 <b>${result.source_at}</b>｜新增 ${newN} 版本｜完全相同跳过 ${
        (result.identical_skipped && result.identical_skipped.version) || 0}<br>
      在版版本发生变化的宗地：${(result.current_changes || []).length}</div>
      <h4>新旧版本对应关系</h4>
      <table class="version-map"><thead><tr><th>宗地</th><th>版本</th><th>导入状态</th>
        <th>来源在版</th><th>导入前本地在版</th></tr></thead><tbody>` +
      v.map((x) => `<tr>
        <td>${x.parcel_id}</td><td>${x.version_id}<br><small>v${x.version_no} · ${x.status}</small></td>
        <td><span class="pill ${x.state}">${x.state === "NEW" ? "新增" : "相同跳过"}</span></td>
        <td>${x.source_current ? "是" : "否"}</td>
        <td><small>${x.local_current_before || "（无）"}</small></td></tr>`).join("") +
      `</tbody></table>` +
      (result.replayed ? `<div class="hint">相同包标识重复导入：返回首次结果，未二次落账。</div>` : "");
  }

  // ---- 操作审计 ----
  const evs = snapState.events || [];
  const EV_TEXT = {
    CREATE: "创建会话", RESUME_SESSION: "恢复会话", CHUNK_ACCEPTED: "接收分块",
    CHUNK_CONFLICT: "分块内容冲突", WRITE_DENIED: "拒绝写入",
    HANDOVER: "负责人移交", RENEW: "续期", FREEZE: "冻结", REOPEN: "重新开启",
    REOPEN_REJECTED: "重开校验被拒（终局）",
    FINALIZE_IMPORT: "终检导入", FINALIZE_REJECTED: "终检驳回" };
  html += `<h4>操作审计（${evs.length}）</h4><div class="snap-events">` +
    evs.slice(-30).map((e) => {
      const d = e.detail || {};
      let note = "";
      if (e.action === "HANDOVER") note = `${d.from_owner || "—"} → ${d.to_owner}`;
      else if (e.action === "RENEW") note = `至 ${(d.to_valid_until || "").slice(0, 16)}`;
      else if (e.action === "FREEZE") note = d.reason || "";
      else if (e.action === "CHUNK_ACCEPTED") note = `#${d.seq}`;
      else if (e.action === "WRITE_DENIED") note = d.reason || "";
      else if (e.action === "REOPEN") note = `至 ${(d.valid_until || "").slice(0, 16)}`;
      else if (e.action === "REOPEN_REJECTED")
        note = `失配 ${d.mismatch_count ?? ""} 项 · 操作标识 ${d.request_key || ""}`;
      return `<div class="evt evt-${e.action}"><span class="evt-seq">${e.seq}</span>
        <span class="evt-when">${String(e.created_at).slice(5, 19).replace("T", " ")}</span>
        <span class="evt-act">${EV_TEXT[e.action] || e.action}</span>
        <span class="evt-actor">${escapeHtml(e.actor) || "—"}</span>
        <span class="evt-note">${escapeHtml(note)}</span></div>`;
    }).join("") + `</div>`;
  box.innerHTML = html;
}

$("#plan-req-key") && 0; // 保持既有脚本结构占位（无操作）

$$("#plan-filters button").forEach((b) => b.onclick = () => {
  planState.filter = b.dataset.f;
  $$("#plan-filters button").forEach((x) => x.classList.toggle("active", x === b));
  renderPlanList();
});
$("#btn-plan-refresh").onclick = () => loadPlans(planState.selectedId);



// --------------------------------------------------------------- 启动
function resizeCanvas() {
  canvas.width = canvas.parentElement.clientWidth;
  canvas.height = 680;
  render();
}
window.addEventListener("resize", resizeCanvas);
loadMap().then(resizeCanvas);
setInterval(() => { if (!document.hidden) loadMap(); }, 15000);
render();
