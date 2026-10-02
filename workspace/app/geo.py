"""几何内核：平面坐标下的界址环校验、共享边分析与折片段（fragment）差异。

约定
----
* 环 ring = [[x, y], ...]，**不含重复终点**，统一逆时针（CCW）。
* "折片段" 指两个折点（anchor，环上方向显著变化的顶点）之间的边界链，
  可能含若干中间界址点。共享边争议以折片段为最小单位。
"""
from __future__ import annotations

import math
from collections import Counter
from typing import Optional

from shapely.geometry import LineString, Polygon, LinearRing
from shapely.ops import shared_paths, unary_union
from shapely import hausdorff_distance

from . import config


# --------------------------------------------------------------------------
# 基础工具
# --------------------------------------------------------------------------
def _dist(a, b) -> float:
    return math.hypot(a[0] - b[0], a[1] - b[1])


def _grid(v: float, g: float) -> float:
    return round(v / g) * g


def round_pt(p, ndigits: int = 3):
    return [round(float(p[0]), ndigits), round(float(p[1]), ndigits)]


def norm_ring(ring) -> list[list[float]]:
    """去重终点、去零长段、统一为逆时针。不改变未闭合状态（交给校验）。"""
    pts = [round_pt(p) for p in ring]
    if len(pts) >= 2 and _dist(pts[0], pts[-1]) < config.CLOSURE_TOL_M:
        pts = pts[:-1]
    clean = []
    for p in pts:
        if not clean or _dist(clean[-1], p) > config.SELF_INTERSECT_GRID:
            clean.append(p)
    if len(clean) >= 3 and _dist(clean[0], clean[-1]) <= config.SELF_INTERSECT_GRID:
        clean = clean[:-1]
    if len(clean) >= 3 and signed_area(clean) < 0:
        clean.reverse()
    return clean


def closure_gap(ring) -> float:
    if len(ring) < 3:
        return float("inf")
    return _dist(ring[0], ring[-1])


def closed_coords(ring) -> list[tuple[float, float]]:
    return [(float(x), float(y)) for x, y in ring] + [(float(ring[0][0]), float(ring[0][1]))]


def signed_area(ring) -> float:
    s = 0.0
    n = len(ring)
    for i in range(n):
        x1, y1 = ring[i]
        x2, y2 = ring[(i + 1) % n]
        s += x1 * y2 - x2 * y1
    return s / 2.0


def ring_area(ring) -> float:
    return abs(signed_area(ring))


def as_polygon(ring) -> Polygon:
    return Polygon(closed_coords(ring))


def as_boundary(ring, grid: float = 0.0) -> LineString:
    coords = closed_coords(ring)
    if grid:
        coords = [(_grid(x, grid), _grid(y, grid)) for x, y in coords]
    return LineString(coords)


def _seg_intersection(p1, p2, p3, p4):
    """线段 (p1,p2) 与 (p3,p4) 的内部/端点交点，无则 None。"""
    x1, y1 = p1; x2, y2 = p2; x3, y3 = p3; x4, y4 = p4
    d = (x1 - x2) * (y3 - y4) - (y1 - y2) * (x3 - x4)
    if abs(d) < 1e-12:
        return None
    t = ((x1 - x3) * (y3 - y4) - (y1 - y3) * (x3 - x4)) / d
    u = -((x1 - x2) * (y1 - y3) - (y1 - y2) * (x1 - x3)) / d
    eps = 1e-9
    if -eps <= t <= 1 + eps and -eps <= u <= 1 + eps:
        return (x1 + t * (x2 - x1), y1 + t * (y2 - y1))
    return None


def self_intersection_points(ring) -> list[tuple[float, float]]:
    """逐对检查非相邻边，返回自交点（环须已闭合）。"""
    coords = [tuple(p) for p in ring] + [tuple(ring[0])]
    n = len(coords) - 1  # 边数
    hits, seen = [], set()
    for i in range(n):
        for j in range(i + 1, n):
            adjacent = (i + 1) % n == j or (j + 1) % n == i
            if i == j or adjacent:
                continue  # 相邻边（共享顶点是正常的）
            pt = _seg_intersection(coords[i], coords[i + 1],
                                   coords[j], coords[j + 1])
            if pt is None:
                continue
            rp = tuple(round_pt(pt))
            # 非相邻边在端点相遇（顶点重复接触）也属自交，予以保留
            if rp not in seen:
                seen.add(rp)
                hits.append(rp)
    return hits


def zero_segments(ring) -> list[int]:
    out = []
    n = len(ring)
    for i in range(n):
        if _dist(ring[i], ring[(i + 1) % n]) < config.MIN_SEG_LEN_M:
            out.append(i)
    return out


# --------------------------------------------------------------------------
# 折线 / 片段偏差
# --------------------------------------------------------------------------
def _densify(chain, n=64):
    """按累计长度等距取 n 个点（含两端），用于**有向**链比较。"""
    pts = [(float(x), float(y)) for x, y in chain]
    seg = [_dist(pts[i], pts[i + 1]) for i in range(len(pts) - 1)]
    total = sum(seg)
    if total <= 0:
        return [pts[0]] * n
    out, cumulative = [], [0.0]
    for s in seg:
        cumulative.append(cumulative[-1] + s)
    for k in range(n):
        d = total * k / (n - 1)
        # 定位所在段
        i = 0
        while i < len(seg) and cumulative[i + 1] < d:
            i += 1
        i = min(i, len(seg) - 1)
        t = 0 if seg[i] == 0 else (d - cumulative[i]) / seg[i]
        out.append((pts[i][0] + t * (pts[i + 1][0] - pts[i][0]),
                    pts[i][1] + t * (pts[i + 1][1] - pts[i][1])))
    return out


def directed_deviation(chain_a, chain_b, n=64) -> float:
    """方向敏感的链偏差：逐对应点平均距离（米）。"""
    if len(chain_a) < 2 or len(chain_b) < 2:
        return float("inf")
    a, b = _densify(chain_a, n), _densify(chain_b, n)
    return sum(_dist(x, y) for x, y in zip(a, b)) / n


def path_pair_match(p_start_end, p_end_start, reference) -> tuple[float, float]:
    """环上两条固定方向路径与参考链的贴合度。

    p_start_end 是 start→end，与参考**同向**比较；
    p_end_start 是 end→start，与参考**反向**比较。
    """
    return (directed_deviation(p_start_end, reference),
            directed_deviation(p_end_start, list(reversed(reference))))


def chain_deviation(chain_a, chain_b, densify_m: float = 0.25) -> float:
    """两条折线的对称最大偏差（Hausdorff 距离，米）。"""
    if len(chain_a) < 2 or len(chain_b) < 2:
        return float("inf")
    la = LineString([(float(x), float(y)) for x, y in chain_a])
    lb = LineString([(float(x), float(y)) for x, y in chain_b])
    if la.length <= 0 or lb.length <= 0:
        return float("inf")
    # densify 参数是"每段最大分数"，按物理间距换算并钳制到 (0,1]
    frac = min(1.0, densify_m / max(la.length, lb.length, densify_m))
    return float(hausdorff_distance(la, lb, densify=max(frac, 1e-6)))


def _line_coords(geom):
    """LineString/MultiLineString/GeometryCollection 中所有线段的坐标点。"""
    pts = []
    if geom is None or geom.is_empty:
        return pts
    gt = geom.geom_type
    if gt == "LineString":
        return list(geom.coords)
    for g in getattr(geom, "geoms", []):
        if g.geom_type == "LineString":
            pts.extend(g.coords)
        elif g.geom_type == "MultiLineString":
            for ln in g.geoms:
                pts.extend(ln.coords)
    return pts


def boundary_band(ring_a, ring_b) -> dict:
    """分析 A 环边界与 B 环边界的贴近情况。

    返回 {consistent_len, mismatch_len, mismatch_sample}：
    * B 缓冲 CONSIST 内 = 一致；
    * SEARCH 内但 CONSIST 外 = 共享但不一致（偏移/争议）。

    缓冲差分在重合段两端会产生约 SEARCH_TOL 长的"缓冲帽"数值伪影
    （shapely 2 下约 0.45m），这些与一致段端点相连的短碎片不计为偏差。
    """
    ba = as_boundary(ring_a, config.SELF_INTERSECT_GRID)
    bb = as_boundary(ring_b, config.SELF_INTERSECT_GRID)
    near = ba.intersection(bb.buffer(config.SHARED_SEARCH_TOL_M, quad_segs=8))
    good = ba.intersection(bb.buffer(config.SHARED_CONSIST_TOL_M, quad_segs=8))
    mismatch = near.difference(good.buffer(config.SELF_INTERSECT_GRID))
    sample, real_len = None, 0.0
    if not mismatch.is_empty:
        good_pts = _line_coords(good)
        parts = []
        for g in getattr(mismatch, "geoms", [mismatch]):
            if g.geom_type not in ("LineString", "MultiLineString") or g.is_empty:
                continue
            lines = g.geoms if g.geom_type == "MultiLineString" else [g]
            parts.extend(lines)
        for ln in parts:
            # 端点贴合一致段 → 缓冲帽伪影，跳过
            c0, c1 = ln.coords[0], ln.coords[-1]
            touches_good = any(_dist(c0, q) <= config.SELF_INTERSECT_GRID * 2 or
                               _dist(c1, q) <= config.SELF_INTERSECT_GRID * 2
                               for q in good_pts)
            if touches_good and ln.length < config.SHARED_SEARCH_TOL_M:
                continue
            real_len += ln.length
            if sample is None and ln.length > config.MIN_SEG_LEN_M:
                sample = list(ln.interpolate(0.5).coords)[0]
    return {
        "consistent_len": round(float(good.length), 3),
        "mismatch_len": round(float(max(real_len, 0.0)), 3),
        "mismatch_sample": round_pt(sample) if sample else None,
    }


def shared_segments(ring_a, ring_b) -> list[dict]:
    """提取两环共有的重合段（shared_paths），用于指认相邻宗地。"""
    la = as_boundary(ring_a, config.SELF_INTERSECT_GRID)
    lb = as_boundary(ring_b, config.SELF_INTERSECT_GRID)
    try:
        coll = shared_paths(la, lb)
    except Exception:
        return []
    # shapely 1.x 返回 (forward, backward) 二元组；2.x 返回含两个
    # MultiLineString 的 GeometryCollection
    geoms = getattr(coll, "geoms", None)
    if geoms is not None and len(geoms) == 2:
        fwd, bwd = geoms[0], geoms[1]
    elif isinstance(coll, tuple):
        fwd, bwd = coll
    else:
        return []
    out = []
    for coll in (fwd, bwd):
        if coll.is_empty:
            continue
        geoms = coll.geoms if hasattr(coll, "geoms") else [coll]
        for g in geoms:
            if g.length >= config.MIN_SEG_LEN_M:
                mid = g.interpolate(0.5, normalized=True)
                out.append({
                    "length": round(float(g.length), 3),
                    "midpoint": round_pt(mid.coords[0]),
                })
    return out


def overlap_area(ring_a, ring_b) -> float:
    pa, pb = as_polygon(ring_a), as_polygon(ring_b)
    if not pa.is_valid or not pb.is_valid:
        return float("inf")
    return float(pa.intersection(pb).area)


def polygon_union(rings) -> tuple[object, float]:
    polys = [as_polygon(r) for r in rings]
    return unary_union(polys), sum(p.area for p in polys)


# --------------------------------------------------------------------------
# 折片段（fragment）差异
# --------------------------------------------------------------------------
def _key(p) -> tuple[float, float]:
    return (round(float(p[0]), 2), round(float(p[1]), 2))


def anchor_key(start, end) -> str:
    """两个锚点（不排序）构成的片段键。"""
    def _k(p):
        return (round(float(p[0]), 2), round(float(p[1]), 2))
    return f"{_k(start)[0]}|{_k(start)[1]}|{_k(end)[0]}|{_k(end)[1]}"


def edge_key(start, end) -> str:
    """不区分方向的共享边键（两端点排序）。"""
    def _k(p):
        return (round(float(p[0]), 2), round(float(p[1]), 2))
    lo, hi = sorted((_k(start), _k(end)))
    return f"{lo[0]}|{lo[1]}|{hi[0]}|{hi[1]}"


def _vertex_mapping(base, new, snap: float):
    """按环顺序建立 基环节点 -> 新环节点 的唯一对应。返回 [(b_idx, n_idx), ...]（按 b_idx 排序）。"""
    nearest_for_b = {}
    for bi, bp in enumerate(base):
        best, best_d = None, snap
        for ni, np_ in enumerate(new):
            d = _dist(bp, np_)
            if d <= best_d:
                best, best_d = ni, d
        if best is not None:
            nearest_for_b[bi] = (best, best_d)
    # 消解一个新节点被多个旧节点争抢：距离小者胜
    winners = {}
    for bi, (ni, d) in sorted(nearest_for_b.items(), key=lambda kv: kv[1][1]):
        if ni not in winners.values():
            winners[bi] = ni
    return [(bi, ni) for bi, ni in sorted(winners.items())]


def _slice_ring_cyclic(ring, i: int, j: int) -> list:
    """沿环正向（CCW）取 i -> j 的顶点链（含两端）。"""
    n = len(ring)
    if i == j:
        return [ring[i]]
    if i < j:
        return ring[i:j + 1]
    return ring[i:] + ring[:j + 1]


def diff_fragments(base, new, tol: Optional[float] = None) -> list[dict]:
    """对比同一宗地的两版环，输出发生变化的折片段列表。

    每项: {anchor_start:[x,y], anchor_end:[x,y], base_chain, new_chain, deviation}
    """
    tol = tol or config.SHARED_CONSIST_TOL_M
    base, new = norm_ring(base), norm_ring(new)
    anchors = _vertex_mapping(base, new, config.POINT_SNAP_TOL_M)

    if len(anchors) < 2:
        # 找不到两个公共折点：整环视为一个争议片段（无固定端点）
        dev = chain_deviation(base + [base[0]], new + [new[0]])
        return [{
            "anchor_start": None, "anchor_end": None,
            "base_chain": base, "new_chain": new, "deviation": round(dev, 3),
        }]

    out = []
    for k in range(len(anchors)):
        bi, ni = anchors[k]
        bj, nj = anchors[(k + 1) % len(anchors)]
        bc = _slice_ring_cyclic(base, bi, bj)
        nc = _slice_ring_cyclic(new, ni, nj)
        dev = chain_deviation(bc, nc)
        if dev > tol:
            out.append({
                "anchor_start": round_pt(base[bi]),
                "anchor_end": round_pt(base[bj]),
                "base_chain": [round_pt(p) for p in bc],
                "new_chain": [round_pt(p) for p in nc],
                "deviation": round(dev, 3),
            })
    return out


def find_vertex(ring, p, snap: float) -> Optional[int]:
    for i, q in enumerate(ring):
        if _dist(p, q) <= snap:
            return i
    return None


def ring_chain_between(ring, start, end, snap: Optional[float] = None,
                       reference=None) -> list:
    """取环上 start -> end 的正向链；若两条路径均存在，用 reference 链选路。"""
    snap = snap or config.POINT_SNAP_TOL_M
    i = find_vertex(ring, start, snap)
    j = find_vertex(ring, end, snap)
    if i is None or j is None:
        raise ValueError("裁定锚点在当前环上不存在")
    p1 = _slice_ring_cyclic(ring, i, j)
    p2 = _slice_ring_cyclic(ring, j, i)
    if reference:
        d1, d2 = path_pair_match(p1, p2, reference)
        return p1 if d1 <= d2 else p2
    return p1 if len(p1) <= len(p2) else p2


def replace_chain(ring, start, end, new_chain, snap: Optional[float] = None) -> list:
    """用 new_chain 替换环上 start -> end 片段，保留其余边界**原样不动**。"""
    snap = snap or config.POINT_SNAP_TOL_M
    i = find_vertex(ring, start, snap)
    j = find_vertex(ring, end, snap)
    if i is None or j is None:
        raise ValueError("锚点不存在，无法替换片段")
    rest = _slice_ring_cyclic(ring, j, i)  # 终点 -> 起点（未争议部分，含两端）
    chain = [round_pt(p) for p in new_chain]
    if _dist(chain[0], start) <= snap:
        chain[0] = round_pt(start)
    if _dist(chain[-1], end) <= snap:
        chain[-1] = round_pt(end)
    merged = chain[:-1] + rest  # end 不重复
    return norm_ring(merged)


def replace_segment(ring, start, end, new_chain, base_chain,
                    snap: Optional[float] = None) -> list:
    """按**基线段 base_chain** 指认环上要替换的路径（两锚点间有两条路径时不选错），
    用 new_chain 替换之；另一条路径（补链）逐点保留。

    新链方向自动对齐到被替换段。合并严格按"新段 + 补链"成环，与环绕方向无关。
    """
    snap = snap or config.POINT_SNAP_TOL_M
    i = find_vertex(ring, start, snap)
    j = find_vertex(ring, end, snap)
    if i is None or j is None or i == j:
        raise ValueError("锚点不存在，无法替换片段")
    p1 = _slice_ring_cyclic(ring, i, j)
    p2 = _slice_ring_cyclic(ring, j, i)
    d1, d2 = path_pair_match(p1, p2, base_chain)
    if d1 <= d2:
        # p1 是被替换段（i→j，start→end），p2 是补链（j→i，end→start）
        chain_in, complement = _orient(new_chain, p1), p2
        merged = chain_in[:-1] + complement
    else:
        # p2 是被替换段（j→i，end→start），p1 是补链（i→j，start→end）
        chain_in, complement = _orient(new_chain, p2), p1
        merged = complement[:-1] + chain_in
    return norm_ring(merged)


def _orient(new_chain, segment):
    """把新链端点对齐到 segment 的方向。"""
    chain = [round_pt(p) for p in new_chain]
    if _dist(chain[0], segment[0]) > _dist(chain[-1], segment[0]):
        chain = list(reversed(chain))
    chain[0] = round_pt(segment[0])
    chain[-1] = round_pt(segment[-1])
    return chain


def changed_fragment_keys(frags) -> set[str]:
    return {anchor_key(f["anchor_start"], f["anchor_end"]) for f in frags
            if f["anchor_start"] is not None}


# --------------------------------------------------------------------------
# 历史更正：变更片段向后代版本传导（SPLIT/MERGE/ADJUDICATION 血缘推演）
# --------------------------------------------------------------------------
def _segment_intersect(p1, p2, p3, p4):
    """开放线段求交：返回交点（端点相接也算），平行/无交返回 None。"""
    x1, y1 = p1; x2, y2 = p2; x3, y3 = p3; x4, y4 = p4
    d = (x1 - x2) * (y3 - y4) - (y1 - y2) * (x3 - x4)
    if abs(d) < 1e-12:
        return None  # 共线重叠在本场景不出现（分割线与外边界横切）
    t = ((x1 - x3) * (y3 - y4) - (y1 - y3) * (x3 - x4)) / d
    u = -((x1 - x2) * (y1 - y3) - (y1 - y2) * (x1 - x3)) / d
    eps = 1e-9
    if -eps <= t <= 1 + eps and -eps <= u <= 1 + eps:
        return (x1 + t * (x2 - x1), y1 + t * (y2 - y1))
    return None


def _arcmap(chain):
    """开放折线 → (累计弧长列表, 总长)。"""
    cum = [0.0]
    for i in range(len(chain) - 1):
        cum.append(cum[-1] + _dist(chain[i], chain[i + 1]))
    return cum, cum[-1]


def _point_at(chain, cum, total, t):
    """归一化弧长 t∈[0,1] 上的点（端点精确返回）。"""
    if t >= 1.0:
        return tuple(chain[-1])
    if t <= 0.0:
        return tuple(chain[0])
    d = t * total
    i = 0
    while i < len(cum) - 2 and cum[i + 1] < d - 1e-9:
        i += 1
    seg = cum[i + 1] - cum[i]
    f = 0.0 if seg <= 1e-12 else (d - cum[i]) / seg
    return (chain[i][0] + f * (chain[i + 1][0] - chain[i][0]),
            chain[i][1] + f * (chain[i + 1][1] - chain[i][1]))


def _arc_param(p, chain, cum, total, tol):
    """点 p 到链的最近投影 → (归一化弧长参数, 距离)；无投影返 None。"""
    best_d, best_t = float("inf"), None
    for i in range(len(chain) - 1):
        a, b = chain[i], chain[i + 1]
        vx, vy = b[0] - a[0], b[1] - a[1]
        L2 = vx * vx + vy * vy
        f = 0.0 if L2 <= 1e-12 else max(0.0, min(1.0,
            ((p[0] - a[0]) * vx + (p[1] - a[1]) * vy) / L2))
        q = (a[0] + f * vx, a[1] + f * vy)
        d = _dist(p, q)
        if d < best_d:
            best_d, best_t = d, (cum[i] + f * (cum[i + 1] - cum[i])) / total
    return (best_t, best_d) if best_d <= tol else None


def _slice_interval(chain, cum, total, t0, t1):
    """开放链弧长区间 [t0,t1]⊂[0,1] 折线（含插值端点）。"""
    d0, d1 = min(t0, t1) * total, max(t0, t1) * total
    pts = [list(_point_at(chain, cum, total, min(t0, t1)))]
    for i, c in enumerate(cum):
        if d0 + 1e-9 < c < d1 - 1e-9:
            pts.append([chain[i][0], chain[i][1]])
    pts.append(list(_point_at(chain, cum, total, max(t0, t1))))
    clean = []
    for q in pts:
        if not clean or _dist(clean[-1], q) > config.SELF_INTERSECT_GRID:
            clean.append(q)
    return clean



def geo_chain_match(chain_a, chain_b):
    """两条等长顶点链的逐点平均偏差（用于判别 sub_base 沿哪条弧走）。"""
    if len(chain_a) != len(chain_b):
        return float("inf")
    return sum(_dist(a, b) for a, b in zip(chain_a, chain_b)) / max(len(chain_a), 1)


class _BoundaryMap:
    """旧边界环 → 更正后新边界环 的分段参数映射。

    以基环顶点 0 为弧长参数原点（与 transfer 侧 bclosed 一致）。变更片段由
    diff_fragments 给出两锚点间的实际短弧基链与替换链：沿基环正向遍历时，
    未变更部分用旧折线、片段处换成新折线；跨顶点 0 的片段在接缝（顶点0）处
    把新链按旧弧长比例切成"尾(t0→1)、头(0→t1)"两段。段内按各自折线弧长
    线性插值——分割切口落在片段中间、凸出/凹入使两侧弧长不等都能正确映射。

    segments: [(旧t0, 旧t1, 新折线, 是否变更)]，t∈[0,1]，首尾覆盖整环。
    """

    def __init__(self, base_ring, fragments):
        self.base = norm_ring(base_ring)
        nb = len(self.base)
        self.bclosed = self.base + [self.base[0]]
        self.bcum, self.btot = _arcmap(self.bclosed)

        if not fragments:
            self.new_ring = [list(q) for q in self.base]
            self.segments = [(0.0, 1.0, self.bclosed, False)]
            self.change_intervals = []
            self.change_chains = []
            return

        # 统一用"未展开"片段表示：(旧弧长区间 [a,b]⊂[0,1], 新折线)。
        # 先把每个 diff 片段按其真实短弧方向拆成 1~2 个不跨 0/1 的片段。
        change_chains = []
        spans = []  # (a, b, new_chain)
        for f in fragments:
            sub_base = [round_pt(q) for q in f["base_chain"]]
            sub_new = [round_pt(q) for q in f["new_chain"]]
            if _dist(sub_new[0], sub_base[0]) > _dist(sub_new[-1], sub_base[0]):
                sub_new = list(reversed(sub_new))
            change_chains.append(sub_base)

            # 沿基环顶点走，找到与 sub_base 匹配的有向短弧（顶点序列）
            si = find_vertex(self.base, sub_base[0], config.POINT_SNAP_TOL_M)
            ei = find_vertex(self.base, sub_base[-1], config.POINT_SNAP_TOL_M)
            if si is None or ei is None:
                continue
            fwd_d = (ei - si) % nb or nb
            fwd = [self.base[(si + k) % nb] for k in range(fwd_d + 1)]
            rev = list(reversed(fwd))
            use_fwd = geo_chain_match(sub_base, fwd) <= geo_chain_match(sub_base, rev)

            # 展开成有向边索引序列 start..end（CCW 为正方向，跨 0 时用负值/>=nb）
            if use_fwd:
                start, d = si, fwd_d
            else:
                start, d = ei, nb - fwd_d  # 反向短弧：从 ei 正向走到 si
            end = start + d
            chain = sub_new if use_fwd else list(reversed(sub_new))

            # 该弧在基环上的旧弧长（沿 start→end 逐边累加），及接缝位置
            edge_pts = [self.base[i % nb] for i in range(start, end)] + \
                       [self.base[end % nb]]
            cum_b, tot_b = _arcmap(edge_pts)
            seam_i = next((i for i, q in enumerate(edge_pts)
                           if i > 0 and _dist(q, self.base[0]) <=
                           config.SELF_INTERSECT_GRID), None)

            def t_at_edge(edge):
                e = edge % nb
                k = 0 if edge >= 0 else -1
                return (k + self.bcum[e] / self.btot) % 1.0

            if seam_i is None or start >= 0 and end <= nb:
                a0 = t_at_edge(start); b0 = t_at_edge(end)
                if use_fwd and end <= nb:
                    a0, b0 = self.bcum[start] / self.btot, self.bcum[end] / self.btot
                spans.append((a0, b0, chain))
                continue

            # 跨接缝：在接缝顶点把旧弧、新链都切成两段
            cut = cum_b[seam_i] / max(tot_b, 1e-12)
            cum_n, tot_n = _arcmap(chain)
            to_seam = _slice_interval(chain, cum_n, tot_n, 0.0, cut)
            from_seam = _slice_interval(chain, cum_n, tot_n, cut, 1.0)
            seam = list(self.base[0])
            # 沿 start→end 行进，第一段(to_seam)在过接缝前、第二段(from_seam)在其后：
            #  * start≥0、end>nb：第一段落在 t=1 侧=尾，第二段落在 t=0 侧=头；
            #  * start<0、end∈[0,nb)：第一段落在 t=1 侧=尾，第二段=头（同理）。
            tail_ch, head_ch = to_seam, from_seam
            tail_ch[-1] = seam
            head_ch[0] = seam
            len_tail = cum_b[seam_i]          # 起点→接缝 的旧弧长
            len_head = tot_b - cum_b[seam_i]  # 接缝→终点 的旧弧长
            spans.append((0.0, len_head / self.btot, head_ch))
            spans.append((1.0 - len_tail / self.btot, 1.0, tail_ch))

        # 沿 0→1 合并：未变更段取旧环，变更段取新链
        spans.sort(key=lambda x: x[0])
        segments, out = [], []
        cursor = 0.0

        def emit(a, b, ch, changed):
            if b - a <= 1e-12:
                return
            segments.append((a, b, ch, changed))
            out.extend(ch[:-1])

        for a, b, ch in spans:
            if a > cursor + 1e-12:
                emit(cursor, a, _slice_interval(
                    self.bclosed, self.bcum, self.btot, cursor, a), False)
            emit(a, b, ch, True)
            cursor = max(cursor, b)
        if cursor < 1.0 - 1e-9:
            emit(cursor, 1.0, _slice_interval(
                self.bclosed, self.bcum, self.btot, cursor, 1.0), False)

        self.new_ring = norm_ring(out)
        self.segments = segments
        self.change_intervals = [(a, b) for a, b, _c, ch in segments if ch]
        self.change_chains = change_chains

    def is_changed_point(self, p):
        """切点 p 是否落在某变更片段旧基链上（在上面则随片段移动）。"""
        for ch in self.change_chains:
            cum, tot = _arcmap(ch)
            if _arc_param(p, ch, cum, tot, config.SHARED_SEARCH_TOL_M):
                return True
        return False

    def point(self, t):
        """旧环归一化/展开参数 → 新几何点。

        变更段内部（含其端点）按段折线插值，保证落在更正片段上的切口
        （即便恰好在锚点/接缝处）也取到更正后位置；未变更段端点直接返回。
        """
        k0 = int(math.floor(t)) if t >= 0 else -int(math.ceil(-t))
        ti = t - k0
        # 整数圈：属于上一圈终点
        if ti <= 1e-12 and k0 >= 1:
            last = self.segments[-1]
            return list(last[2][-1])
        # 变更段优先（端点也插值，避免锚点移动时取错）。
        # 关键：段内比例由**旧弧长参数**差给出（ti-lo)/(hi-lo)，
        # 而新链按自身折线弧长取点——凸出使新链更长时比例仍然正确。
        for lo, hi, chain, changed in self.segments:
            if changed and lo - 1e-12 <= ti <= hi + 1e-12:
                f = (ti - lo) / max(hi - lo, 1e-12)
                return list(_point_on_polyline_fraction(chain, f))
        # 未变更段：端点精确
        for lo, hi, chain, _ in self.segments:
            if abs(ti - lo) <= 1e-12:
                return list(chain[0])
            if abs(ti - hi) <= 1e-12:
                return list(chain[-1])
        for lo, hi, chain, _ in self.segments:
            if lo - 1e-12 <= ti <= hi + 1e-12:
                f = (ti - lo) / max(hi - lo, 1e-12)
                return list(_point_on_polyline_fraction(chain, f))
        return list(self.segments[-1][2][-1])

    def slice_unwrapped(self, t0, t1):
        """旧环展开区间 → 新折线，保留区间内段端点与折线内部顶点。"""
        pts = [self.point(t0)]
        events = []
        for k in range(int(math.floor(t0)) - 1, int(math.ceil(t1)) + 2):
            for lo, hi, chain, _ in self.segments:
                a, b = lo + k, hi + k
                cum, tot = _arcmap(chain)
                for i in range(1, len(chain) - 1):
                    c = a + (b - a) * (cum[i] / tot) if tot > 1e-12 else a
                    events.append((c, list(chain[i])))
                events.append((b, list(chain[-1])))
        for c, q in events:
            if t0 + 1e-9 < c < t1 - 1e-9:
                pts.append(q)
        pts.append(self.point(t1))
        clean = []
        for q in pts:
            if not clean or _dist(clean[-1], q) > 1e-6:
                clean.append(q)
        return clean


def _point_on_polyline_fraction(chain, f):
    """开放折线上按全长比例 f∈[0,1] 的点（沿子段弧长）。"""
    cum, tot = _arcmap(chain)
    return _point_at(chain, cum, tot, f)


def transfer_fragments(child_ring, base_ring, fragments,
                       tol: Optional[float] = None) -> list[list[float]]:
    """把 base_ring→新边界 的变更片段传导到一个后代环 child_ring。

    更正预演核心：目标宗地外边界被更正后，沿 SPLIT/MERGE 等血缘推演
    后代（子宗/合并结果）的新几何。

    1. 逐边求 child 环与 base 环的交点，把 child 边切成小段；
    2. 沿基环弧段贴合的段（外边界继承部分）标记 on，其余（分割内线、
       未变更边界）off；切口落在变更片段中间也能正确切分；
    3. 连续 on 段合并为 run，按旧环弧长参数区间经 _BoundaryMap 映射到
       更正后新边界（分段线性，凸出/凹入导致两侧弧长不等也不偏）；
       off 段逐点保留。

    返回替换后的环（调用方再做 norm_ring/合法性校验）。
    """
    tol = tol or config.SHARED_SEARCH_TOL_M
    child = norm_ring(child_ring)
    base = norm_ring(base_ring)
    bm = _BoundaryMap(base, fragments)

    # ---- 1) 切 child 边，逐段判 on/off ----
    # 切点来源：
    #  a) child 边与 base 边的交点；
    #  b) 变更片段基链的每个顶点（锚点/中间点）若落在 child 某条边上——
    #     MERGE 后代环可能把多个父宗边界合并成长边，父片段锚点会落在其内部，
    #     必须切开才能只替换被更正的那一段。
    frag_pts = []
    for f in fragments:
        frag_pts.extend(round_pt(q) for q in f["base_chain"])
    n = len(child)
    nb = len(base)
    raw = []
    for i in range(n):
        a, b = child[i], child[(i + 1) % n]
        cuts = {tuple(round_pt(a)), tuple(round_pt(b))}
        for j in range(nb):
            hit = _segment_intersect(a, b, base[j], base[(j + 1) % nb])
            if hit:
                cuts.add(tuple(round_pt(hit)))
        for fp in frag_pts:
            pr = _arc_param(fp, [a, b], [0.0, _dist(a, b)], _dist(a, b), tol)
            if pr:  # 片段基链顶点落在该 child 边上
                cuts.add(tuple(round_pt(fp)))
        ordered = sorted(cuts, key=lambda q: _dist(a, q))
        for k in range(len(ordered) - 1):
            p0, p1 = list(ordered[k]), list(ordered[k + 1])
            if _dist(p0, p1) <= config.MIN_SEG_LEN_M:
                continue
            raw.append({"p": p0, "q": p1,
                        **_classify_piece(p0, p1, bm.bclosed, bm.bcum, bm.btot, tol)})

    # 旋转到从 off 段开始（全 on = 整环继承，直接返回新边界）
    start = next((k for k, pc in enumerate(raw) if not pc["on"]), 0)
    if raw and all(pc["on"] for pc in raw):
        return [list(q) for q in bm.new_ring]
    pieces0 = raw[start:] + raw[:start]
    m = len(pieces0)

    # 切点的更正后位置：
    #  * 连接某条 on（继承基环）段 → 按基环参数映射到更正后位置；
    #  * 只接 off 段（内部分割线）但几何落在某变更片段旧基链上
    #    （如更正顶边时分割线顶端）→ 同样映射（分割线端点随之移动）；
    #  * 其余点保持原位。
    pieces = []
    for i, pc in enumerate(pieces0):
        prev_on, next_on = pieces0[(i - 1) % m]["on"], pieces0[(i + 1) % m]["on"]

        def pos(pt, touch):
            pr = _arc_param(pt, bm.bclosed, bm.bcum, bm.btot, tol)
            if not pr:
                return list(pt)
            if touch or bm.is_changed_point(pt):
                return bm.point(pr[0])
            return list(pt)

        pieces.append({**pc, "pm": pos(pc["p"], pc["on"] or prev_on),
                       "qm": pos(pc["q"], pc["on"] or next_on)})

    # ---- 2) 连续 on 合并为 run，取更正后切片；off 段端点用上面的位置 ----
    result: list[list[float]] = []

    def close_run(r):
        d = r["te"] - r["ts"]
        if d > 0.5:
            t0, t1 = r["ts"], r["te"] - 1.0
        elif d < -0.5:
            t0, t1 = r["ts"] + 1.0, r["te"]
        else:
            t0, t1 = r["ts"], r["te"]
        seg = bm.slice_unwrapped(min(t0, t1), max(t0, t1))
        if _dist(seg[0], r["pm"]) > _dist(seg[-1], r["pm"]):
            seg = list(reversed(seg))
        if result and _dist(result[-1], seg[0]) <= config.SELF_INTERSECT_GRID:
            result.pop()
        result.extend(seg)

    seq = pieces + [pieces[0]]
    run, last_t = None, None
    for idx, pc in enumerate(seq):
        sentinel = idx == len(seq) - 1
        if pc["on"]:
            ts = pc["t"] if last_t is None else min(
                (pc["t"] - 1.0, pc["t"], pc["t"] + 1.0),
                key=lambda x: abs(x - last_t))
            te = ts + pc["dt"]
            last_t = te
            if run is None:
                run = {"pm": pc["pm"], "qm": pc["qm"], "ts": ts, "te": te}
            else:
                run["qm"], run["te"] = pc["qm"], te
        else:
            if run is not None:
                close_run(run)
                run = None
            last_t = None
            if not sentinel:
                for pt in (pc["pm"], pc["qm"]):
                    if not result or _dist(result[-1], pt) > config.SELF_INTERSECT_GRID:
                        result.append(list(pt))
    if run is not None:
        close_run(run)

    if len(result) > 1 and _dist(result[0], result[-1]) <= config.SELF_INTERSECT_GRID:
        result = result[:-1]
    return result


def _classify_piece(p0, p1, bclosed, bcum, btot, tol):
    """子段是否沿基环弧段贴合 → {on,t,dt}；t 起点模参数，dt 短弧有向差。"""
    pr0 = _arc_param(p0, bclosed, bcum, btot, tol)
    pr1 = _arc_param(p1, bclosed, bcum, btot, tol)
    if not pr0 or not pr1:
        return {"on": False, "t": None, "dt": None}
    t0, _ = pr0
    t1, _ = pr1
    dt = t1 - t0
    if dt > 0.5:
        dt -= 1.0
    elif dt < -0.5:
        dt += 1.0
    if abs(dt) * btot > _dist(p0, p1) + tol:
        return {"on": False, "t": None, "dt": None}  # 内部分割弦：弧长≫弦长
    for k in (0.25, 0.5, 0.75):
        q = _point_at(bclosed, bcum, btot, (t0 + dt * k) % 1.0)
        px = p0[0] + (p1[0] - p0[0]) * k
        py = p0[1] + (p1[1] - p0[1]) * k
        if _dist(q, (px, py)) > tol:
            return {"on": False, "t": None, "dt": None}
    return {"on": True, "t": t0, "dt": dt}
