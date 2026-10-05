"""撤销风险告知测试：已签收 ACCEPT 归档受撤销波及时的告知生成、查询与确认。

覆盖：告知生成（撤销批次/受影响目标/链上命中编号/序位从 1）、同包同批只记
一份、未签收/REJECT 不生成、两次撤销两份告知、多级链命中被撤销与级联失效
证书、定稿邀请编号+一次性密钥查询与确认、密钥过期不影响已签收后的查询与
确认、错误密钥/未知邀请/未知告知/跨邀请告知拒绝、重复确认返回首次确认
时间、签收与撤销并发按提交次序（先签收生成告知、先撤销 ACCEPT 拒绝且无
告知）、并发确认恰一份首次、既有归档/签收/撤销接口契约与根索引不变。

直接压 HTTP 接口（urllib，无第三方依赖）。服务需已启动。
用法: python3 scripts/notice_checks.py [base_url] [management_key]

依赖：DELIVERY_MANAGEMENT_KEY 默认为 test-admin-key（与其余 *_checks.py 相同，
直接对按默认/测试配置启动的服务运行即可）。
"""
import json
import sys
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8080"
MK = sys.argv[2] if len(sys.argv) > 2 else "test-admin-key"
results = []


def call(method, path, body=None, key=None):
    data = json.dumps(body).encode() if body is not None else None
    headers = {"Content-Type": "application/json"}
    if key is not None:
        headers["X-Management-Key"] = key
    req = urllib.request.Request(BASE + path, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def check(name, cond, detail=""):
    results.append((name, cond, detail))
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}" + ("" if cond else f" :: {detail}"))


def err_code(body):
    return body.get("error", {}).get("code")


TZ = timezone(timedelta(hours=8))
t0 = datetime(2026, 2, 1, 0, 0, tzinfo=TZ)
_seq = [0]


def nxt(prefix):
    _seq[0] += 1
    return f"{prefix}-{_seq[0]}"


def iso(offset_days=0):
    return (t0 + timedelta(days=offset_days)).isoformat()


def future(seconds=3600):
    return (datetime.now(timezone.utc) + timedelta(seconds=seconds)).isoformat()


def ref(no):
    return call("POST", "/api/v1/reference-certificates", {
        "cert_no": no, "device_id": "DEV-" + no, "device_name": "基准" + no,
        "valid_from": iso(0), "valid_to": iso(1500), "calibrated_at": iso(0)})


def cal(no, parent):
    return call("POST", "/api/v1/certificates", {
        "cert_no": no, "device_id": "DEV-" + no, "device_name": "仪表" + no,
        "valid_from": iso(2), "valid_to": iso(1200), "calibrated_at": iso(3),
        "conclusion": "PASS", "parent_cert_no": parent})


def make_chain(tag, depth=2):
    """基准 + depth-1 张普通证书链；返回 [根, ..., 末级] 编号列表。"""
    r = nxt("RC-" + tag)
    check(f"[{tag}] 基准 201", ref(r)[0] == 201)
    nos = [r]
    for _ in range(depth - 1):
        c = nxt("CC-" + tag)
        check(f"[{tag}] 普通证书 201", cal(c, nos[-1])[0] == 201)
        nos.append(c)
    return nos


def make_archive(tag, cert_nos):
    no = nxt("DA-" + tag)
    s, _ = call("POST", "/api/v1/delivery-archives", {"archive_no": no, "cert_nos": cert_nos})
    check(f"[{tag}] 归档包 {no} 201", s == 201, f"got {s}")
    return no


def make_invite(archive_no, recipient="测试客户", deadline=None):
    s, inv = call("POST", "/api/v1/delivery-invitations", {
        "archive_no": archive_no, "recipient": recipient,
        "deadline": deadline or iso(1000)}, key=MK)
    check(f"邀请 {archive_no} 201", s == 201, f"got {s}")
    return inv


def sign(inv, decision="ACCEPT", reason=None):
    body = {"invitation_no": inv["invitation_no"], "key": inv["key"], "decision": decision}
    if reason is not None:
        body["reason"] = reason
    return call("POST", "/api/v1/delivery-receipts", body)


def query_notices(inv, key=None):
    return call("POST", "/api/v1/delivery-risk-notices/query",
                {"invitation_no": inv["invitation_no"], "key": key or inv["key"]})


def ack_notice(inv, notice_id, key=None):
    return call("POST", "/api/v1/delivery-risk-notices/acknowledge",
                {"invitation_no": inv["invitation_no"], "key": key or inv["key"],
                 "notice_id": notice_id})


def revoke(cert_no, reason="质量复核发现超差"):
    return call("POST", f"/api/v1/certificates/{cert_no}/revoke",
                {"reason": reason, "operator": "qa"})


def hits_of(notice, cert_no):
    """告知中指定目标的链上命中编号列表（[(cert_no, chain_position), ...]）。"""
    for t in notice["affected_targets"]:
        if t["cert_no"] == cert_no:
            return [(h["cert_no"], h["chain_position"]) for h in t["chain_hits"]]
    return None


# ---------------------------------------------------------------------------
print("== 0. 前置数据：多条独立链（签收/未签收/拒收/多级链） ==")
# 链 A：两级普通证书，归档 [cA1, cA2] 并 ACCEPT
rA, cA1, cA2 = make_chain("NA", 3)
aA = make_archive("NA", [cA1, cA2])
invA = make_invite(aA, recipient="客户甲")
s, receiptA = sign(invA)
check("链A ACCEPT 定稿 201", s == 201 and receiptA["decision"] == "ACCEPT", f"got {s}")

# 链 B：归档并创建邀请但不签收
rB, cB = make_chain("NB", 2)
aB = make_archive("NB", [cB])
invB = make_invite(aB, recipient="未签收客户")

# 链 C：归档并 REJECT
rC, cC = make_chain("NC", 2)
aC = make_archive("NC", [cC])
invC = make_invite(aC, recipient="拒收客户")
s, receiptC = sign(invC, "REJECT", "开箱发现封条破损")
check("链C REJECT 定稿 201", s == 201 and receiptC["decision"] == "REJECT", f"got {s}")

# 链 D：三级链（基准 -> 中间 -> 末级），归档末级并 ACCEPT
rD, mD, cD = make_chain("ND", 3)
aD = make_archive("ND", [cD])
invD = make_invite(aD, recipient="客户丁")
s, _ = sign(invD)
check("链D ACCEPT 定稿 201", s == 201, f"got {s}")

# ---------------------------------------------------------------------------
print("== A. 撤销波及已签收归档 -> 生成告知（批次/受影响目标/链上命中编号） ==")
s, rev = revoke(rA)
check("撤销基准 200", s == 200, f"got {s}")
check("撤销响应契约不变（batch_id/revoked/affected_count/affected）",
      s == 200 and rev["batch_id"] and rev["revoked"]["cert_no"] == rA
      and rev["affected_count"] == 2 and len(rev["affected"]) == 2,
      json.dumps({k: rev.get(k) for k in ("batch_id", "affected_count")}))
batchA = rev["batch_id"]

s, q = query_notices(invA)
check("查询告知 200", s == 200, f"got {s}")
check("查询响应回显邀请/归档/收件人",
      q["invitation_no"] == invA["invitation_no"] and q["archive_no"] == aA
      and q["recipient"] == "客户甲", json.dumps(q, ensure_ascii=False)[:200])
check("恰好一份告知", len(q["notices"]) == 1, str(len(q["notices"])))
nA = q["notices"][0]
check("告知列出撤销批次与被撤销证书",
      nA["batch_id"] == batchA and nA["revoked_cert_no"] == rA and bool(nA["revoked_at"]))
check("告知含生成时刻且尚未确认",
      bool(nA["created_at"]) and nA["acknowledged_at"] is None)
check("受影响目标按交付序位列出",
      [t["cert_no"] for t in nA["affected_targets"]] == [cA1, cA2]
      and [t["delivery_position"] for t in nA["affected_targets"]] == [1, 2],
      json.dumps(nA["affected_targets"], ensure_ascii=False))
check("链上命中编号及序位（冻结链首为 1；根撤销致整链命中）",
      hits_of(nA, cA1) == [(rA, 1), (cA1, 2)]
      and hits_of(nA, cA2) == [(rA, 1), (cA1, 2), (cA2, 3)],
      json.dumps(nA["affected_targets"], ensure_ascii=False))

# ---------------------------------------------------------------------------
print("== B. 未签收 / REJECT 的归档不生成告知 ==")
s, _ = revoke(rB)
check("撤销链B基准 200", s == 200)
s, _ = revoke(rC)
check("撤销链C基准 200", s == 200)
s, qB = query_notices(invB)
check("未签收归档无告知", s == 200 and qB["notices"] == [], f"{s}")
s, qC = query_notices(invC)
check("REJECT 归档无告知", s == 200 and qC["notices"] == [], f"{s}")

# ---------------------------------------------------------------------------
print("== C. 多级链：命中编号含被撤销证书与级联失效证书 ==")
s, rev = revoke(mD)
check("撤销链D中间证书 200", s == 200, f"got {s}")
batchD1 = rev["batch_id"]
s, q = query_notices(invD)
check("链D 一份告知", s == 200 and len(q["notices"]) == 1)
nD1 = q["notices"][0]
check("告知批次匹配", nD1["batch_id"] == batchD1 and nD1["revoked_cert_no"] == mD)
check("受影响目标仅末级证书",
      [t["cert_no"] for t in nD1["affected_targets"]] == [cD]
      and nD1["affected_targets"][0]["delivery_position"] == 1)
check("链上命中编号含被撤销证书与级联失效证书（序位 2、3）",
      hits_of(nD1, cD) == [(mD, 2), (cD, 3)],
      json.dumps(nD1["affected_targets"], ensure_ascii=False))

# ---------------------------------------------------------------------------
print("== D. 同包同批只记一份；重复查询结果稳定 ==")
s, q2 = query_notices(invA)
check("重复查询仍一份且内容不变",
      s == 200 and len(q2["notices"]) == 1 and q2["notices"][0] == nA, f"{s}")

# ---------------------------------------------------------------------------
print("== E. 两次撤销（不同批次）波及同一包 -> 两份告知 ==")
s, rev = revoke(rD)
check("撤销链D基准 200", s == 200, f"got {s}")
batchD2 = rev["batch_id"]
s, q = query_notices(invD)
check("链D 现有两份告知", s == 200 and len(q["notices"]) == 2, str(len(q.get("notices", []))))
check("两份告知按生成顺序对应两个撤销批次",
      [n["batch_id"] for n in q["notices"]] == [batchD1, batchD2]
      and q["notices"][0]["notice_id"] < q["notices"][1]["notice_id"],
      json.dumps([n["batch_id"] for n in q.get("notices", [])]))
check("第二份告知命中基准（冻结链序位 1）",
      hits_of(q["notices"][1], cD) == [(rD, 1)],
      json.dumps(q["notices"][1]["affected_targets"], ensure_ascii=False))

# ---------------------------------------------------------------------------
print("== F. 认证与边界：未知邀请/错误密钥/未知告知/跨邀请告知 ==")
s, e = call("POST", "/api/v1/delivery-risk-notices/query",
            {"invitation_no": "DINV-0000000000000000", "key": "whatever"})
check("查询未知邀请 404", s == 404 and err_code(e) == "invitation_not_found", f"{s} {err_code(e)}")
s, e = query_notices(invA, key="bad-secret")
check("查询错误密钥 401", s == 401 and err_code(e) == "invalid_receipt_key", f"{s} {err_code(e)}")
s, e = call("POST", "/api/v1/delivery-risk-notices/acknowledge",
            {"invitation_no": "DINV-0000000000000000", "key": "whatever", "notice_id": 1})
check("确认未知邀请 404", s == 404 and err_code(e) == "invitation_not_found", f"{s} {err_code(e)}")
s, e = ack_notice(invA, nA["notice_id"], key="bad-secret")
check("确认错误密钥 401", s == 401 and err_code(e) == "invalid_receipt_key", f"{s} {err_code(e)}")
s, e = ack_notice(invA, 999999999)
check("确认未知告知 404", s == 404 and err_code(e) == "notice_not_found", f"{s} {err_code(e)}")
s, e = ack_notice(invA, nD1["notice_id"])
check("跨邀请确认他人归档的告知 404",
      s == 404 and err_code(e) == "notice_not_found", f"{s} {err_code(e)}")

# ---------------------------------------------------------------------------
print("== G. 确认：首次 201；重复确认返回首次确认时间 ==")
s, ack1 = ack_notice(invA, nA["notice_id"])
check("首次确认 201", s == 201, f"got {s}")
check("确认回执为同一份告知且写入确认时刻",
      ack1["notice_id"] == nA["notice_id"] and ack1["batch_id"] == batchA
      and bool(ack1["acknowledged_at"]), json.dumps(ack1, ensure_ascii=False)[:200])
first_ack_at = ack1["acknowledged_at"]
s, ack2 = ack_notice(invA, nA["notice_id"])
check("重复确认 200", s == 200, f"got {s}")
check("重复确认返回首次确认时间且内容不变",
      ack2["acknowledged_at"] == first_ack_at and ack2 == ack1,
      f"{ack2.get('acknowledged_at')} != {first_ack_at}")
s, q = query_notices(invA)
check("查询回显确认时刻",
      s == 200 and q["notices"][0]["acknowledged_at"] == first_ack_at, f"{s}")

# ---------------------------------------------------------------------------
print("== H. 密钥过期不影响已签收后的查询与确认 ==")
rH, cH = make_chain("NH", 2)
aH = make_archive("NH", [cH])
invH = make_invite(aH, recipient="过期客户", deadline=future(2))
s, _ = sign(invH)
check("截止前 ACCEPT 201", s == 201, f"got {s}")
time.sleep(2.3)  # 邀请截止（密钥过期）
s, rev = revoke(rH)
check("撤销链H基准 200", s == 200)
s, q = query_notices(invH)
check("过期后仍可查询告知", s == 200 and len(q["notices"]) == 1, f"{s}")
s, ack = ack_notice(invH, q["notices"][0]["notice_id"])
check("过期后仍可确认告知 201", s == 201 and bool(ack["acknowledged_at"]), f"got {s}")

# ---------------------------------------------------------------------------
print("== I. 并发：签收与撤销按提交次序（先签收生成告知，先撤销无告知） ==")
N = 16
chains = []
for i in range(N):
    rr, cc = make_chain(f"NR{i}", 2)
    aa = make_archive(f"NR{i}", [cc])
    ii = make_invite(aa)
    chains.append((rr, cc, aa, ii))
barrier = threading.Barrier(N * 2)
res = {}
rlock = threading.Lock()


def race_accept(idx, ii):
    barrier.wait()
    s, b = sign(ii)
    with rlock:
        res[idx] = (s, b.get("error", {}).get("code"))


def race_revoke(idx, rr):
    barrier.wait()
    s, b = revoke(rr, "并发撤销")
    with rlock:
        res[(idx, "rv")] = s


threads = []
for idx, (rr, cc, aa, ii) in enumerate(chains):
    threads.append(threading.Thread(target=race_accept, args=(idx, ii)))
    threads.append(threading.Thread(target=race_revoke, args=(idx, rr)))
for t in threads:
    t.start()
for t in threads:
    t.join()

n_signed = n_blocked = 0
for idx, (rr, cc, aa, ii) in enumerate(chains):
    check(f"[{idx}] 撤销恒成功", res[(idx, "rv")] == 200, str(res[(idx, "rv")]))
    a_status, a_code = res[idx]
    s, q = query_notices(ii)
    if a_status == 201:
        n_signed += 1
        check(f"[{idx}] 先签收：生成一份告知", s == 200 and len(q["notices"]) == 1,
              f"{s} notices={len(q.get('notices', []))}")
    else:
        n_blocked += 1
        check(f"[{idx}] 先撤销：ACCEPT 422 且无告知",
              a_status == 422 and a_code == "receipt_targets_revoked"
              and s == 200 and q["notices"] == [],
              f"{a_status} {a_code} notices={len(q.get('notices', []))}")
check(f"并发次序两类结果均出现且总数守恒（{n_signed} 先签收 / {n_blocked} 先撤销）",
      n_signed + n_blocked == N and n_signed > 0 and n_blocked > 0,
      f"{n_signed}+{n_blocked}!={N}")

# ---------------------------------------------------------------------------
print("== J. 并发确认同一告知：恰一份首次，其余返回首次确认时间 ==")
rJ, cJ = make_chain("NJ", 2)
aJ = make_archive("NJ", [cJ])
invJ = make_invite(aJ)
s, _ = sign(invJ)
check("链J ACCEPT 201", s == 201)
s, rev = revoke(rJ)
s, q = query_notices(invJ)
noticeJ = q["notices"][0]["notice_id"]
M = 10
bar = threading.Barrier(M)
outs = []
olk = threading.Lock()


def ack_worker():
    bar.wait()
    s, b = ack_notice(invJ, noticeJ)
    with olk:
        outs.append((s, b))


ths = [threading.Thread(target=ack_worker) for _ in range(M)]
for t in ths:
    t.start()
for t in ths:
    t.join()
codes = sorted(s for s, _ in outs)
check("并发确认：1×201 其余 200", codes == [200] * (M - 1) + [201], str(codes))
ack_ats = {b.get("acknowledged_at") for _, b in outs}
check("并发确认：确认时刻全同（首次确认时间）", len(ack_ats) == 1 and None not in ack_ats,
      str(ack_ats))

# ---------------------------------------------------------------------------
print("== K. 既有接口契约保持 ==")
s, snap = call("GET", f"/api/v1/delivery-archives/{aA}")
frozen = [n["certificate"]["status"] for n in snap["items"][0]["chain"]["nodes"]]
check("归档快照链状态仍冻结为 ACTIVE", s == 200 and frozen == ["ACTIVE"] * len(frozen),
      str(frozen))
s, q = call("GET", f"/api/v1/delivery-archives/{aA}/receipt", key=MK)
check("定稿记录不被撤销与告知改写",
      s == 200 and q["decision"] == "ACCEPT" and q == receiptA, f"{s}")
s, cert = call("GET", f"/api/v1/certificates/{cA1}")
check("证书详情仍返回当前状态（INVALID）", s == 200 and cert["status"] == "INVALID", f"{s}")
s, idx = call("GET", "/")
eps = idx["endpoints"]
check("根索引列出新端点", s == 200
      and any(x.endswith("/api/v1/delivery-risk-notices/query") for x in eps)
      and any(x.endswith("/api/v1/delivery-risk-notices/acknowledge") for x in eps))

# ---------------------------------------------------------------------------
n_pass = sum(1 for _, ok, _ in results if ok)
n_fail = len(results) - n_pass
print(f"\n结果: PASS={n_pass} FAIL={n_fail}")
sys.exit(1 if n_fail else 0)
