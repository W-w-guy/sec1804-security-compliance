"""个人信息保险箱：tokenize / detokenize，字段级 AES-256-GCM，密钥可轮换。

- 库里只有 token + 密文 + key_version，明文不落库（用例直查表断言）。
- detokenize 需权限 + 非空理由，拒绝也写审计（AC3）。
- 轮换后旧数据仍可解（key_version 随行存储）。
"""
from __future__ import annotations
import base64
import hmac
import hashlib
import time
import uuid

from app.errors import Forbidden, NotFound
from app.rbac import Principal, require

TYPE_ALIASES = {
    "姓名": "name", "name": "name",
    "手机号": "phone", "phone": "phone", "mobile": "phone",
    "身份证号": "id_card", "id_card": "id_card", "idcard": "id_card",
    "银行卡号": "bank_card", "bank_card": "bank_card",
    "地址": "address", "address": "address",
}
MASK_RULES = {
    "name": lambda v: v[0] + "*" * max(1, len(v) - 1),
    "phone": lambda v: (v[-11:-8] + "****" + v[-4:]) if len(v) >= 11 else v[:1] + "****",
    "id_card": lambda v: v[:6] + "********" + v[-4:] if len(v) >= 10 else "****",
    "bank_card": lambda v: "**** **** **** " + v[-4:],
    "address": lambda v: v[:3] + "****",
}


def norm_type(t: str) -> str:
    k = TYPE_ALIASES.get((t or "").strip())
    if not k:
        raise Forbidden(f"不支持的信息类型: {t}", code="unsupported_type")
    return k


class Vault:
    def __init__(self, db, cipher, kms, audit, settings):
        self.db, self.cipher, self.kms, self.audit, self.settings = db, cipher, kms, audit, settings

    # ---------- 内部 ----------
    def _token_for(self, item_type: str, value: str) -> str:
        digest = hmac.new(self.kms.stable_key(), f"{item_type}\x00{value}".encode(),
                          hashlib.sha256).digest()
        return "vt_" + base64.urlsafe_b64encode(digest).decode().rstrip("=")[:26]

    def _store(self, item_type: str, value: str, actor: str, role: str,
               now: float | None = None) -> str:
        token = self._token_for(item_type, value)
        row = self.db.one("SELECT token FROM vault_items WHERE token=?", (token,))
        if row:
            return token
        version, nonce, ct = self.cipher.encrypt(item_type, value)
        try:
            self._insert_row(token, item_type, version, nonce, ct, now)
        except Exception:
            # 并发同值时另一个线程已经插进去了：token 相同，直接返回即可。
            # （B2 轮实测：32 线程并发 tokenize 同一号码 → UNIQUE constraint failed）
            if self.db.one("SELECT token FROM vault_items WHERE token=?", (token,)):
                return token
            raise
        try:
            self.audit.append(actor, role, "vault.tokenize", target=token,
                              detail={"type": item_type, "key_version": version}, now=now)
        except Exception:
            # 审计写不进去 = 这次写入无法解释，必须撤掉刚插的密文行，
            # 否则库里会出现"有密文、没痕迹"的孤儿（D6 轮实测就是这么留下的）。
            try:
                self.db.execute("DELETE FROM vault_items WHERE token=?", (token,))
            except Exception:                       # noqa: BLE001
                pass
            raise
        return token

    def _insert_row(self, token, item_type, version, nonce, ct, now):
        self.db.insert("vault_items", {
            "token": token, "item_type": item_type, "key_version": version,
            "nonce": base64.b64encode(nonce).decode(),
            "ciphertext": base64.b64encode(ct).decode(),
            "created_at": _ts(now), "rotated_from": None})

    def _load(self, token: str) -> dict:
        row = self.db.one("SELECT * FROM vault_items WHERE token=?", (token,))
        if not row:
            raise NotFound("token 不存在", code="token_not_found")
        return row

    # ---------- 对外 ----------
    def tokenize(self, item_type: str, value: str, actor: str = "system",
                 role: str = "admin", now: float | None = None) -> dict:
        item_type = norm_type(item_type)
        if value is None or str(value) == "":
            raise Forbidden("value 不能为空", code="empty_value")
        # 单个字段值不该有 1 万字符（C5 轮实测 10000 字符被静默接受）：
        # 超长值既不像真实姓名/号码，又会把密文和审计撑大，直接拒绝。
        if len(str(value)) > self.settings.max_value_len:
            raise Forbidden(f"value 超长（上限 {self.settings.max_value_len} 字符）",
                            code="value_too_long")
        token = self._store(item_type, str(value), actor, role, now)
        return {"token": token, "type": item_type, "masked": self._mask(item_type, str(value))}

    def detokenize(self, token: str, reason: str, principal: Principal,
                   now: float | None = None) -> dict:
        # 1) 权限
        if not principal.can("vault.detokenize"):
            self.audit.append(principal.actor, principal.role, "vault.detokenize.denied",
                              target=token, detail={"cause": "missing_permission"}, now=now)
            raise Forbidden(f"角色 {principal.role} 无 detokenize 权限", code="missing_permission")
        # 2) 理由
        if not reason or len(reason.strip()) < self.settings.reason_min_len:
            self.audit.append(principal.actor, principal.role, "vault.detokenize.denied",
                              target=token, detail={"cause": "reason_too_short"}, now=now)
            raise Forbidden(f"必须写明理由（≥{self.settings.reason_min_len} 字）",
                            code="reason_required")
        row = self._load(token)
        value = self.cipher.decrypt(row["item_type"],
                                    int(row["key_version"]),
                                    base64.b64decode(row["nonce"]),
                                    base64.b64decode(row["ciphertext"]))
        self.audit.append(principal.actor, principal.role, "vault.detokenize", target=token,
                          detail={"type": row["item_type"], "reason": reason.strip(),
                                  "key_version": int(row["key_version"])}, now=now)
        return {"token": token, "type": row["item_type"], "value": value}

    def masked_of(self, token: str) -> dict:
        row = self._load(token)
        value = self.cipher.decrypt(row["item_type"], int(row["key_version"]),
                                    base64.b64decode(row["nonce"]),
                                    base64.b64decode(row["ciphertext"]))
        return {"token": token, "type": row["item_type"], "masked": self._mask(row["item_type"], value)}

    def _mask(self, item_type: str, value: str) -> str:
        return MASK_RULES.get(item_type, lambda v: "****")(value)

    def rotate(self, actor: str = "system", reencrypt: bool = False,
               now: float | None = None) -> dict:
        old = self.kms.current_version()
        new = self.kms.rotate()
        moved = 0
        if reencrypt:
            for row in self.db.query("SELECT * FROM vault_items WHERE key_version<>?", (new,)):
                value = self.cipher.decrypt(row["item_type"], int(row["key_version"]),
                                            base64.b64decode(row["nonce"]),
                                            base64.b64decode(row["ciphertext"]))
                version, nonce, ct = self.cipher.encrypt(row["item_type"], value)
                self.db.update("vault_items", {"token": row["token"]},
                               {"key_version": version, "nonce": base64.b64encode(nonce).decode(),
                                "ciphertext": base64.b64encode(ct).decode(),
                                "rotated_from": str(row["key_version"])})
                moved += 1
        self.audit.append(actor, "admin", "kms.rotate", target="kms",
                          detail={"from": old, "to": new, "reencrypted": moved}, now=now)
        return {"from": old, "to": new, "reencrypted": moved}

    def rollback_to(self, version: int, actor: str = "system",
                    now: float | None = None) -> dict:
        """把"当前密钥版本"指针退回旧版本（只回退指针，旧的密钥材料仍在）。

        用途：新版本密钥上线后发现问题，需要立刻回到旧版本继续服务。
        注意这不能撤销"已经用新密钥加密的数据"——那部分仍按各自 key_version 解密，
        所以回滚是安全的（不会让已加密数据变不可解）。
        """
        st = self.kms._load()
        if str(version) not in (st.get("keys") or {}):
            raise Forbidden(f"密钥版本 {version} 不存在，无法回滚", code="key_version_missing")
        old = int(st.get("current", 1))
        st["current"] = int(version)
        self.kms._save(st)
        self.audit.append(actor, "admin", "kms.rollback", target="kms",
                          detail={"from": old, "to": int(version)}, now=now)
        return {"from": old, "to": int(version)}

    def stats(self) -> dict:
        rows = self.db.query("SELECT item_type, COUNT(*) AS c FROM vault_items GROUP BY item_type")
        return {r["item_type"]: int(r["c"]) for r in rows}


def _ts(t: float | None) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() if t is None else t))
