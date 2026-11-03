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
        self.db.insert("vault_items", {
            "token": token, "item_type": item_type, "key_version": version,
            "nonce": base64.b64encode(nonce).decode(),
            "ciphertext": base64.b64encode(ct).decode(),
            "created_at": _ts(now), "rotated_from": None})
        self.audit.append(actor, role, "vault.tokenize", target=token,
                          detail={"type": item_type, "key_version": version}, now=now)
        return token

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

    def stats(self) -> dict:
        rows = self.db.query("SELECT item_type, COUNT(*) AS c FROM vault_items GROUP BY item_type")
        return {r["item_type"]: int(r["c"]) for r in rows}


def _ts(t: float | None) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() if t is None else t))
