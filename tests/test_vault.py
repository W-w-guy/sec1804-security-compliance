"""AC1 / AC3：保险箱可用、库内无明文、轮换后旧数据可解、无权限或无理由被拒且写审计。"""
import base64
import json
import re

import pytest

from app.errors import Forbidden
from app.rbac import Principal


def test_tokenize_detokenize_roundtrip(c):
    v = c.vault
    tok = v.tokenize("手机号", "13800138000", "tester", "admin")["token"]
    got = v.detokenize(tok, "客服回访核验", Principal("adm", "admin", all_cities=True))
    assert got["value"] == "13800138000"
    assert re.match(r"^vt_[A-Za-z0-9_-]{20,}$", tok)


def test_plaintext_never_in_db(c):
    v = c.vault
    v.tokenize("姓名", "王小二", "tester", "admin")
    v.tokenize("手机号", "13800138000", "tester", "admin")
    v.tokenize("身份证号", "44030519900101123X", "tester", "admin")
    dump = json.dumps([c.db.query("SELECT * FROM vault_items"),
                       c.db.query("SELECT * FROM audit_log")], ensure_ascii=False)
    for plain in ("13800138000", "王小二", "44030519900101123X"):
        assert plain not in dump
    # 密文可解，但不是明文直存
    for row in c.db.query("SELECT * FROM vault_items"):
        assert len(row["ciphertext"]) > 10


def test_rotation_old_data_still_decrypts(c):
    v = c.vault
    tok = v.tokenize("手机号", "13900139000", "tester", "admin")["token"]
    old_version = c.db.one("SELECT key_version FROM vault_items WHERE token=?", (tok,))["key_version"]
    res = v.rotate("adm", reencrypt=False)
    assert res["to"] > old_version
    assert v.detokenize(tok, "轮换后校验", Principal("adm", "admin", all_cities=True))["value"] == "13900139000"
    # 再轮换 + 重加密一遍，旧 token 仍可解
    v.rotate("adm", reencrypt=True)
    assert v.detokenize(tok, "重加密校验", Principal("adm", "admin", all_cities=True))["value"] == "13900139000"


def test_detokenize_denied_without_permission_and_audited(c):
    v = c.vault
    tok = v.tokenize("手机号", "13800138000", "tester", "admin")["token"]
    with pytest.raises(Forbidden) as ei:
        v.detokenize(tok, "想看看", Principal("rec1", "recruiter"))
    assert ei.value.code == "missing_permission"
    rows = c.db.query("SELECT action, detail FROM audit_log WHERE action='vault.detokenize.denied'")
    assert rows and "missing_permission" in rows[-1]["detail"]


def test_detokenize_denied_without_reason_and_audited(c):
    v = c.vault
    tok = v.tokenize("手机号", "13800138000", "tester", "admin")["token"]
    with pytest.raises(Forbidden) as ei:
        v.detokenize(tok, "  ", Principal("adm", "admin", all_cities=True))
    assert ei.value.code == "reason_required"
    rows = c.db.query("SELECT detail FROM audit_log WHERE action='vault.detokenize.denied'")
    assert rows and "reason_too_short" in rows[-1]["detail"]


def test_mask_rules_per_contract(c):
    tok = c.vault.tokenize("手机号", "13800138000", "t", "admin")["token"]
    assert c.vault.masked_of(tok)["masked"] == "138****8000"
    tok2 = c.vault.tokenize("姓名", "王小二", "t", "admin")["token"]
    assert c.vault.masked_of(tok2)["masked"] == "王**"


def test_same_value_same_token(c):
    v = c.vault
    a = v.tokenize("手机号", "13800138000", "t", "admin")["token"]
    b = v.tokenize("手机号", "13800138000", "t", "admin")["token"]
    assert a == b


def test_aad_binds_type_ciphertext_not_cross_decryptable(c):
    v = c.vault
    tok = v.tokenize("手机号", "13800138000", "t", "admin")["token"]
    row = c.db.one("SELECT * FROM vault_items WHERE token=?", (tok,))
    from cryptography.exceptions import InvalidTag
    with pytest.raises(InvalidTag):
        c.cipher.decrypt("name", int(row["key_version"]),
                         base64.b64decode(row["nonce"]), base64.b64decode(row["ciphertext"]))
