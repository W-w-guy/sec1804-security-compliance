"""KMS 适配层：密钥与数据分离，支持轮换；后端可替换（file / HashiCorp Vault KV v2）。

- 数据侧只保存 key_version + nonce + ciphertext，从不保存密钥。
- rotate() 生成新版本，旧版本仍保留以便解密历史数据。
- 本地 file 后端用 0600 权限的密钥文件；Vault 后端走 KV v2 HTTP 接口（可替换）。
"""
from __future__ import annotations
import base64
import json
import os
import secrets
import threading
import time
from abc import ABC, abstractmethod

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class KMS(ABC):
    _index_lock: threading.RLock | None = None

    @abstractmethod
    def current_version(self) -> int: ...

    @abstractmethod
    def key(self, version: int) -> bytes: ...

    @abstractmethod
    def rotate(self) -> int: ...

    def current_key(self) -> bytes:
        return self.key(self.current_version())

    @abstractmethod
    def _load(self) -> dict: ...

    @abstractmethod
    def _save(self, state: dict) -> None: ...

    def stable_key(self) -> bytes:
        """用于生成稳定 token 的索引密钥：不随轮换变化，保证同一值 token 稳定。

        并发首用是有坑的：两个线程同时发现"没有 index_key"，各自生成一把再写，
        后写者覆盖先写者 —— 于是同一个手机号在不同线程下得到不同 token。
        （B2 轮实测：32 线程并发 tokenize 同一号码，出现 3 个不同 token。
          Windows 上不并发就永远看不到。）
        处理：① 有 KMS_SECRET 时由 secret 派生，天然确定；
              ② 没有 secret 时加锁 get-or-create，并在写完后**再读一次以落盘值为准**。
        """
        st = self._load()
        if "index_key" in st:
            return base64.b64decode(st["index_key"])
        if self._index_lock is None:
            self._index_lock = threading.RLock()
        with self._index_lock:
            st = self._load()                       # double-check
            if "index_key" not in st:
                if isinstance(self, FileKMS) and self.secret:
                    import hashlib
                    raw = hashlib.sha256(f"{self.secret}:index".encode()).digest()
                else:
                    raw = secrets.token_bytes(32)
                st["index_key"] = base64.b64encode(raw).decode()
                self._save(st)
            st = self._load()                       # 以落盘为准（多进程可能刚被改）
            return base64.b64decode(st["index_key"])


class FileKMS(KMS):
    def __init__(self, kms_dir: str, secret: str = ""):
        self.dir = kms_dir
        self.secret = secret
        self._lock = threading.RLock()
        os.makedirs(self.dir, exist_ok=True)

    @property
    def path(self) -> str:
        return os.path.join(self.dir, "keys.json")

    def _load(self) -> dict:
        with self._lock:
            if not os.path.exists(self.path):
                st = {"current": 1, "keys": {"1": base64.b64encode(self._material(1)).decode()}}
                self._save(st)
                return st
            with open(self.path, "r", encoding="utf-8") as fh:
                return json.load(fh)

    def _save(self, state: dict) -> None:
        with self._lock:
            os.makedirs(self.dir, exist_ok=True)
            tmp = self.path + ".tmp"
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(state, fh)
            os.replace(tmp, self.path)

    def _material(self, version: int) -> bytes:
        """无外部 secret 时用进程随机；有 secret 时由 secret+version 派生（可复现）。"""
        if self.secret:
            import hashlib
            return hashlib.sha256(f"{self.secret}:{version}".encode()).digest()
        return secrets.token_bytes(32)

    def current_version(self) -> int:
        return int(self._load()["current"])

    def key(self, version: int) -> bytes:
        st = self._load()
        raw = st["keys"].get(str(version))
        if raw is None:
            raise KeyError(f"unknown key version {version}")
        return base64.b64decode(raw)

    def rotate(self) -> int:
        with self._lock:
            st = self._load()
            new = int(st["current"]) + 1
            st["keys"][str(new)] = base64.b64encode(self._material(new)).decode()
            st["current"] = new
            st["rotated_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            self._save(st)
            return new


class VaultKMS(KMS):  # pragma: no cover - 需真实 Vault，接口与 FileKMS 一致
    """HashiCorp Vault KV v2 适配层占位实现（同接口，可替换）。"""

    def __init__(self, addr: str, token: str, mount: str = "secret", path: str = "sec1804"):
        self.addr, self.token, self.mount, self.path = addr.rstrip("/"), token, mount, path

    def _req(self, method: str, url: str, payload: dict | None = None) -> dict:
        import urllib.request
        data = json.dumps(payload).encode() if payload is not None else None
        req = urllib.request.Request(url, data=data, method=method,
                                     headers={"X-Vault-Token": self.token,
                                              "Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            return json.loads(resp.read() or b"{}")

    def _load(self) -> dict:
        """读取密钥状态；首次不存在（Vault 返回 404）时**自举**出 v1 密钥。

        踩过的坑：原实现读取失败就返回 {"current":1,"keys":{}}，
        随后 key(1) 直接 KeyError: '1' —— 也就是"Vault 后端从第一次用就是坏的"，
        而 file 后端一切正常，所以本地测试永远发现不了。
        """
        u = f"{self.addr}/v1/{self.mount}/data/{self.path}"
        try:
            st = self._req("GET", u)["data"]["data"]
            if st.get("keys"):
                return st
        except Exception:
            st = {}
        st = {"current": int(st.get("current", 1)),
              "keys": dict(st.get("keys") or {})}
        if "1" not in st["keys"]:
            st["keys"]["1"] = base64.b64encode(secrets.token_bytes(32)).decode()
            st["current"] = 1
            self._save(st)
        return st

    def _save(self, state: dict) -> None:
        self._req("POST", f"{self.addr}/v1/{self.mount}/data/{self.path}", {"data": state})

    def current_version(self) -> int:
        return int(self._load().get("current", 1))

    def key(self, version: int) -> bytes:
        raw = self._load()["keys"][str(version)]
        return base64.b64decode(raw)

    def rotate(self) -> int:
        st = self._load()
        new = int(st.get("current", 1)) + 1
        st.setdefault("keys", {})[str(new)] = base64.b64encode(secrets.token_bytes(32)).decode()
        st["current"] = new
        self._save(st)
        return new


def build_kms(settings) -> KMS:
    if settings.kms_backend == "vault":
        return VaultKMS(os.environ.get("VAULT_ADDR", "http://vault:8200"),
                        os.environ.get("VAULT_TOKEN", "root"))
    return FileKMS(settings.kms_dir, settings.kms_secret)


class FieldCipher:
    """字段级 AES-256-GCM；AAD 绑定 item_type，防止密文跨字段重放。"""

    def __init__(self, kms: KMS):
        self.kms = kms

    def encrypt(self, item_type: str, value: str) -> tuple[int, bytes, bytes]:
        version = self.kms.current_version()
        nonce = secrets.token_bytes(12)
        ct = AESGCM(self.kms.key(version)).encrypt(nonce, value.encode(), item_type.encode())
        return version, nonce, ct

    def decrypt(self, item_type: str, version: int, nonce: bytes, ct: bytes) -> str:
        return AESGCM(self.kms.key(version)).decrypt(nonce, ct, item_type.encode()).decode()
