"""统一错误体 {code, message}（契约 v1）。"""
from __future__ import annotations


class ApiError(Exception):
    status = 400
    code = "bad_request"

    def __init__(self, message: str, code: str | None = None, status: int | None = None):
        super().__init__(message)
        self.message = message
        if code:
            self.code = code
        if status:
            self.status = status

    def body(self) -> dict:
        return {"code": self.code, "message": self.message}


class Unauthorized(ApiError):
    status, code = 401, "unauthorized"


class Forbidden(ApiError):
    status, code = 403, "forbidden"


class NotFound(ApiError):
    status, code = 404, "not_found"


class Conflict(ApiError):
    status, code = 409, "conflict"
