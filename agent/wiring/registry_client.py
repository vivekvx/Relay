# Thin HTTP client over the hosted registry's existing API
# (registry/api/*_routes.py) — no business logic, just request/response
# shaping and rejection-outcome surfacing. This is the only module that
# knows the registry is HTTP.

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any

import httpx


class RegistryRejection(Exception):
    """Raised for any non-2xx registry response whose body carries
    {"detail": {"outcome": ..., "message": ...}} — same rejection shape
    relay_service/grant_service already use."""

    def __init__(self, status_code: int, outcome: str, message: str):
        self.status_code = status_code
        self.outcome = outcome
        self.message = message
        super().__init__(f"{outcome}: {message}")


@dataclass
class RegistryClient:
    base_url: str
    http: httpx.Client

    @classmethod
    def create(cls, base_url: str, timeout: float = 10.0) -> "RegistryClient":
        return cls(base_url=base_url.rstrip("/"), http=httpx.Client(timeout=timeout))

    def _raise_for_rejection(self, response: httpx.Response) -> None:
        if response.status_code < 400:
            return
        try:
            detail = response.json()["detail"]
            outcome, message = detail["outcome"], detail["message"]
        except (ValueError, KeyError, TypeError):
            outcome, message = "http_error", response.text
        raise RegistryRejection(response.status_code, outcome, message)

    # ---- identities ----

    def register_identity(self, handle: str, public_key_hex: str, x25519_public_key_hex: str) -> None:
        response = self.http.post(
            f"{self.base_url}/identities",
            json={
                "handle": handle,
                "public_key_hex": public_key_hex,
                "x25519_public_key_hex": x25519_public_key_hex,
            },
        )
        self._raise_for_rejection(response)

    def get_identity(self, handle: str) -> dict[str, Any] | None:
        response = self.http.get(f"{self.base_url}/identities/{handle}")
        if response.status_code == 404:
            return None
        self._raise_for_rejection(response)
        return response.json()

    # ---- relay ----

    def submit_relay(
        self, payload_hex: str, signature_hex: str, content_ciphertext_hex: str | None = None
    ) -> str:
        response = self.http.post(
            f"{self.base_url}/relay",
            json={
                "payload_hex": payload_hex,
                "signature_hex": signature_hex,
                "content_ciphertext_hex": content_ciphertext_hex,
            },
        )
        self._raise_for_rejection(response)
        return response.json()["id"]

    def fetch_pending(self, recipient: str) -> list[dict[str, Any]]:
        response = self.http.get(f"{self.base_url}/relay/pending/{recipient}")
        self._raise_for_rejection(response)
        return response.json()

    # ---- grants ----

    def create_grant(
        self,
        grantor: str,
        grantee: str,
        grant_type: str,
        scope_capsule_ids: list[str],
        timestamp: int,
        nonce: str,
        signature_hex: str,
        expires_at: datetime | None = None,
    ) -> str:
        response = self.http.post(
            f"{self.base_url}/grants",
            json={
                "grantor": grantor,
                "grantee": grantee,
                "grant_type": grant_type,
                "scope_capsule_ids": scope_capsule_ids,
                "expires_at": expires_at.isoformat() if expires_at else None,
                "timestamp": timestamp,
                "nonce": nonce,
                "signature_hex": signature_hex,
            },
        )
        self._raise_for_rejection(response)
        return response.json()["id"]

    def revoke_grant(self, grant_id: str, timestamp: int, nonce: str, signature_hex: str) -> None:
        response = self.http.post(
            f"{self.base_url}/grants/revoke",
            json={
                "grant_id": grant_id,
                "timestamp": timestamp,
                "nonce": nonce,
                "signature_hex": signature_hex,
            },
        )
        self._raise_for_rejection(response)

    def list_grants(self, grantee: str) -> list[dict[str, Any]]:
        response = self.http.get(f"{self.base_url}/grants", params={"grantee": grantee})
        self._raise_for_rejection(response)
        return response.json()
