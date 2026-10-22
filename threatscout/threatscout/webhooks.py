from __future__ import annotations

from typing import Any

import httpx


async def dispatch_webhook(kind: str, url: str, token: str, payload: dict[str, Any]) -> str:
    kind = (kind or "generic").lower()
    timeout = httpx.Timeout(12.0)
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
        if kind == "splunk":
            headers = {"Content-Type": "application/json"}
            if token:
                headers["Authorization"] = f"Splunk {token}"
            r = await client.post(url, json={"event": payload, "sourcetype": "threatscout"}, headers=headers)
        elif kind in {"elastic", "elasticsearch"}:
            headers = {"Content-Type": "application/json"}
            if token:
                headers["Authorization"] = f"ApiKey {token}" if not token.lower().startswith("basic ") else token
            r = await client.post(url, json=payload, headers=headers)
        else:
            headers = {"Content-Type": "application/json"}
            if token:
                headers["Authorization"] = f"Bearer {token}"
            r = await client.post(url, json=payload, headers=headers)
        r.raise_for_status()
        return f"HTTP {r.status_code}"
