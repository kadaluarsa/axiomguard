"""High-level runtime wrapper for AxiomGuard Python SDK."""

import json
import logging
import threading
import time
import urllib.request
import urllib.error
from typing import Any, Dict, List, Optional

try:
    from axiomguard import Guard as BaseGuard, compute_hash
except ImportError:  # pragma: no cover
    raise ImportError("Install axiomguard first: pip install axiomguard")

logger = logging.getLogger("axiomguard_runtime")


def _retry_request(
    req: urllib.request.Request,
    timeout: float,
    max_retries: int = 3,
    base_delay: float = 0.1,
) -> bytes:
    last_error: Optional[Exception] = None
    for attempt in range(max_retries):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.read()
        except urllib.error.HTTPError as e:
            if e.code >= 500:
                last_error = e
                if attempt < max_retries - 1:
                    time.sleep(base_delay * (2**attempt))
                continue
            raise
        except urllib.error.URLError as e:
            last_error = e
            if attempt < max_retries - 1:
                time.sleep(base_delay * (2**attempt))
            continue
    raise RuntimeError(
        f"Control plane request failed after {max_retries} retries: {last_error}"
    ) from last_error


class RuntimeGuard:
    """AxiomGuard runtime with automatic audit flush and policy refresh loops."""

    def __init__(
        self,
        cp_url: str,
        api_key: str,
        tenant_id: str,
        agent_id: Optional[str] = None,
        timeout: float = 5.0,
        flush_interval_seconds: float = 30.0,
        policy_refresh_interval_seconds: float = 300.0,
    ):
        self._guard = BaseGuard(
            cp_url=cp_url,
            api_key=api_key,
            tenant_id=tenant_id,
            agent_id=agent_id,
            timeout=timeout,
        )
        self._cp_url = cp_url.rstrip("/")
        self._api_key = api_key
        self._tenant_id = tenant_id
        self._agent_id = agent_id or "default"
        self._timeout = timeout
        self._flush_interval = flush_interval_seconds
        self._refresh_interval = policy_refresh_interval_seconds
        self._audit_events: List[Dict[str, Any]] = []
        self._audit_lock = threading.Lock()
        self._policy: Optional[Dict[str, Any]] = None
        self._stop_event = threading.Event()
        self._flush_thread: Optional[threading.Thread] = None
        self._refresh_thread: Optional[threading.Thread] = None

    def start(self) -> None:
        if self._stop_event.is_set():
            self._stop_event.clear()
        self._flush_thread = threading.Thread(target=self._flush_loop, daemon=True)
        self._refresh_thread = threading.Thread(target=self._refresh_loop, daemon=True)
        self._flush_thread.start()
        self._refresh_thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        self._flush_once()
        if self._flush_thread and self._flush_thread.is_alive():
            self._flush_thread.join(timeout=5.0)
        if self._refresh_thread and self._refresh_thread.is_alive():
            self._refresh_thread.join(timeout=5.0)

    def check(
        self,
        tool: str,
        args: Dict[str, Any],
        session_id: Optional[str] = None,
        agent_id: Optional[str] = None,
    ) -> Any:
        result = self._guard.check(tool, args, session_id=session_id, agent_id=agent_id)
        with self._audit_lock:
            self._audit_events.append(
                {
                    "event_id": f"evt-{int(time.time() * 1000)}",
                    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    "tenant_id": self._tenant_id,
                    "agent_id": agent_id or self._agent_id,
                    "session_id": session_id or "",
                    "tool_name": tool,
                    "decision": result.decision,
                    "risk_score": result.risk_score,
                    "processing_time_us": 0,
                    "reason": result.reason,
                    "matched_rules": [],
                }
            )
        return result

    def _flush_loop(self) -> None:
        while not self._stop_event.wait(self._flush_interval):
            try:
                self._flush_once()
            except Exception:
                logger.exception("Audit flush loop failed")

    def _flush_once(self) -> None:
        with self._audit_lock:
            batch = self._audit_events
            self._audit_events = []
        if not batch:
            return
        body = json.dumps({"events": batch}).encode("utf-8")
        req = urllib.request.Request(
            f"{self._cp_url}/v1/audit/batch",
            data=body,
            headers={
                "Content-Type": "application/json",
                "X-API-Key": self._api_key,
                "X-Tenant-ID": self._tenant_id,
            },
            method="POST",
        )
        try:
            _retry_request(req, self._timeout)
        except Exception:
            logger.exception("Audit flush failed")
            with self._audit_lock:
                self._audit_events = batch + self._audit_events

    def _refresh_loop(self) -> None:
        while not self._stop_event.wait(self._refresh_interval):
            try:
                self._refresh_policy()
            except Exception:
                logger.exception("Policy refresh loop failed")

    def _refresh_policy(self) -> None:
        body = json.dumps(
            {"agent_id": self._agent_id, "tenant_id": self._tenant_id}
        ).encode("utf-8")
        req = urllib.request.Request(
            f"{self._cp_url}/v1/policy/pull",
            data=body,
            headers={
                "Content-Type": "application/json",
                "X-API-Key": self._api_key,
                "X-Tenant-ID": self._tenant_id,
            },
            method="POST",
        )
        data = _retry_request(req, self._timeout)
        self._policy = json.loads(data.decode("utf-8"))

    def __enter__(self) -> "RuntimeGuard":
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.stop()
