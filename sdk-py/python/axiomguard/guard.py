"""High-level Guard API for AxiomGuard."""

import json
import time
import urllib.request
import urllib.error
from typing import Any, Dict, Optional

from axiomguard._axiomguard_core import compute_hash, verify_token_with_checks


class GuardResult:
    """Result of a guard check."""

    __slots__ = (
        "decision",
        "reason",
        "risk_score",
        "token",
        "tool",
        "agent_id",
        "session_id",
    )

    def __init__(
        self,
        decision: str,
        reason: str,
        risk_score: float,
        token: Optional[str],
        tool: str,
        agent_id: str,
        session_id: str,
    ):
        self.decision = decision
        self.reason = reason
        self.risk_score = risk_score
        self.token = token
        self.tool = tool
        self.agent_id = agent_id
        self.session_id = session_id

    def __repr__(self) -> str:
        return (
            f"GuardResult(decision='{self.decision}', tool='{self.tool}', "
            f"agent_id='{self.agent_id}', risk={self.risk_score:.2f})"
        )

    @property
    def allowed(self) -> bool:
        return self.decision == "Allow"

    def verify_token_for(
        self,
        tool: str,
        args: Dict[str, Any],
        agent_id: Optional[str] = None,
        verifying_key_hex: Optional[str] = None,
    ) -> bool:
        """Verify the token matches the given tool and args."""
        if self.token is None:
            return False

        args_json = json.dumps(args, sort_keys=True, separators=(",", ":"))

        try:
            vk_hex = verifying_key_hex or self._verifying_key_hex
            if vk_hex is None:
                return False
            result = verify_token_with_checks(
                self.token,
                vk_hex,
                expected_tool=tool,
                expected_agent_id=agent_id,
                expected_args_json=args_json,
            )
            return result.valid
        except Exception:
            return False

    _verifying_key_hex: Optional[str] = None


class CircuitBreaker:
    """Simple circuit breaker for the control plane connection."""

    def __init__(self, failure_threshold: int = 5, recovery_timeout: float = 30.0):
        self._failure_count = 0
        self._failure_threshold = failure_threshold
        self._recovery_timeout = recovery_timeout
        self._last_failure_time: Optional[float] = None
        self._state = "closed"

    def record_success(self):
        self._failure_count = 0
        self._state = "closed"

    def record_failure(self):
        self._failure_count += 1
        self._last_failure_time = time.monotonic()
        if self._failure_count >= self._failure_threshold:
            self._state = "open"

    def allow_request(self) -> bool:
        if self._state == "closed":
            return True
        if self._state == "open":
            if self._last_failure_time and (
                time.monotonic() - self._last_failure_time > self._recovery_timeout
            ):
                self._state = "half-open"
                return True
            return False
        return True


def _retry_request(
    req: urllib.request.Request,
    timeout: float,
    max_retries: int = 3,
    base_delay: float = 0.1,
    circuit_breaker: Optional[CircuitBreaker] = None,
) -> bytes:
    """Execute HTTP request with exponential backoff and circuit breaker."""
    if circuit_breaker and not circuit_breaker.allow_request():
        raise RuntimeError("Circuit breaker is open — control plane unavailable")

    last_error: Optional[Exception] = None
    for attempt in range(max_retries):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = resp.read()
                if circuit_breaker:
                    circuit_breaker.record_success()
                return data
        except urllib.error.HTTPError as e:
            if e.code >= 500:
                last_error = e
                if circuit_breaker:
                    circuit_breaker.record_failure()
                if attempt < max_retries - 1:
                    time.sleep(base_delay * (2**attempt))
                continue
            raise
        except urllib.error.URLError as e:
            last_error = e
            if circuit_breaker:
                circuit_breaker.record_failure()
            if attempt < max_retries - 1:
                time.sleep(base_delay * (2**attempt))
            continue

    raise RuntimeError(
        f"Control plane request failed after {max_retries} retries: {last_error}"
    ) from last_error


class Guard:
    """AxiomGuard client for checking tool calls.

    Usage::

        guard = Guard(
            cp_url="http://localhost:8080",
            api_key="your-api-key",
            tenant_id="tenant-1",
            agent_id="agent-1",
        )

        result = guard.check("exec", {"command": "ls", "args": ["-la"]})
        if result.allowed:
            print("Token:", result.token)
    """

    def __init__(
        self,
        cp_url: str,
        api_key: str,
        tenant_id: str,
        agent_id: Optional[str] = None,
        verifying_key_hex: Optional[str] = None,
        timeout: float = 5.0,
        max_retries: int = 3,
        circuit_breaker: Optional[CircuitBreaker] = None,
    ):
        self.cp_url = cp_url.rstrip("/")
        self.api_key = api_key
        self.tenant_id = tenant_id
        self.agent_id = agent_id
        self.verifying_key_hex = verifying_key_hex
        self.timeout = timeout
        self.max_retries = max_retries
        self.circuit_breaker = circuit_breaker or CircuitBreaker()

    def check(
        self,
        tool: str,
        args: Dict[str, Any],
        session_id: Optional[str] = None,
        agent_id: Optional[str] = None,
    ) -> GuardResult:
        """Check a tool call against the control plane.

        Args:
            tool: Tool name (e.g., "exec", "file", "http").
            args: Tool arguments as a dict.
            session_id: Session identifier (auto-generated if None).
            agent_id: Override agent_id for this call.

        Returns:
            GuardResult with decision, token, and metadata.
        """
        effective_agent = agent_id or self.agent_id or "default"
        effective_session = session_id or f"py-{int(time.time())}"

        args_json = json.dumps(args, sort_keys=True, separators=(",", ":"))
        args_hash = compute_hash(args_json)

        body = json.dumps(
            {
                "tool": tool,
                "args_hash": args_hash,
                "session_id": effective_session,
                "tenant_id": self.tenant_id,
                "agent_id": effective_agent,
                "decision": "Allow",
                "risk_score": 0.0,
            }
        ).encode("utf-8")

        req = urllib.request.Request(
            f"{self.cp_url}/v1/token/issue",
            data=body,
            headers={
                "Content-Type": "application/json",
                "X-API-Key": self.api_key,
                "X-Tenant-ID": self.tenant_id,
            },
            method="POST",
        )

        try:
            resp_data_raw = _retry_request(
                req,
                self.timeout,
                self.max_retries,
                circuit_breaker=self.circuit_breaker,
            )
            resp_data = json.loads(resp_data_raw.decode("utf-8"))
        except urllib.error.HTTPError as e:
            if e.code == 401:
                raise RuntimeError(
                    f"AxiomGuard blocked tool call: authentication failed"
                ) from e
            if e.code == 429:
                raise RuntimeError(f"AxiomGuard blocked tool call: rate limited") from e
            if e.code >= 400:
                raise RuntimeError(
                    f"AxiomGuard blocked tool call: CP returned {e.code}"
                ) from e
            body_text = e.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"Control plane returned {e.code}: {body_text}") from e
        except urllib.error.URLError as e:
            raise RuntimeError(f"Control plane unreachable: {e.reason}") from e

        token = resp_data.get("token")
        result = GuardResult(
            decision="Allow" if token else "Block",
            reason="" if token else "No token issued",
            risk_score=0.0,
            token=token,
            tool=tool,
            agent_id=effective_agent,
            session_id=effective_session,
        )
        result._verifying_key_hex = self.verifying_key_hex
        return result

    def check_sync(
        self,
        tool: str,
        args: Dict[str, Any],
        **kwargs,
    ) -> GuardResult:
        """Alias for check(). Kept for backward compatibility."""
        return self.check(tool, args, **kwargs)


def execute_with_token(
    guard: Guard,
    tool: str,
    args: Dict[str, Any],
    executor,
    agent_id: Optional[str] = None,
    session_id: Optional[str] = None,
):
    """Check with guard, then execute with the token if allowed.

    Args:
        guard: Guard instance.
        tool: Tool name.
        args: Tool arguments.
        executor: Callable that receives (args, token) and returns result.
        agent_id: Override agent_id.
        session_id: Override session_id.

    Returns:
        Whatever executor returns.

    Raises:
        RuntimeError: If the guard blocks the call.
    """
    result = guard.check(tool, args, agent_id=agent_id, session_id=session_id)

    if not result.allowed:
        raise RuntimeError(
            f"AxiomGuard blocked tool call: {result.decision} — {result.reason}"
        )

    return executor(args, result.token)
