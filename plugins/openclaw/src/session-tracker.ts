import type { SessionState, AxiomGuardPluginConfig } from "./types.js";

const DEFAULT_MAX_SESSIONS = 10_000;
const DEFAULT_EVICTION_MS = 3_600_000; // 1 hour

/**
 * In-memory session risk tracker.
 *
 * Tracks cumulative risk scores per session with auto-eviction of stale
 * sessions and a hard cap on total sessions to prevent memory leaks.
 */
export class SessionTracker {
  private sessions = new Map<string, SessionState>();
  private readonly maxSessions: number;
  private readonly evictionMs: number;

  constructor(config?: Partial<Pick<AxiomGuardPluginConfig, never>> & {
    maxSessions?: number;
    evictionMs?: number;
  }) {
    this.maxSessions = config?.maxSessions ?? DEFAULT_MAX_SESSIONS;
    this.evictionMs = config?.evictionMs ?? DEFAULT_EVICTION_MS;
  }

  /** Get the current cumulative risk for a session (0.0 if unknown). */
  getRisk(sessionId: string): number {
    return this.sessions.get(sessionId)?.risk ?? 0;
  }

  /** Record a tool call event and update cumulative risk. */
  record(
    sessionId: string,
    entry: { category: string; riskScore: number; decision: string },
  ): void {
    const now = Date.now();
    let session = this.sessions.get(sessionId);

    if (!session) {
      // Evict stale sessions if at capacity before adding new one
      if (this.sessions.size >= this.maxSessions) {
        this.evict();
      }
      // If still at capacity after eviction, drop the new session (safest)
      if (this.sessions.size >= this.maxSessions) {
        return;
      }

      session = {
        sessionId,
        risk: 0,
        entries: [],
        lastActivity: now,
      };
      this.sessions.set(sessionId, session);
    }

    session.entries.push({ ...entry, ts: now });
    session.risk = Math.min(1.0, session.risk + entry.riskScore);
    session.lastActivity = now;
  }

  /** Get the full session state (for testing/introspection). */
  get(sessionId: string): SessionState | undefined {
    return this.sessions.get(sessionId);
  }

  /** Remove sessions idle longer than evictionMs. */
  evict(): void {
    const cutoff = Date.now() - this.evictionMs;
    for (const [id, session] of this.sessions) {
      if (session.lastActivity < cutoff) {
        this.sessions.delete(id);
      }
    }
  }

  /** Clear all sessions. */
  destroy(): void {
    this.sessions.clear();
  }

  /** Current number of tracked sessions. */
  get size(): number {
    return this.sessions.size;
  }
}
