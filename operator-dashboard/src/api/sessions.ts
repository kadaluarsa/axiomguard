import { apiClient } from './client'
import type { Session, SessionTimelineItem } from '../types'

export async function getSessions(): Promise<Session[]> {
  return apiClient.get<Session[]>('/admin/sessions')
}

export async function getSessionTimeline(sessionId: string): Promise<SessionTimelineItem[]> {
  return apiClient.get<SessionTimelineItem[]>(`/admin/sessions/${sessionId}/timeline`)
}
