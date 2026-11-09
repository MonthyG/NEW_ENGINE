// fetch wrapper for /api/v1. Session cookies authenticate; every state-changing request carries the
// CSRF header the manager requires. The demo build answers from src/demo instead of the network.

import { demoRequest } from './demo/mock'

export const DEMO = import.meta.env.MODE === 'demo'

export class ApiError extends Error {
  status: number
  field?: string
  body: any
  constructor(status: number, message: string, field?: string, body?: any) {
    super(message)
    this.status = status
    this.field = field
    this.body = body
  }
}

let onUnauthorized: () => void = () => {}
export function setUnauthorizedHandler(fn: () => void) {
  onUnauthorized = fn
}

async function request<T>(method: string, path: string, body?: unknown, raw?: BodyInit): Promise<T> {
  if (DEMO) {
    const r = demoRequest(method, path, body)
    if (r.status >= 400) throw new ApiError(r.status, r.body?.error ?? 'Request failed', r.body?.field, r.body)
    return r.body as T
  }
  const headers: Record<string, string> = { Accept: 'application/json' }
  if (method !== 'GET') headers['X-Requested-With'] = 'hiwaf'
  let payload: BodyInit | undefined = raw
  if (body !== undefined) {
    headers['Content-Type'] = 'application/json'
    payload = JSON.stringify(body)
  }
  const res = await fetch('/api/v1' + path, { method, headers, body: payload, credentials: 'same-origin' })
  if (res.status === 204) return undefined as T
  const text = await res.text()
  let data: any
  try {
    data = text ? JSON.parse(text) : undefined
  } catch {
    data = text
  }
  if (!res.ok) {
    if (res.status === 401 && !path.startsWith('/auth/login')) onUnauthorized()
    throw new ApiError(res.status, (data && data.error) || res.statusText || 'Request failed', data && data.field, data)
  }
  return data as T
}

export const api = {
  get: <T>(path: string) => request<T>('GET', path),
  post: <T>(path: string, body?: unknown) => request<T>('POST', path, body ?? {}),
  put: <T>(path: string, body: unknown) => request<T>('PUT', path, body),
  patch: <T>(path: string, body: unknown) => request<T>('PATCH', path, body),
  del: <T>(path: string) => request<T>('DELETE', path),
  upload: <T>(path: string, form: FormData) => request<T>('POST', path, undefined, form),
}

export function qs(params: Record<string, string | number | undefined | null>): string {
  const p = new URLSearchParams()
  for (const [k, v] of Object.entries(params)) if (v !== undefined && v !== null && v !== '') p.set(k, String(v))
  const s = p.toString()
  return s ? '?' + s : ''
}

export function errText(e: unknown): string {
  if (e instanceof ApiError) return e.field ? `${e.field}: ${e.message}` : e.message
  if (e instanceof Error) return e.message
  return String(e)
}
