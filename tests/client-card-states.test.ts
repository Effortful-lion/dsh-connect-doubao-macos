import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

const stateHooks: Array<{ value: unknown; setter: (next: unknown) => void }> = []
let stateCursor = 0
let effectQueue: Array<() => unknown> = []
const ranMountEffects = new Set<number>()
let effectCursor = 0

vi.mock('react', async () => {
  const actual = await vi.importActual<typeof import('react')>('react')
  return {
    ...actual,
    useState: (initial: unknown) => {
      const idx = stateCursor++
      if (stateHooks[idx] === undefined) {
        const slot = {
          value: typeof initial === 'function' ? (initial as () => unknown)() : initial,
          setter: (next: unknown) => {
            slot.value = typeof next === 'function'
              ? (next as (prev: unknown) => unknown)(slot.value)
              : next
          },
        }
        stateHooks[idx] = slot
      }
      return [stateHooks[idx]!.value, stateHooks[idx]!.setter]
    },
    useEffect: (fn: () => unknown, deps?: unknown[]) => {
      const idx = effectCursor++
      if (deps === undefined || deps.length > 0 || !ranMountEffects.has(idx)) {
        ranMountEffects.add(idx)
        effectQueue.push(fn)
      }
    },
    useCallback: <T>(fn: T) => fn,
    useMemo: <T>(fn: () => T) => fn(),
    useRef: (initial: unknown) => ({ current: initial }),
  }
})

vi.mock('react-dom', () => ({
  createPortal: (node: unknown) => node,
}))

import {
  DOUBAO_AUTH_PATH,
  DOUBAO_CATALOG_PATH,
  DOUBAO_QUOTA_PATH,
  DOUBAO_SAVE_PATH,
  DOUBAO_STATS_PATH,
} from '../src/client/contract.ts'
import { DoubaoQuotaCard } from '../src/client/DoubaoQuotaCard.tsx'
import { translator, zh } from '../src/client/index.ts'

function inspectTree(node: unknown): {
  texts: string[]
  elements: Array<{ type: unknown; props: Record<string, unknown> }>
} {
  const texts: string[] = []
  const elements: Array<{ type: unknown; props: Record<string, unknown> }> = []
  const walk = (item: unknown): void => {
    if (item === null || item === undefined || typeof item === 'boolean') return
    if (typeof item === 'string' || typeof item === 'number') {
      texts.push(String(item))
      return
    }
    if (Array.isArray(item)) {
      for (const child of item) walk(child)
      return
    }
    if (typeof item === 'object') {
      const el = item as { type?: unknown; props?: Record<string, unknown> }
      if (typeof el.type === 'function') {
        walk((el.type as (p: unknown) => unknown)(el.props ?? {}))
        return
      }
      if (el.type !== undefined && el.props !== undefined) {
        elements.push({ type: el.type, props: el.props })
      }
      if (el.props?.children !== undefined) walk(el.props.children)
    }
  }
  walk(node)
  return { texts, elements }
}

function renderCard(t: ReturnType<typeof translator>) {
  stateCursor = 0
  effectCursor = 0
  return inspectTree(DoubaoQuotaCard({ t: (key, vars) => t(key as never, vars) }))
}

const effectCleanups: Array<() => void> = []

beforeEach(() => {
  stateHooks.length = 0
  stateCursor = 0
  effectQueue = []
  ranMountEffects.clear()
  effectCursor = 0
  vi.stubGlobal('document', {
    head: { appendChild: () => {} },
    getElementById: () => ({ id: 'exists' }),
    createElement: () => ({}),
    visibilityState: 'visible',
    addEventListener: () => {},
    removeEventListener: () => {},
  })
})

afterEach(() => {
  for (const cleanup of effectCleanups.splice(0)) {
    try { cleanup() } catch {}
  }
  vi.unstubAllGlobals()
  vi.restoreAllMocks()
})

function jsonRes(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  })
}

describe('DoubaoQuotaCard honest loading/error presentation', () => {
  it('shows loading state (never DPAPI failure) while quota is pending, and shows real quota error without blaming DPAPI when signed in', async () => {
    let resolveQuota!: (res: Response) => void
    let quotaCalls = 0
    vi.stubGlobal('fetch', vi.fn(async (input: string | URL) => {
      const url = String(input)
      if (url === DOUBAO_AUTH_PATH) {
        return jsonRes({ ok: true, signedIn: true, expiresAt: Date.now() + 86_400_000 * 30, daysLeft: 30, detail: null })
      }
      if (url === DOUBAO_QUOTA_PATH) {
        quotaCalls += 1
        if (quotaCalls === 1) {
          return await new Promise<Response>((resolve) => { resolveQuota = resolve })
        }
        return jsonRes({ error: 'upstream quota timeout' }, 500)
      }
      if (url === DOUBAO_STATS_PATH) {
        return jsonRes({
          ok: true,
          startedAt: 1,
          updatedAt: 1,
          activeConversations: 1,
          totals: {
            requests: 1,
            succeeded: 1,
            failed: 0,
            continuations: 0,
            promptTokens: 10,
            uncachedInputTokens: 10,
            cachedInputTokens: 0,
            completionTokens: 5,
            reasoningTokens: 0,
            totalTokens: 15,
            cacheHitRate: 0,
            avgTtftMs: 100,
            avgTps: 10,
            totalDurationMs: 200,
            decodeMs: 100,
            decodeTokens: 5,
          },
          byModel: [],
          sessions: [],
          lastTurn: null,
        })
      }
      if (url === DOUBAO_CATALOG_PATH) return jsonRes({ ok: true, models: [], error: null })
      if (url === DOUBAO_SAVE_PATH) return jsonRes({ ok: true, value: {} })
      throw new Error(`unexpected fetch: ${url}`)
    }))

    const t = translator(zh)
    renderCard(t)
    for (const fn of effectQueue.splice(0)) {
      const cleanup = fn()
      if (typeof cleanup === 'function') effectCleanups.push(cleanup as () => void)
    }
    await new Promise((r) => setTimeout(r, 20))

    // Auth & stats already settled while quota is still in flight:
    // must say loading, NEVER "本机保存的会话无法解密", and stats must already be visible!
    const whilePending = renderCard(t).texts.join(' | ')
    expect(whilePending).toContain('正在读取豆包额度')
    expect(whilePending).not.toContain('无法解密')
    expect(whilePending).toContain('已登录')
    expect(whilePending).toContain('30 天后到期')
    expect(whilePending).toContain('活跃会话 1')

    // Now quota fails with HTTP 500: must still NOT lie about DPAPI decryption!
    resolveQuota(jsonRes({ error: 'quota endpoint failed' }, 500))
    await new Promise((r) => setTimeout(r, 20))

    const afterError = renderCard(t).texts.join(' | ')
    expect(afterError).not.toContain('无法解密')
    expect(afterError).toContain('额度获取失败：quota endpoint failed')
    expect(afterError).toContain('连接豆包失败')
  })

  it('keeps existing quota visible if a later refresh fails and keeps relogin enabled when GET /auth errors', async () => {
    let quotaCalls = 0
    vi.stubGlobal('fetch', vi.fn(async (input: string | URL) => {
      const url = String(input)
      if (url === DOUBAO_AUTH_PATH) return jsonRes({ error: 'auth probe failed' }, 500)
      if (url === DOUBAO_QUOTA_PATH) {
        quotaCalls += 1
        if (quotaCalls === 1) {
          return jsonRes({
            ok: true,
            profile: '<not found>',
            plan: '标准套餐',
            exhausted: false,
            windows: {
              package: {
                usedPercent: 10,
                remainingPercent: 90,
                resetsAt: Date.now() + 3_600_000,
                resetsInMs: 3_600_000,
                label: null,
                startsOnUse: false,
                usedAmount: 100,
                totalAmount: 1000,
              },
              fiveHour: null,
              weekly: null,
              incentive: [],
            },
            available: 900,
            fetchedAt: Date.now(),
            error: null,
          })
        }
        return jsonRes({ error: 'transient 502' }, 502)
      }
      if (url === DOUBAO_STATS_PATH) return jsonRes({ ok: true, startedAt: 1, updatedAt: 1, activeConversations: 0, totals: { requests: 0, succeeded: 0, failed: 0, continuations: 0, promptTokens: 0, uncachedInputTokens: 0, cachedInputTokens: 0, completionTokens: 0, reasoningTokens: 0, totalTokens: 0, cacheHitRate: null, avgTtftMs: null, avgTps: null, totalDurationMs: 0, decodeMs: 0, decodeTokens: 0 }, byModel: [], sessions: [], lastTurn: null })
      if (url === DOUBAO_CATALOG_PATH) return jsonRes({ ok: true, models: [], error: null })
      if (url === DOUBAO_SAVE_PATH) return jsonRes({ ok: true, value: {} })
      throw new Error(`unexpected fetch: ${url}`)
    }))

    const t = translator(zh)
    renderCard(t)
    for (const fn of effectQueue.splice(0)) {
      const cleanup = fn()
      if (typeof cleanup === 'function') effectCleanups.push(cleanup as () => void)
    }
    await new Promise((r) => setTimeout(r, 20))

    const initial = renderCard(t)
    expect(initial.texts.join(' | ')).toContain('标准套餐')
    const reloginBtn = initial.elements.find((el) => el.type === 'button' && String(el.props.children) === '重新登录')
    expect(reloginBtn?.props.disabled).toBe(false)

    const refreshBtn = initial.elements.find((el) => el.type === 'button' && String(el.props.children) === '刷新额度')
    expect(refreshBtn).toBeDefined()
    ;(refreshBtn!.props.onClick as () => void)()
    await new Promise((r) => setTimeout(r, 20))

    const afterRefreshFail = renderCard(t).texts.join(' | ')
    expect(afterRefreshFail).toContain('标准套餐')
    expect(afterRefreshFail).toContain('额度获取失败：transient 502')
    expect(afterRefreshFail).not.toContain('无法解密')
  })
})
