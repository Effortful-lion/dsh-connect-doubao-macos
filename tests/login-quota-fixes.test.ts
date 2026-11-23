import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import {
  CORE_AUTH_COOKIE_NAMES,
  REQUIRED_COOKIE_NAMES,
  clearCredentialCache,
  invalidateCredentialCache,
  loadBrowserCredentials,
  loadDoubaoCredentials,
  saveBrowserCredentials,
} from '../src/doubao-auth.ts'
import { fetchQuota, invalidateQuotaCache } from '../src/doubao-quota.ts'
import { applyRenewals, invalidateRenewals } from '../src/doubao-upstream.ts'
import { classifyQuotaView, type DoubaoQuotaView } from '../src/client/contract.ts'

const sampleCreds = {
  ok: true,
  header: REQUIRED_COOKIE_NAMES.map((name) => `${name}=v`).join('; '),
  pairs: new Map(REQUIRED_COOKIE_NAMES.map((name) => [name, 'v'])),
}

describe('login & DPAPI credential fixes', () => {
  let home = ''
  let savedUserProfile: string | undefined
  let savedHome: string | undefined

  beforeEach(() => {
    savedUserProfile = process.env.USERPROFILE
    savedHome = process.env.HOME
    home = mkdtempSync(join(tmpdir(), 'dsh-doubao-auth-fix-'))
    process.env.USERPROFILE = home
    process.env.HOME = home
    invalidateCredentialCache()
  })

  afterEach(() => {
    clearCredentialCache()
    invalidateRenewals()
    if (savedUserProfile === undefined) delete process.env.USERPROFILE
    else process.env.USERPROFILE = savedUserProfile
    if (savedHome === undefined) delete process.env.HOME
    else process.env.HOME = savedHome
    rmSync(home, { recursive: true, force: true })
  })

  it('distinguishes a missing DPAPI file (signed_out) from a corrupt/unreadable DPAPI file (unreadable)', () => {
    const missing = loadDoubaoCredentials({ force: true })
    expect(missing.ok).toBe(false)
    expect(missing.reason).toContain('还没有浏览器登录态')
    expect(classifyQuotaView({
      ok: false,
      profile: '<not found>',
      plan: null,
      exhausted: false,
      windows: { package: null, fiveHour: null, weekly: null, incentive: [] },
      available: null,
      fetchedAt: 1,
      error: missing.reason ?? null,
    })).toBe('signed_out')

    mkdirSync(join(home, '.dsh'), { recursive: true })
    writeFileSync(join(home, '.dsh', 'doubao-credentials-browser.dpapi'), Buffer.from('corrupt-dpapi-blob'))
    const corrupt = loadDoubaoCredentials({ force: true })
    expect(corrupt.ok).toBe(false)
    expect(corrupt.reason).toContain('无法解密')
    expect(classifyQuotaView({
      ok: false,
      profile: '<not found>',
      plan: null,
      exhausted: false,
      windows: { package: null, fiveHour: null, weekly: null, incentive: [] },
      available: null,
      fetchedAt: 1,
      error: corrupt.reason ?? null,
    })).toBe('unreadable')
  })

  it.skipIf(process.platform !== 'win32')(
    'seals & unseals via DPAPI even when only core auth cookies are present, while rejecting missing core cookies',
    () => {
      // Only core auth cookies (e.g. auxiliary tracking cookie ttwid/s_v_web_id absent):
      // must remain usable instead of discarding the sign-in right after scan.
      const coreOnly = new Map(CORE_AUTH_COOKIE_NAMES.map((name) => [name, `val-${name}`]))
      saveBrowserCredentials(coreOnly)
      const loaded = loadBrowserCredentials()
      expect(loaded?.ok).toBe(true)
      expect(loaded?.pairs.get('sessionid')).toBe('val-sessionid')

      // Missing a core auth cookie (`uid_tt`) must still be rejected cleanly.
      const incomplete = new Map<string, string>([
        ['sessionid', 's1'],
        ['sessionid_ss', 's2'],
        ['sid_tt', 's3'],
      ])
      saveBrowserCredentials(incomplete)
      expect(loadBrowserCredentials()).toBeUndefined()
      const failed = loadDoubaoCredentials({ force: true })
      expect(failed.ok).toBe(false)
      expect(failed.reason).toContain('uid_tt')
    },
    20_000,
  )

  it('clears rotated cookie renewals cleanly on invalidateRenewals', () => {
    // applyRenewals returns header verbatim when renewals map is empty
    expect(applyRenewals('sessionid=abc')).toBe('sessionid=abc')
    invalidateRenewals()
    expect(applyRenewals('sessionid=abc')).toBe('sessionid=abc')
  })
})

describe('quota error & classifier fixes', () => {
  afterEach(() => {
    vi.unstubAllGlobals()
    invalidateQuotaCache()
  })

  it('surfaces HTTP 200 business error codes (710012001 / 710022004 / generic) and missing data instead of returning silent empty ok', async () => {
    const cases = [
      { body: { code: 710012001, msg: 'expired', data: null }, expectedState: 'session_dead' },
      { body: { code: 710022004, msg: 'slide verify', data: null }, expectedState: 'risk_challenge' },
      { body: { code: 50001, msg: 'quota backend down', data: null }, expectedState: 'network' },
      { body: { code: 0, data: null }, expectedState: 'network' },
    ] as const

    for (const testCase of cases) {
      vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify(testCase.body), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      })))
      const quota = await fetchQuota({ force: true, credentials: sampleCreds })
      expect(quota.error).toBeDefined()
      const view: DoubaoQuotaView = {
        ok: false,
        profile: '<not found>',
        plan: null,
        exhausted: false,
        windows: { package: null, fiveHour: null, weekly: null, incentive: [] },
        available: null,
        fetchedAt: quota.fetchedAt,
        error: quota.error ?? null,
      }
      expect(classifyQuotaView(view)).toBe(testCase.expectedState)
    }
  })

  it('maps HTTP 401/403 from quota endpoint to session_dead instead of network', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response('unauthorized', { status: 401 })))
    const quota = await fetchQuota({ force: true, credentials: sampleCreds })
    expect(quota.error).toContain('401')
    expect(classifyQuotaView({
      ok: false,
      profile: '<not found>',
      plan: null,
      exhausted: false,
      windows: { package: null, fiveHour: null, weekly: null, incentive: [] },
      available: null,
      fetchedAt: quota.fetchedAt,
      error: quota.error ?? null,
    })).toBe('session_dead')
  })

  it('classifies undefined quota accurately based on loading / auth / routeError context', () => {
    expect(classifyQuotaView(undefined, { loading: true })).toBe('loading')
    expect(classifyQuotaView(undefined, {
      loading: false,
      auth: { ok: true, signedIn: true, expiresAt: 1000, daysLeft: 30, detail: null },
      routeError: 'HTTP 500',
    })).toBe('network')
    expect(classifyQuotaView(undefined, {
      loading: false,
      auth: { ok: true, signedIn: false, expiresAt: null, daysLeft: null, detail: '还没有浏览器登录态' },
    })).toBe('signed_out')
    expect(classifyQuotaView(undefined, {
      loading: false,
      auth: { ok: true, signedIn: false, expiresAt: null, daysLeft: null, detail: '本机保存的会话无法解密' },
    })).toBe('unreadable')
  })
})
