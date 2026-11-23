/**
 * The fingerprint is the ONE identity the direct path may present.
 *
 * What matters for risk control is that it carries the page's own values and
 * never a frozen per-request signature: a stale `msToken`/`a_bogus` would be
 * worse than no fingerprint at all, and a wrong host would poison the query.
 */
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import {
  fingerprintFromRequest,
  readBrowserFingerprint,
  sanitizeFingerprintQuery,
  writeBrowserFingerprint,
} from '../src/doubao-auth-browser.ts'

const APP_URL = 'https://www.doubao.com/alice/slot/action_bar_v3/brief_list'
  + '?aid=497858&device_id=7123456789&device_platform=web&client_platform=web'
  + '&web_id=7654321&fp=verify_7123456789&runtime=web&version_code=20800'

const HEADERS = {
  'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/147.0.0.0 Safari/537.36',
  Referer: 'https://www.doubao.com/chat/123',
  'sec-ch-ua': '"Chromium";v="147", "Not.A/Brand";v="8"',
}

describe('browser fingerprint', () => {
  it('drops per-request signatures and the regenerated tab id', () => {
    const query = sanitizeFingerprintQuery(
      '?aid=1&msToken=SECRET&a_bogus=SIG&web_tab_id=t&_signature=s&runtime=web',
    )
    expect(query).toEqual({ aid: '1', runtime: 'web' })
  })

  it('reads the identity from a real same-origin app request', () => {
    const fingerprint = fingerprintFromRequest(APP_URL + '&msToken=SECRET', HEADERS)
    expect(fingerprint).toBeDefined()
    expect(fingerprint!.userAgent).toContain('Chrome/147')
    expect(fingerprint!.referer).toBe('https://www.doubao.com/chat/123')
    expect(fingerprint!.secChUa).toContain('Chromium')
    expect(fingerprint!.query.aid).toBe('497858')
    expect(fingerprint!.query.device_platform).toBe('web')
    expect(JSON.stringify(fingerprint)).not.toContain('SECRET')
    expect(fingerprint!.query.web_tab_id).toBeUndefined()
  })

  it('refuses another host, a missing aid, or a missing user agent', () => {
    expect(fingerprintFromRequest('https://mcs.doubao.com/upload?aid=1', HEADERS)).toBeUndefined()
    expect(fingerprintFromRequest('https://www.doubao.com/alice/x?device_id=1', HEADERS)).toBeUndefined()
    expect(fingerprintFromRequest(APP_URL, { Referer: 'https://www.doubao.com/chat/' })).toBeUndefined()
    expect(fingerprintFromRequest('not a url', HEADERS)).toBeUndefined()
  })

  describe('writing', () => {
    let home = ''
    let savedUserProfile: string | undefined
    let savedHome: string | undefined

    beforeEach(() => {
      savedUserProfile = process.env.USERPROFILE
      savedHome = process.env.HOME
      home = mkdtempSync(join(tmpdir(), 'dsh-doubao-fingerprint-'))
      process.env.USERPROFILE = home
      process.env.HOME = home
    })

    afterEach(() => {
      rmSync(home, { recursive: true, force: true })
      if (savedUserProfile === undefined) delete process.env.USERPROFILE
      else process.env.USERPROFILE = savedUserProfile
      if (savedHome === undefined) delete process.env.HOME
      else process.env.HOME = savedHome
    })

    it('writes the same shape the upstream client reads back', () => {
      const fingerprint = fingerprintFromRequest(APP_URL, HEADERS)!
      const path = writeBrowserFingerprint(fingerprint)
      expect(path.endsWith(join('.dsh', 'doubao-browser-fingerprint.json'))).toBe(true)
      const parsed = JSON.parse(readFileSync(path, 'utf8')) as {
        userAgent?: string
        referer?: string
        query?: Record<string, string>
      }
      expect(parsed.query?.aid).toBe('497858')
      expect(parsed.userAgent).toContain('Chrome/147')
    })

    it('reads back a usable identity and refuses a malformed one', () => {
      writeBrowserFingerprint(fingerprintFromRequest(APP_URL, HEADERS)!)
      expect(readBrowserFingerprint()?.query.aid).toBe('497858')

      writeFileSync(join(home, '.dsh', 'doubao-browser-fingerprint.json'), '{"userAgent":"x"}', 'utf8')
      expect(readBrowserFingerprint()).toBeUndefined()
    })
  })
})
