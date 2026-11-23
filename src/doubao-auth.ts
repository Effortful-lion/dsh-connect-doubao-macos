/**
 * Doubao credentials — the sealed browser session.
 *
 * WHY THERE IS ONLY ONE SOURCE
 *
 * This module used to decrypt the desktop client's cookie jar: read the DPAPI
 * master key out of `<User Data>\Local State`, open
 * `<User Data>\Default\Network\Cookies` as SQLite, AES-GCM each `v10` value and
 * strip Chrome's host-binding prefix. It was removed, not merely deprecated,
 * because of a defect that no amount of care could fix from outside the app:
 *
 *   the client holds its cookie database with an EXCLUSIVE lock while it runs,
 *   and this plugin exists precisely for an account whose app IS running.
 *   So the live read failed in the normal case, the code fell back to a 12-hour
 *   sealed copy, and once the server rotated the session every request was
 *   rejected upstream — with a local state that still looked "signed in", and
 *   therefore no local explanation for the user.
 *
 * The browser sign-in in `./doubao-auth-browser.ts` has neither of those
 * failure modes: it captures the cookies over CDP from a throwaway Chromium
 * profile, so there is no lock to lose, and what this module seals is exactly
 * what was just captured, so there is no stale copy to prefer. One source also
 * means one account: no fallback can silently serve whoever else happened to be
 * signed in somewhere on this machine.
 *
 * SECURITY: cookie values live in this process's memory and in one sealed file.
 * The sealing mechanism is the operating system's own, from `./doubao-seal.ts`:
 * DPAPI (current-user scope) on Windows, and a key held in the login keychain
 * with AES-256-GCM on macOS. Neither another account on this machine nor a
 * copied file on another machine can open it. Nothing here is logged, and
 * nothing leaves except the outbound request's `Cookie:` header.
 *
 * @module dsh-connect-doubao-macos/auth
 */
import { readFileSync, writeFileSync, mkdirSync, unlinkSync } from 'node:fs'
import { homedir } from 'node:os'
import { dirname, join } from 'node:path'
import { seal, unseal, sealBackendLabel } from './doubao-seal.ts'

export interface DoubaoCredentials {
  /** Cookie pairs ready for a `Cookie:` header. */
  header: string
  /** Individual pairs, for selective use (e.g. msToken in a query string). */
  pairs: Map<string, string>
  /** True when a usable session was loaded. */
  ok: boolean
  /** Human-readable reason when `ok` is false. Never contains a secret. */
  reason?: string
}

/**
 * How long a loaded session stays in the process cache.
 *
 * Not a security boundary: opening the sealed file costs a child process on
 * Windows (the DPAPI helper) or a keychain lookup on macOS, and every upstream
 * call wants the header, so the cache is what keeps a chat turn from spawning
 * one process per request. Doubao rotates its own cookies server-side; the
 * first rejected request is the accurate expiry signal.
 */
export const CREDENTIAL_TTL_MS = 10 * 60 * 1000

/**
 * Cookie names Doubao's chat backend actually needs for authentication.
 * Verified in M1/M2: this exact set authenticated while the app was closed.
 */
/**
 * Core cookie names Doubao actually requires to authenticate an account.
 *
 * browserLogin() still waits briefly for the full 9-cookie jar so that
 * anti-bot and expiry cookies are captured whenever issued, while
 * loadBrowserCredentials() will not discard an otherwise working session
 * merely because an auxiliary tracking cookie was blocked or delayed.
 */
export const CORE_AUTH_COOKIE_NAMES = [
  'sessionid',
  'sessionid_ss',
  'sid_tt',
  'uid_tt',
] as const

export const REQUIRED_COOKIE_NAMES = [
  'sessionid',
  'sessionid_ss',
  'sid_tt',
  'sid_guard',
  'uid_tt',
  'ttwid',
  'odin_tt',
  'passport_csrf_token',
  's_v_web_id',
] as const

/* ------------------------------------------------------------------ *
 * The sealed browser session
 * ------------------------------------------------------------------ */

/**
 * Where the one usable session lives.
 *
 * The name no longer says "dpapi": on macOS the file is an AES-GCM envelope
 * whose key sits in the login keychain, so a `.dpapi` suffix would be a lie.
 * The old name is still read so an existing session survives the upgrade; a
 * legacy file that cannot be opened is simply replaced on the next login.
 *
 * There is no TTL here, on purpose: the session lives ~30 days server-side and
 * the FIRST rejected request is the accurate expiry signal. A clock on top of
 * that could only invent failures for a session that still works.
 */
const BROWSER_CACHE_FILENAME = 'doubao-credentials-browser.sealed'

/** Older on-disk names, read only so an upgrade does not throw a working session away. */
const LEGACY_CACHE_FILENAMES = ['doubao-credentials-browser.dpapi']

function cachePaths(): [string, ...string[]] {
  const dir = join(homedir(), '.dsh')
  return [
    join(dir, BROWSER_CACHE_FILENAME),
    ...LEGACY_CACHE_FILENAMES.map((name) => join(dir, name)),
  ]
}

/** The file this session lives in: the new name, or a legacy file when that is all there is. */
export function browserCachePath(): string {
  const [primary, ...legacy] = cachePaths()
  for (const candidate of legacy) {
    try {
      readFileSync(candidate)
      try {
        readFileSync(primary)
      } catch {
        return candidate
      }
    } catch { /* absent */ }
  }
  return primary
}

/** Seal browser-harvested cookies to disk. Throws when sealing is unavailable. */
export function saveBrowserCredentials(pairs: Map<string, string>): void {
  const header = [...pairs.entries()].map(([name, value]) => `${name}=${value}`).join('; ')
  const payload = JSON.stringify({
    savedAt: Date.now(),
    source: 'browser',
    header,
    pairs: [...pairs.entries()],
  })
  const sealed = seal(Buffer.from(payload, 'utf8'))
  const path = cachePaths()[0]
  mkdirSync(dirname(path), { recursive: true })
  writeFileSync(path, sealed, { mode: 0o600 })
}

/** Read the sealed browser session with a failure diagnosis when unusable. */
function readBrowserCredentials():
  | { ok: true; credentials: DoubaoCredentials }
  | { ok: false; kind: 'missing' | 'unreadable' | 'incomplete'; reason: string } {
  let sealed: Buffer | undefined
  for (const path of cachePaths()) {
    try {
      sealed = readFileSync(path)
      break
    } catch {
      continue
    }
  }
  if (sealed === undefined) {
    return {
      ok: false,
      kind: 'missing',
      reason: '还没有浏览器登录态。请在豆包卡片里点「重新登录」扫码一次。',
    }
  }

  let json: string
  try {
    json = unseal(sealed).toString('utf8')
  } catch (error: unknown) {
    return {
      ok: false,
      kind: 'unreadable',
      reason: `本机保存的会话无法解密（${(error as Error)?.message ?? String(error)}），请重新登录一次。`,
    }
  }

  try {
    const parsed = JSON.parse(json) as { header?: unknown; pairs?: unknown }
    if (typeof parsed.header !== 'string' || !Array.isArray(parsed.pairs)) {
      return { ok: false, kind: 'unreadable', reason: '本机保存的会话格式损坏（无法解密），请重新登录一次。' }
    }
    const pairs = new Map<string, string>()
    for (const entry of parsed.pairs) {
      if (!Array.isArray(entry) || entry.length !== 2) continue
      const [name, value] = entry as [unknown, unknown]
      if (typeof name === 'string' && typeof value === 'string' && name !== '') pairs.set(name, value)
    }
    const missingCore = CORE_AUTH_COOKIE_NAMES.filter((name) => !pairs.get(name))
    if (missingCore.length > 0) {
      return {
        ok: false,
        kind: 'incomplete',
        reason: `登录态不完整（缺少 ${missingCore.join(', ')}），请在豆包卡片里点「重新登录」重新扫码。`,
      }
    }
    return { ok: true, credentials: { ok: true, header: parsed.header, pairs } }
  } catch {
    return { ok: false, kind: 'unreadable', reason: '本机保存的会话格式损坏（无法解密），请重新登录一次。' }
  }
}

/** Read the sealed browser session, or `undefined` when absent/unusable. */
export function loadBrowserCredentials(): DoubaoCredentials | undefined {
  const result = readBrowserCredentials()
  return result.ok ? result.credentials : undefined
}

/** True when a sealed browser session exists on disk. */
export function hasBrowserCredentials(): boolean {
  return loadBrowserCredentials() !== undefined
}

/** Drop the sealed session (a re-login always overwrites it). */
export function clearBrowserCredentials(): void {
  for (const path of cachePaths()) {
    try { unlinkSync(path) } catch { /* already gone */ }
  }
}

/** Which sealing mechanism protects this machine's session — reported by `doctor`. */
export function credentialSealLabel(): string {
  return sealBackendLabel()
}

/* ------------------------------------------------------------------ *
 * Profile location
 * ------------------------------------------------------------------ */

/**
 * Locate the Doubao Chromium profile directory on this machine.
 *
 * Discovery lives in `./doubao-profile.ts` and is re-exported here because
 * every caller (discovery, upstream, doctor, probe) reaches for it through this
 * module. It is not hardcoded to one OS-specific folder: Windows puts `User
 * Data` under `%LOCALAPPDATA%\Doubao`, macOS puts the same Chromium layout
 * directly at `~/Library/Application Support/Doubao`, and the app lets users
 * move it either way. The cookie jar inside that folder is no longer read — the
 * paths still matter for the task-mode workspace, the model catalog and
 * diagnostics.
 */
export {
  findDoubaoUserDataDir,
  listDoubaoProfiles,
  describeProfileLocation,
  extractUserDataDir,
  resolveUserProvided,
  setProfileOverride,
  looksLikeProfile,
  PROFILE_ENV,
  type DoubaoProfileLocation,
  type ProfileSource,
} from './doubao-profile.ts'

/* ------------------------------------------------------------------ *
 * Public entry point
 * ------------------------------------------------------------------ */

let cached: { at: number; credentials: DoubaoCredentials } | undefined

/**
 * The session this plugin runs on: the sealed browser sign-in, or a failure that
 * tells the user what to do about it.
 *
 * Cached in process memory for `CREDENTIAL_TTL_MS` because the read costs a
 * child process. A failure is reported as `{ ok: false, reason }` rather than
 * thrown so the provider can surface an actionable message instead of a stack
 * trace; the login route drops this cache, so a fresh scan is visible
 * immediately.
 */
export function loadDoubaoCredentials(options: { force?: boolean } = {}): DoubaoCredentials {
  const now = Date.now()
  if (!options.force && cached !== undefined && now - cached.at < CREDENTIAL_TTL_MS) {
    return cached.credentials
  }

  const result = readBrowserCredentials()
  const credentials: DoubaoCredentials = result.ok ? result.credentials : {
    ok: false,
    reason: result.reason,
    header: '',
    pairs: new Map(),
  }

  // Missing-file reads are cheap and a CLI login may have just succeeded;
  // never cache the "not signed in" state, so a fresh scan is picked up at once.
  if (result.ok || result.kind !== 'missing') {
    cached = { at: now, credentials }
  }
  return credentials
}

/** Drop the in-memory cache. Used by tests and by explicit user refresh. */
export function invalidateCredentialCache(): void {
  cached = undefined
}

/**
 * Revoke the sealed session on disk as well.
 *
 * Called when the server refuses the session. Replacing it needs a fresh QR
 * scan, so keeping the file would only make every later request fail the same
 * way while the card still showed a signed-in account — the user's fix
 * (「重新登录」) would then look like it had no effect. Deleting it makes the
 * next request say "log in", which is the truth.
 */
export function clearCredentialCache(): void {
  cached = undefined
  clearBrowserCredentials()
}
