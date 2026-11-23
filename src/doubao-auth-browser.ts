/**
 * Browser-based sign-in for the Doubao plugin.
 *
 * WHY THIS EXISTS
 *
 * This is the ONLY way the plugin obtains a session. It used to be the fallback
 * for machines without the desktop app, while the primary path decrypted the
 * app's own cookie jar; that primary path is gone (see `./doubao-auth.ts` for
 * why) because the running app locks its cookie database exclusively — which is
 * exactly the state this plugin is meant to run in.
 *
 * Doubao's passport endpoints are plain HTTPS + a `sessionid` cookie, and
 * `a_bogus`/`msToken` are NOT verified for the account/quota calls this plugin
 * makes — measured 2026-11-07: a request with a deliberately corrupted `a_bogus`
 * still answered 200, and only the cookie mattered. So a single interactive
 * sign-in in a real Chromium is enough, with no app and no signature algorithm.
 *
 * HOW
 *
 * Spawn Chrome/Edge against a DEDICATED profile under `~/.dsh` and drive it over
 * the DevTools protocol. `Storage.getCookies` is browser-scoped, so one call
 * returns every cookie for every context — no target attach, no page reload.
 * The profile persists between logins, so the second run usually finds the
 * session still valid and needs no scan at all.
 *
 * SECURITY: the returned pairs are the user's live session. They are handed to
 * `doubao-auth.ts`, which seals them with DPAPI before anything touches disk.
 * Nothing here logs a value.
 *
 * @module dsh-connect-doubao-macos/auth-browser
 */
import { spawn, spawnSync, type ChildProcess } from 'node:child_process'
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { createServer } from 'node:net'
import { homedir } from 'node:os'
import { dirname, join, win32 } from 'node:path'
import { CORE_AUTH_COOKIE_NAMES, REQUIRED_COOKIE_NAMES } from './doubao-auth.ts'

/** Domains whose cookies belong to Doubao (the passport jar spans several). */
const DOUBAO_DOMAIN = /(^|\.)(doubao|bytedance|zijieapi)\.com$/i

/** Where the dedicated Chromium profile lives. Persisted on purpose. */
export function browserProfileDir(): string {
  return join(homedir(), '.dsh', 'doubao-browser-profile')
}

/**
 * Chromium binaries worth trying, per platform.
 *
 * macOS installs are application BUNDLES, and the binary inside them is not
 * reliably named after the app (Chrome ships `.../MacOS/Google Chrome`, Edge
 * ships `.../MacOS/Microsoft Edge`), so each entry is resolved through the
 * bundle's own `Info.plist` instead of being guessed.
 */
const WINDOWS_CANDIDATES = [
  'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
  'C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe',
  'C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe',
  'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe',
]

/** Default CDP debug port (login uses a dynamic free port based on this). */
const DEFAULT_DEBUG_PORT = 9333

/** macOS app bundles that carry a Chromium engine the sign-in can use. */
const MACOS_BUNDLES = [
  'Google Chrome.app',
  'Google Chrome Beta.app',
  'Google Chrome Canary.app',
  'Microsoft Edge.app',
  'Chromium.app',
  'Brave Browser.app',
]

/** Env var to point at a browser binary the discovery list misses. */
export const BROWSER_ENV = 'DSH_DOUBAO_BROWSER'

/** Host page for the sign-in. `/chat` is the page that actually mints the jar. */
const LOGIN_URL = 'https://www.doubao.com/chat/'

export interface BrowserLoginOptions {
  /** Overall budget for the user to finish signing in. Default 5 minutes. */
  timeoutMs?: number
  /** Called with progress text; the route does not need it, the CLI does. */
  onProgress?: (message: string) => void
}

export interface BrowserLoginResult {
  ok: boolean
  /** Actionable failure text, or undefined on success. Never a secret. */
  reason?: string
  /** `name=value` pairs for a Cookie header. Empty on failure. */
  pairs?: Map<string, string>
  /** Ready-made `Cookie:` header value. Empty on failure. */
  header?: string
  /**
   * Whether the request identity was captured from the page that signed in.
   *
   * `captured` means the plugin now presents the SAME web identity as the
   * browser that owns these cookies — the condition that keeps `710022004`
   * away. `undefined` means capture did not run or failed; the session itself
   * is still valid.
   */
  fingerprint?: 'captured'
}

/** Minimal CDP cookie shape — only the fields this module reads. */
interface CdpCookie {
  name?: unknown
  value?: unknown
  domain?: unknown
  expires?: unknown
}

/**
 * The executable inside a macOS app bundle, read from the bundle's own plist.
 *
 * The binary is NOT reliably named after the app, and a path assembled as
 * `<bundle>/Contents/MacOS/<AppName without .app>` misses real installs. The
 * bundle documents the real name, so asking it is both correct and robust to a
 * future build that renames the binary.
 */
function macosBundleExecutable(bundle: string): string | undefined {
  const plist = join(bundle, 'Contents', 'Info.plist')
  if (!existsSync(plist)) return undefined
  // PlistBuddy handles both XML and binary plists; a regex over the raw file
  // would only ever work for the XML half.
  const result = spawnSync('/usr/libexec/PlistBuddy', ['-c', 'Print :CFBundleExecutable', plist], {
    encoding: 'utf8',
    timeout: 5_000,
  })
  const name = (result.stdout ?? '').trim()
  if (result.status !== 0 || name === '') return undefined
  const binary = join(bundle, 'Contents', 'MacOS', name)
  return existsSync(binary) ? binary : undefined
}

/** Find an installed Chromium binary, or undefined. */
export function findBrowser(): string | undefined {
  // 1. explicit override — the escape hatch for a non-standard install.
  const override = process.env[BROWSER_ENV]
  if (typeof override === 'string' && override.trim() !== '' && existsSync(override.trim())) {
    return override.trim()
  }

  // 2. the platform's usual locations.
  if (process.platform === 'darwin') {
    for (const bundle of MACOS_BUNDLES) {
      for (const root of ['/Applications', join(homedir(), 'Applications')]) {
        const binary = macosBundleExecutable(join(root, bundle))
        if (binary !== undefined) return binary
      }
    }
    return undefined
  }

  for (const candidate of WINDOWS_CANDIDATES) {
    if (existsSync(candidate)) return candidate
  }
  return undefined
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => { setTimeout(resolve, ms) })
}

async function allocateDebugPort(): Promise<number> {
  return await new Promise<number>((resolve) => {
    const server = createServer()
    server.unref()
    server.on('error', () => resolve(DEFAULT_DEBUG_PORT))
    server.listen(0, '127.0.0.1', () => {
      const address = server.address()
      const port = typeof address === 'object' && address !== null ? address.port : DEFAULT_DEBUG_PORT
      server.close(() => resolve(port > 0 ? port : DEFAULT_DEBUG_PORT))
    })
  })
}

async function probeDevtools(port: number): Promise<string | undefined> {
  try {
    const response = await fetch(`http://127.0.0.1:${port}/json/version`, {
      signal: AbortSignal.timeout(2000),
    })
    if (response.ok) {
      const body = await response.json() as { webSocketDebuggerUrl?: unknown }
      if (typeof body.webSocketDebuggerUrl === 'string') return body.webSocketDebuggerUrl
    }
  } catch {
    // Not listening yet.
  }
  return undefined
}

/** Poll `http://127.0.0.1:<port>/json/version` until it answers or the browser exits. */
async function waitForDevtools(
  port: number,
  deadline: number,
  isChildExited: () => boolean,
): Promise<{ wsUrl: string; port: number; attachedExisting: boolean } | undefined> {
  while (Date.now() < deadline) {
    const wsUrl = await probeDevtools(port)
    if (wsUrl !== undefined) return { wsUrl, port, attachedExisting: false }
    if (isChildExited()) {
      // Chrome hands off to an already-running instance on the same profile and
      // exits immediately; check the default `--verify`/`--relay` port once.
      const existing = await probeDevtools(DEFAULT_DEBUG_PORT)
      if (existing !== undefined) {
        return { wsUrl: existing, port: DEFAULT_DEBUG_PORT, attachedExisting: true }
      }
      return undefined
    }
    await sleep(300)
  }
  return undefined
}

/** The global WebSocket (Node 22+), typed structurally to avoid lib assumptions. */
export type SocketLike = {
  addEventListener: (type: string, listener: (event: unknown) => void) => void
  send: (data: string) => void
  close: () => void
}

export function openSocket(url: string): SocketLike | undefined {
  const Ctor = (globalThis as { WebSocket?: new (url: string) => SocketLike }).WebSocket
  return Ctor === undefined ? undefined : new Ctor(url)
}

/** Run a single browser-level CDP command and return its `result` payload. */
async function cdpCommand(
  wsUrl: string,
  method: string,
  params: Record<string, unknown> = {},
  timeoutMs = 15_000,
): Promise<Record<string, unknown>> {
  const socket = openSocket(wsUrl)
  if (socket === undefined) throw new Error('this Node build has no global WebSocket')
  return await new Promise<Record<string, unknown>>((resolve, reject) => {
    const timer = setTimeout(() => {
      try { socket.close() } catch { /* already closing */ }
      reject(new Error(`CDP timeout while running ${method}`))
    }, timeoutMs)

    socket.addEventListener('open', () => {
      socket.send(JSON.stringify({ id: 1, method, params }))
    })
    socket.addEventListener('error', () => {
      clearTimeout(timer)
      reject(new Error('CDP socket error'))
    })
    socket.addEventListener('message', (event: unknown) => {
      const data = (event as { data?: unknown }).data
      if (typeof data !== 'string') return
      let message: { id?: unknown; result?: Record<string, unknown>; error?: { message?: unknown } }
      try {
        message = JSON.parse(data) as typeof message
      } catch {
        return
      }
      if (message.id !== 1) return
      clearTimeout(timer)
      try { socket.close() } catch { /* already closed */ }
      if (message.error !== undefined) {
        reject(new Error(String(message.error.message ?? 'CDP error')))
        return
      }
      resolve(message.result ?? {})
    })
  })
}

/**
 * One `Storage.getCookies` round-trip.
 *
 * Browser-scoped on purpose: the page target may still be navigating, and
 * attaching to it would race the sign-in redirect chain.
 */
async function readCookies(wsUrl: string, timeoutMs = 15_000): Promise<CdpCookie[]> {
  const result = await cdpCommand(wsUrl, 'Storage.getCookies', {}, timeoutMs)
  const cookies = result.cookies
  return Array.isArray(cookies) ? cookies as CdpCookie[] : []
}

async function clearCookiesAndReload(wsUrl: string, port: number): Promise<void> {
  await cdpCommand(wsUrl, 'Storage.clearCookies', {}).catch(() => {})
  const pageWs = await chatTarget(port)
  if (pageWs !== undefined) {
    await cdpCommand(pageWs, 'Page.navigate', { url: LOGIN_URL }, 5_000).catch(() => {})
  }
}

async function verifySessionOnline(header: string): Promise<'valid' | 'rejected' | 'unknown'> {
  try {
    const response = await fetch(
      'https://www.doubao.com/passport/account/info/v2/?aid=497858&device_platform=web',
      {
        method: 'GET',
        headers: {
          cookie: header,
          Referer: LOGIN_URL,
          accept: 'application/json, text/plain, */*',
        },
        signal: AbortSignal.timeout(5_000),
      },
    )
    if (response.status === 401 || response.status === 403) return 'rejected'
    if (!response.ok) return 'unknown'
    const payload = await response.json() as { data?: { name?: unknown; error_code?: unknown } }
    if (typeof payload.data?.name === 'string' && payload.data.name !== '') return 'valid'
    return 'rejected'
  } catch {
    return 'unknown'
  }
}

/** Pick the Doubao cookies into `name → value`. */
function pickPairs(cookies: readonly CdpCookie[]): Map<string, string> {
  const pairs = new Map<string, string>()
  for (const cookie of cookies) {
    const name = cookie.name
    const value = cookie.value
    const domain = cookie.domain
    if (typeof name !== 'string' || typeof value !== 'string' || value === '') continue
    if (typeof domain !== 'string' || !DOUBAO_DOMAIN.test(domain.replace(/^\./, ''))) continue
    // First writer wins: the more specific host is listed first by CDP in
    // practice, and a later `.doubao.com` duplicate must not shadow it.
    if (!pairs.has(name)) pairs.set(name, value)
  }
  return pairs
}

function buildCookieHeader(pairs: Map<string, string>): string {
  return [...pairs.entries()].map(([name, value]) => `${name}=${value}`).join('; ')
}

/** Kill a spawned browser including its renderer children. */
function terminate(child: ChildProcess): void {
  if (process.platform === 'darwin') {
    // Chromium on macOS forks helpers (renderer/gpu/crashpad) that survive a
    // plain kill of the main process and keep the user-data-dir locked. The
    // profile path is unique to this plugin, so matching on it is both
    // surgical and complete.
    try {
      spawnSync('pkill', ['-f', browserProfileDir()], { stdio: 'ignore' })
    } catch { /* pkill missing: fall through to the pid kill */ }
    try { child.kill('SIGTERM') } catch { /* gone already */ }
    return
  }
  if (child.pid === undefined) return
  try {
    // Windows: `child.kill()` leaves the renderer/gpu children behind, which
    // keeps the user-data-dir locked and the next login fails to start.
    spawnSync('taskkill', ['/PID', String(child.pid), '/T', '/F'], { stdio: 'ignore' })
  } catch {
    try { child.kill() } catch { /* gone already */ }
  }
}

/**
 * Run one interactive sign-in and return the harvested cookies.
 *
 * The caller decides where the credentials go; this function never writes them
 * anywhere. A browser window stays open for the whole budget, so the user can
 * finish a QR scan or an SMS code at their own pace.
 */
export async function browserLogin(options: BrowserLoginOptions = {}): Promise<BrowserLoginResult> {
  const say = options.onProgress ?? (() => {})
  const exe = findBrowser()
  if (exe === undefined) {
    return {
      ok: false,
      reason: '没找到 Chrome 或 Edge。浏览器扫码登录需要一个 Chromium 内核的浏览器。',
    }
  }

  const timeoutMs = options.timeoutMs ?? 300_000
  const deadline = Date.now() + timeoutMs
  const profile = browserProfileDir()
  mkdirSync(profile, { recursive: true })

  // Allocate an ephemeral debug port so another local tool (or an old browser
  // session) holding 9333 cannot collide with sign-in.
  const port = await allocateDebugPort()
  let childExited = false
  let spawnError: Error | undefined
  const child = spawn(exe, [
    `--remote-debugging-port=${String(port)}`,
    `--user-data-dir=${profile}`,
    '--no-first-run',
    '--no-default-browser-check',
    '--disable-features=Translate',
    LOGIN_URL,
  ], { stdio: 'ignore', detached: false })
  child.once('exit', () => { childExited = true })
  child.once('error', (error) => { spawnError = error; childExited = true })

  let attachedExisting = false
  try {
    say('已打开浏览器，请在弹出的窗口里扫码或短信登录…')
    const attached = await waitForDevtools(port, Math.min(deadline, Date.now() + 20_000), () => childExited)
    if (attached === undefined) {
      if (spawnError !== undefined) {
        return { ok: false, reason: `无法启动登录浏览器：${spawnError.message}` }
      }
      if (childExited) {
        return { ok: false, reason: '登录浏览器启动后立即退出（可能已有同配置窗口占用，请关闭后再试）。' }
      }
      return { ok: false, reason: `浏览器调试端口 ${String(port)} 没起来（可能被安全软件拦截或端口被占用）。` }
    }
    const wsUrl = attached.wsUrl
    const activePort = attached.port
    attachedExisting = attached.attachedExisting

    let lastNote = 0
    let checkedInitial = false
    let preferredWaitStartedAt: number | undefined
    while (Date.now() < deadline) {
      if (!attachedExisting && childExited) {
        return { ok: false, reason: '浏览器窗口已关闭，登录未完成。' }
      }
      let cookies: CdpCookie[] = []
      try {
        cookies = await readCookies(wsUrl)
      } catch (error: unknown) {
        if (!attachedExisting && childExited) {
          return { ok: false, reason: '浏览器窗口已关闭，登录未完成。' }
        }
        // The page may be mid-navigation; retry until the deadline.
        say(`读取登录态失败，重试中：${(error as Error).message}`)
        await sleep(1500)
        continue
      }
      let pairs = pickPairs(cookies)

      // If the persistent profile already held a stale/rejected or incomplete
      // session on startup, clear it once so the official page presents a clean
      // login screen instead of immediately sealing dead cookies.
      if (!checkedInitial) {
        checkedInitial = true
        if (pairs.get('sessionid') !== undefined) {
          const missingCore = CORE_AUTH_COOKIE_NAMES.filter((name) => !pairs.get(name))
          const verdict = missingCore.length > 0 ? 'rejected' : await verifySessionOnline(buildCookieHeader(pairs))
          if (verdict === 'rejected') {
            say('检测到旧登录态已失效，已清理，请在窗口里重新扫码登录…')
            await clearCookiesAndReload(wsUrl, activePort)
            await sleep(1200)
            continue
          }
        }
      }

      if (pairs.get('sessionid') !== undefined) {
        const missingCore = CORE_AUTH_COOKIE_NAMES.filter((name) => !pairs.get(name))
        if (missingCore.length > 0) {
          // A `sessionid` without `uid_tt`/`sid_tt` is a half-written jar: the
          // sign-in wrote cookies in stages. Waiting one more tick avoids
          // sealing a session the server will reject as "会话过期".
          say(`登录已开始，等待核心 cookie 补齐（缺 ${missingCore.join(', ')}）…`)
          await sleep(1000)
          continue
        }

        // Wait briefly (up to 6s) for auxiliary cookies (`sid_guard`, `ttwid`,
        // `odin_tt`, `passport_csrf_token`, `s_v_web_id`) to finish arriving
        // before closing the browser window.
        const missingPreferred = REQUIRED_COOKIE_NAMES.filter((name) => !pairs.get(name))
        if (missingPreferred.length > 0) {
          preferredWaitStartedAt ??= Date.now()
          if (Date.now() - preferredWaitStartedAt < Math.min(6_000, Math.max(0, deadline - Date.now() - 2_000))) {
            say(`登录已开始，等待辅助 cookie 补齐（缺 ${missingPreferred.join(', ')}）…`)
            await sleep(500)
            continue
          }
        }

        say(`已取到登录态（${String(pairs.size)} 条 cookie）`)
        // The browser that just signed in also defines how its requests LOOK.
        // Capturing here is the only moment the profile, the cookies and the
        // page are guaranteed to agree — and it is what lets every user get a
        // consistent identity without a manual setup step.
        const fingerprint = await captureFingerprintFromPort(activePort, Math.min(8_000, Math.max(1_000, deadline - Date.now())))
        if (fingerprint !== undefined) {
          try {
            writeBrowserFingerprint(fingerprint)
            say('已记录网页身份（UA / Referer / aid / device_id）')
          } catch {
            // A missing fingerprint degrades to the desktop identity; it must
            // never fail a sign-in that already succeeded.
          }
        }
        // Reloading during fingerprint capture often finishes minting delayed
        // cookies (`ttwid` / `s_v_web_id` / `msToken`); refresh the jar once.
        try {
          const refreshed = pickPairs(await readCookies(wsUrl, 5_000))
          if (CORE_AUTH_COOKIE_NAMES.every((name) => refreshed.get(name))) {
            pairs = refreshed
          }
        } catch {
          /* keep the already-valid cookie map */
        }
        const header = buildCookieHeader(pairs)
        return { ok: true, pairs, header, ...(fingerprint === undefined ? {} : { fingerprint: 'captured' as const }) }
      }
      if (Date.now() - lastNote > 10_000) {
        lastNote = Date.now()
        say(`… 等待扫码（已看到 ${String(cookies.length)} 条浏览器 cookie）`)
      }
      await sleep(2000)
    }
    return { ok: false, reason: '等待登录超时。扫码完成后请重试。' }
  } finally {
    if (!attachedExisting && !childExited) terminate(child)
  }
}

/* ------------------------------------------------------------------ *
 * Request identity captured from the official page
 * ------------------------------------------------------------------ */

/**
 * The identity the OFFICIAL web page presents on its own API calls.
 *
 * QR login proves the account; it does not make a Node fetch look like the
 * browser that owns the cookies. These four fields are exactly what the
 * risk-control layer compares: the user agent, the page that issued the call,
 * its client hints, and the full non-secret query (aid / device ids / platform).
 * Persisting them in `~/.dsh/doubao-browser-fingerprint.json` lets the direct
 * path present ONE consistent identity instead of a desktop shell wearing web
 * cookies.
 */
export interface BrowserFingerprint {
  userAgent: string
  referer: string
  secChUa?: string
  query: Record<string, string>
}

export interface BrowserCaptureOptions {
  port?: number
  timeoutMs?: number
  onProgress?: (message: string) => void
}

export interface BrowserCaptureResult {
  ok: boolean
  reason?: string
  /** Non-secret identity; present only when ok. */
  fingerprint?: BrowserFingerprint
}

/**
 * Params that must never be frozen into a config file.
 *
 * `msToken` / `a_bogus` are per-request signatures and `web_tab_id` is minted
 * by the client on every call — persisting any of them would replay a stale
 * value on every future request.
 */
const VOLATILE_QUERY = new Set([
  'mstoken',
  'ms_token',
  'a_bogus',
  'x-bogus',
  '_signature',
  'web_tab_id',
])

/** Drop per-request/secret params, keep the stable identity. */
export function sanitizeFingerprintQuery(
  input: URLSearchParams | Record<string, string> | string,
): Record<string, string> {
  const entries = typeof input === 'string'
    ? [...new URLSearchParams(input).entries()]
    : input instanceof URLSearchParams
      ? [...input.entries()]
      : Object.entries(input)
  const out: Record<string, string> = {}
  for (const [rawKey, value] of entries) {
    const key = rawKey.trim()
    if (key === '' || value === '') continue
    if (VOLATILE_QUERY.has(key.toLowerCase())) continue
    out[key] = value
  }
  return out
}

/**
 * Build a fingerprint from ONE observed request, or undefined when the request
 * is not a Doubao app call we can trust (other host, no aid, no user agent).
 */
export function fingerprintFromRequest(
  url: string,
  headers: Record<string, string>,
): BrowserFingerprint | undefined {
  let parsed: URL
  try {
    parsed = new URL(url)
  } catch {
    return undefined
  }
  // The web app's own API calls are same-origin; upload/CDN hosts carry a
  // different query shape and must not become the identity.
  if (parsed.hostname !== 'www.doubao.com') return undefined
  const query = sanitizeFingerprintQuery(parsed.searchParams)
  if (query.aid === undefined) return undefined
  const userAgent = headers['User-Agent'] ?? headers['user-agent'] ?? ''
  if (userAgent === '') return undefined
  const referer = headers.Referer ?? headers.referer ?? `${parsed.origin}/chat/`
  const secChUa = headers['sec-ch-ua'] ?? headers['Sec-CH-UA']
  return {
    userAgent,
    referer,
    ...(secChUa === undefined ? {} : { secChUa }),
    query,
  }
}

/** Where the captured identity lives. The upstream client reads this file. */
export function browserFingerprintPath(): string {
  return join(homedir(), '.dsh', 'doubao-browser-fingerprint.json')
}

/** Persist the fingerprint where the upstream client reads it. No credentials. */
export function writeBrowserFingerprint(fingerprint: BrowserFingerprint): string {
  const path = browserFingerprintPath()
  mkdirSync(dirname(path), { recursive: true })
  writeFileSync(path, JSON.stringify(fingerprint, null, 2) + '\n', 'utf8')
  return path
}

/** Read the captured identity back, or undefined when none is usable. */
export function readBrowserFingerprint(): BrowserFingerprint | undefined {
  try {
    const parsed = JSON.parse(readFileSync(browserFingerprintPath(), 'utf8')) as Partial<BrowserFingerprint>
    const query = parsed.query
    if (typeof parsed.userAgent !== 'string' || typeof parsed.referer !== 'string') return undefined
    if (query === undefined || typeof query !== 'object' || Array.isArray(query)) return undefined
    const pairs = Object.entries(query as Record<string, unknown>)
      .filter((entry): entry is [string, string] => typeof entry[1] === 'string')
    return {
      userAgent: parsed.userAgent,
      referer: parsed.referer,
      ...(typeof parsed.secChUa === 'string' ? { secChUa: parsed.secChUa } : {}),
      query: Object.fromEntries(pairs),
    }
  } catch {
    return undefined
  }
}

/**
 * Best-effort capture from whatever devtools browser is listening on `port`.
 *
 * Never throws: a capture failure leaves the caller's session valid and only
 * degrades the request identity back to the desktop one. Exported so the login
 * flow and the CLI share one implementation (and one test).
 */
export async function captureFingerprintFromPort(
  port: number,
  timeoutMs = 8_000,
): Promise<BrowserFingerprint | undefined> {
  try {
    const budget = Math.max(1_000, timeoutMs)
    const wsUrl = await waitForChatTarget(port, Date.now() + Math.min(budget, 5_000))
    if (wsUrl === undefined) return undefined
    return await readFingerprint(wsUrl, Date.now() + budget)
  } catch {
    return undefined
  }
}

async function chatTarget(port: number): Promise<string | undefined> {
  try {
    const response = await fetch(`http://127.0.0.1:${String(port)}/json/list`, {
      signal: AbortSignal.timeout(1500),
    })
    if (!response.ok) return undefined
    const targets = await response.json() as Array<{
      type?: unknown
      url?: unknown
      webSocketDebuggerUrl?: unknown
    }>
    const page = targets.find((target) =>
      target.type === 'page' && typeof target.url === 'string' && target.url.includes('doubao.com'))
    return typeof page?.webSocketDebuggerUrl === 'string' ? page.webSocketDebuggerUrl : undefined
  } catch {
    return undefined
  }
}

async function waitForChatTarget(port: number, deadline: number): Promise<string | undefined> {
  while (Date.now() < deadline) {
    const socketUrl = await chatTarget(port)
    if (socketUrl !== undefined) return socketUrl
    await sleep(400)
  }
  return undefined
}

interface CdpMessage {
  id?: number
  method?: string
  params?: Record<string, unknown>
  error?: { message?: string }
}

/**
 * Watch ONE real app request on the page and read its identity.
 *
 * Nothing is typed and no turn is sent: the page is reloaded so it re-issues
 * the requests it makes on its own, and the first call carrying `aid` is the
 * sample. A reload costs no inference quota.
 */
async function readFingerprint(wsUrl: string, deadline: number): Promise<BrowserFingerprint> {
  const socket = openSocket(wsUrl)
  if (socket === undefined) throw new Error('this Node build has no global WebSocket')
  let id = 0
  const call = (method: string, params: Record<string, unknown> = {}): void => {
    id += 1
    socket.send(JSON.stringify({ id, method, params }))
  }
  return await new Promise<BrowserFingerprint>((resolve, reject) => {
    let settled = false
    const finish = (run: () => void): void => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      try { socket.close() } catch { /* already closing */ }
      run()
    }
    const timer = setTimeout(() => {
      finish(() => reject(new Error('等待官方页面的请求超时')))
    }, Math.max(1000, deadline - Date.now()))
    socket.addEventListener('error', () => {
      finish(() => reject(new Error('CDP socket error')))
    })
    socket.addEventListener('open', () => {
      call('Network.enable')
      // Re-issue the app's own startup calls; this never sends a prompt.
      setTimeout(() => { if (!settled) call('Page.reload', { ignoreCache: false }) }, 600)
    })
    socket.addEventListener('message', (event: unknown) => {
      const data = (event as { data?: unknown }).data
      if (typeof data !== 'string') return
      let message: CdpMessage
      try { message = JSON.parse(data) as CdpMessage } catch { return }
      if (message.method !== 'Network.requestWillBeSent') return
      const request = (message.params as {
        request?: { url?: unknown; headers?: unknown }
      } | undefined)?.request
      if (request === undefined || typeof request.url !== 'string') return
      const headers = request.headers as Record<string, string> | undefined
      if (headers === undefined) return
      const fingerprint = fingerprintFromRequest(request.url, headers)
      if (fingerprint === undefined) return
      finish(() => resolve(fingerprint))
    })
  })
}

/**
 * Capture the official page's request identity.
 *
 * Attaches to an already-open debugging browser first; otherwise opens the same
 * dedicated profile the QR login uses and closes it afterwards. The profile
 * keeps its device ids across runs, so repeated captures stay consistent.
 */
export async function captureBrowserFingerprint(
  options: BrowserCaptureOptions = {},
): Promise<BrowserCaptureResult> {
  const say = options.onProgress ?? (() => {})
  const port = options.port ?? 9333
  const budget = options.timeoutMs ?? 30_000
  const deadline = Date.now() + budget
  let spawned: ChildProcess | undefined

  let wsUrl = await chatTarget(port)
  if (wsUrl === undefined) {
    const exe = findBrowser()
    if (exe === undefined) return { ok: false, reason: '没找到 Chrome 或 Edge。' }
    const profile = browserProfileDir()
    mkdirSync(profile, { recursive: true })
    spawned = spawn(exe, [
      `--remote-debugging-port=${String(port)}`,
      `--user-data-dir=${profile}`,
      '--no-first-run',
      '--no-default-browser-check',
      LOGIN_URL,
    ], { stdio: 'ignore', detached: false })
    say('已打开官方页面，正在读取它自己的请求身份…')
    wsUrl = await waitForChatTarget(port, Math.min(deadline, Date.now() + 20_000))
  } else {
    say('已连接到正在运行的官方页面，正在读取它的请求身份…')
  }

  if (wsUrl === undefined) {
    if (spawned !== undefined) terminate(spawned)
    return { ok: false, reason: `调试端口 ${String(port)} 上没找到豆包页面（可能被占用或浏览器没起来）。` }
  }

  try {
    const fingerprint = await readFingerprint(wsUrl, Math.min(deadline, Date.now() + 20_000))
    return { ok: true, fingerprint }
  } catch (error) {
    return { ok: false, reason: (error as Error).message }
  } finally {
    if (spawned !== undefined) terminate(spawned)
  }
}
