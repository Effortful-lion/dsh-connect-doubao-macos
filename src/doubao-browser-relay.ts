/**
 * Official-browser request relay.
 *
 * The QR login proves the account to Doubao, but it does not make a Node fetch
 * look like the official web client. This module deliberately does NOT build a
 * chat request or reproduce a_bogus: it asks the official page to send the turn
 * itself, then reads the response stream that page produced.
 *
 * Current scope: ordinary chat. Task mode keeps its existing local-tool path.
 * The official page chooses its own model and signs the request. IO.read drains
 * the resulting CDP body stream until the terminal SSE event; the existing SSE
 * parser still handles every frame afterwards.
 */
import { spawn, type ChildProcess } from 'node:child_process'
import { appendFileSync, existsSync, readFileSync } from 'node:fs'
import { homedir } from 'node:os'
import { join } from 'node:path'
import { browserProfileDir, findBrowser, openSocket, type SocketLike } from './doubao-auth-browser.ts'

const DEFAULT_PORT = 9333
const DEFAULT_TIMEOUT_MS = 120_000
const CHAT_PATH = '/chat/completion'
const CHAT_URL = 'https://www.doubao.com/chat/'

interface RelayConfig {
  enabled?: boolean
  port?: number
  timeoutMs?: number
}

interface RelayOptions {
  signal?: AbortSignal
  timeoutMs?: number
  /** Test/alternate debug endpoint; production uses the configured port. */
  port?: number
}

interface CdpTarget {
  type?: string
  url?: string
  webSocketDebuggerUrl?: string
}

interface CdpMessage {
  id?: number
  method?: string
  params?: Record<string, unknown>
  result?: Record<string, unknown>
  error?: { message?: string }
}

function config(): RelayConfig {
  try {
    const path = join(homedir(), '.dsh', 'doubao-browser-relay.json')
    return JSON.parse(readFileSync(path, 'utf8')) as RelayConfig
  } catch {
    return {}
  }
}

/**
 * Whether the official page could serve a turn at all right now.
 *
 * A Chromium alone is not enough: an empty profile opens a signed-out page, and
 * every relayed turn would end in a login wall instead of a reply. The cookie
 * database is the cheap on-disk evidence that this profile has signed in at
 * least once (Chrome keeps it under Default/Network since v96, Default before).
 */
export function browserRelayAvailable(): boolean {
  try {
    if (findBrowser() === undefined) return false
    const root = browserProfileDir()
    return existsSync(join(root, 'Default', 'Network', 'Cookies'))
      || existsSync(join(root, 'Default', 'Cookies'))
  } catch {
    return false
  }
}

/** Open the official page so a human can clear the challenge. Returns its URL. */
export async function openOfficialChat(port?: number): Promise<string> {
  const target = await ensureChatTarget(port ?? config().port ?? DEFAULT_PORT)
  return target.url ?? CHAT_URL
}

/** Read per request so the user can switch the relay without rebuilding. */
export function browserRelayEnabled(): boolean {
  // Explicit environment wins over the local file, which also keeps mocked
  // upstream tests isolated from a developer's real browser profile.
  if (process.env.DSH_DOUBAO_BROWSER_RELAY === '0') return false
  if (process.env.DSH_DOUBAO_BROWSER_RELAY === '1') return true
  return config().enabled === true
}

class Cdp {
  private nextId = 0
  private readonly pending = new Map<number, {
    resolve: (result: Record<string, unknown>) => void
    reject: (error: Error) => void
  }>()
  private readonly listeners = new Map<string, Set<(params: Record<string, unknown>) => void>>()

  private constructor(private readonly socket: SocketLike) {
    socket.addEventListener('message', (raw: unknown) => {
      const data = (raw as { data?: unknown }).data
      if (typeof data !== 'string') return
      let message: CdpMessage
      try { message = JSON.parse(data) as CdpMessage } catch { return }
      if (message.id !== undefined) {
        const pending = this.pending.get(message.id)
        if (pending === undefined) return
        this.pending.delete(message.id)
        if (message.error !== undefined) pending.reject(new Error(message.error.message ?? 'CDP error'))
        else pending.resolve(message.result ?? {})
        return
      }
      if (message.method === undefined) return
      for (const listener of this.listeners.get(message.method) ?? []) {
        listener(message.params ?? {})
      }
    })
    socket.addEventListener('error', () => {
      for (const pending of this.pending.values()) pending.reject(new Error('CDP socket error'))
      this.pending.clear()
    })
  }

  static async open(url: string): Promise<Cdp> {
    const socket = openSocket(url)
    if (socket === undefined) throw new Error('this Node build has no global WebSocket')
    await new Promise<void>((resolve, reject) => {
      socket.addEventListener('open', () => resolve())
      socket.addEventListener('error', () => reject(new Error('cannot connect to the official browser over CDP')))
    })
    return new Cdp(socket)
  }

  call(method: string, params: Record<string, unknown> = {}): Promise<Record<string, unknown>> {
    const id = ++this.nextId
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject })
      this.socket.send(JSON.stringify({ id, method, params }))
    })
  }

  on(method: string, listener: (params: Record<string, unknown>) => void): () => void {
    const listeners = this.listeners.get(method) ?? new Set()
    listeners.add(listener)
    this.listeners.set(method, listeners)
    return () => { listeners.delete(listener) }
  }

  close(): void {
    this.socket.close()
  }
}

let browserProcess: ChildProcess | undefined
let relayQueue: Promise<unknown> = Promise.resolve()

const sleep = (ms: number): Promise<void> => new Promise(resolve => setTimeout(resolve, ms))

function debug(message: string): void {
  if (process.env.DSH_DOUBAO_RELAY_DEBUG !== '1') return
  try {
    appendFileSync(join(homedir(), '.dsh', 'doubao-relay-debug.log'), `${new Date().toISOString()} ${message}\n`)
  } catch { /* diagnostics never break a turn */ }
}

async function listTargets(port: number): Promise<CdpTarget[]> {
  const response = await fetch(`http://127.0.0.1:${port}/json/list`, {
    signal: AbortSignal.timeout(1500),
  })
  if (!response.ok) throw new Error(`CDP target list failed: HTTP ${response.status}`)
  return await response.json() as CdpTarget[]
}

async function ensureChatTarget(port: number): Promise<CdpTarget> {
  const find = async (): Promise<CdpTarget | undefined> => {
    const targets = await listTargets(port)
    return targets.find(target => target.type === 'page' && target.url?.includes('doubao.com'))
  }
  try {
    const existing = await find()
    if (existing?.webSocketDebuggerUrl) return existing
  } catch {
    // No debuggable browser yet; launch the QR profile below.
  }

  if (browserProcess === undefined) {
    const executable = findBrowser()
    if (executable === undefined) throw new Error('找不到 Chrome 或 Edge，无法启动官方浏览器')
    browserProcess = spawn(executable, [
      `--remote-debugging-port=${port}`,
      `--user-data-dir=${browserProfileDir()}`,
      '--no-first-run',
      '--no-default-browser-check',
      CHAT_URL,
    ], { stdio: 'ignore' })
    // The browser is a shared user-facing service, not a reason the plugin CLI
    // or host must stay alive after its own work has finished.
    browserProcess.unref()
  }

  const deadline = Date.now() + 20_000
  while (Date.now() < deadline) {
    try {
      const target = await find()
      if (target?.webSocketDebuggerUrl) return target
    } catch {
      // Browser is still starting.
    }
    await sleep(400)
  }
  throw new Error('官方浏览器调试端口未就绪；如果扫码浏览器已打开，请先关闭它再重试')
}

async function waitForComposer(cdp: Cdp, timeoutMs: number): Promise<void> {
  const deadline = Date.now() + timeoutMs
  while (Date.now() < deadline) {
    const result = await cdp.call('Runtime.evaluate', {
      expression: `(() => {
        const el = document.querySelector('.ProseMirror') || document.querySelector('[contenteditable="true"]')
        if (!el) return false
        el.focus()
        return true
      })()`,
      returnByValue: true,
    })
    if ((result.result as { value?: unknown } | undefined)?.value === true) return
    await sleep(400)
  }
  throw new Error('官方页面没有找到对话输入框')
}

/** Submit through the page's own composer and capture the response it creates. */
async function relayOnce(prompt: string, options: RelayOptions): Promise<Response> {
  const cfg = config()
  const port = options.port ?? cfg.port ?? DEFAULT_PORT
  const timeoutMs = options.timeoutMs ?? cfg.timeoutMs ?? DEFAULT_TIMEOUT_MS
  const target = await ensureChatTarget(port)
  if (!target.webSocketDebuggerUrl) throw new Error('官方页面没有 CDP 地址')
  const cdp = await Cdp.open(target.webSocketDebuggerUrl)
  let timer: ReturnType<typeof setTimeout> | undefined
  let abortListener: (() => void) | undefined
  try {
    await cdp.call('Page.enable')
    const responsePromise = new Promise<Response>((resolve, reject) => {
      let settled = false
      let requestId: string | undefined
      let streamHandle: string | undefined
      let status = 200
      let statusText = ''
      let headers: Record<string, string> = {}
      const chunks: Buffer[] = []
      let terminalTail = ''
      const complete = (): void => {
        if (settled) return
        settled = true
        debug(`complete status=${status} chunks=${chunks.length}`)
        resolve(new Response(Buffer.concat(chunks), { status, statusText, headers }))
      }
      const fail = (error: Error): void => {
        if (settled) return
        settled = true
        debug(`fail ${error.message}`)
        reject(error)
      }
      // Response-stage interception leaves the request itself — including its
      // dynamic signature — untouched. Network.getResponseBody used to wait for
      // loadingFinished, which is too late for SSE connections that stay alive.
      const offPaused = cdp.on('Fetch.requestPaused', params => {
        if (requestId !== undefined) return
        requestId = String(params.requestId ?? '')
        status = typeof params.responseStatusCode === 'number' ? params.responseStatusCode : 200
        statusText = typeof params.responseStatusText === 'string' ? params.responseStatusText : ''
        const rawHeaders = params.responseHeaders
        if (Array.isArray(rawHeaders)) {
          for (const header of rawHeaders) {
            if (header && typeof header.name === 'string' && typeof header.value === 'string') {
              headers[header.name] = header.value
            }
          }
        } else if (rawHeaders && typeof rawHeaders === 'object') {
          headers = rawHeaders as Record<string, string>
        }
        debug(`paused request=${requestId} status=${status}`)
        void (async () => {
          try {
            const result = await cdp.call('Fetch.takeResponseBodyAsStream', { requestId })
            streamHandle = typeof result.stream === 'string' ? result.stream : undefined
            debug(`take stream=${String(result.stream ?? '(none)')}`)
            if (streamHandle === undefined) throw new Error('CDP returned no response stream handle')
            // Fetch.streamReceived is not delivered consistently across Chromium
            // versions. IO.read is the documented pull-based counterpart and
            // works for long-lived SSE responses as well as finite bodies.
            while (true) {
              const chunk = await cdp.call('IO.read', { handle: streamHandle, size: 65_536 })
              const encoded = chunk.base64Encoded === true
              const data = typeof chunk.data === 'string' ? chunk.data : ''
              const bytes = Buffer.from(data, encoded ? 'base64' : 'utf8')
              chunks.push(bytes)
              terminalTail = (terminalTail + bytes.toString('utf8')).slice(-500)
              const terminal = chunk.eof === true || /event:\s*(?:SSE_REPLY_END|STREAM_ERROR)/.test(terminalTail)
              debug(`chunk bytes=${bytes.length} eof=${String(chunk.eof === true)} terminal=${terminal}`)
              if (terminal) {
                await cdp.call('IO.close', { handle: streamHandle }).catch(() => {})
                complete()
                break
              }
            }
          } catch (error) { fail(error as Error) }
        })()
      })
      const offFailed = cdp.on('Network.loadingFailed', params => {
        if (String(params.requestId ?? '') !== requestId) return
        fail(new Error(`官方浏览器请求失败：${String(params.errorText ?? 'unknown')}`))
      })
      void cdp.call('Fetch.enable', {
        patterns: [{ urlPattern: '*://www.doubao.com/chat/completion*', requestStage: 'Response' }],
      }).catch(error => fail(error as Error))
      timer = setTimeout(() => fail(new Error('官方浏览器回复超时')), timeoutMs)
      if (options.signal !== undefined) {
        abortListener = () => {
          const error = new Error('The operation was aborted')
          error.name = 'AbortError'
          fail(error)
        }
        options.signal.addEventListener('abort', abortListener, { once: true })
      }
      void (async () => {
        try {
          // Each DSH turn is self-contained. Starting a new official conversation
          // avoids ever sending a delta without the history it depends on.
          await cdp.call('Page.navigate', { url: CHAT_URL })
          await waitForComposer(cdp, Math.min(timeoutMs, 20_000))
          await cdp.call('Input.insertText', { text: prompt })
          for (const type of ['keyDown', 'keyUp']) {
            await cdp.call('Input.dispatchKeyEvent', {
              type,
              key: 'Enter',
              code: 'Enter',
              windowsVirtualKeyCode: 13,
              nativeVirtualKeyCode: 13,
              text: type === 'keyDown' ? '\r' : '',
            })
          }
        } catch (error) { fail(error as Error) }
      })()
      void offPaused
      void offFailed
    })
    return await responsePromise
  } finally {
    if (timer !== undefined) clearTimeout(timer)
    if (abortListener !== undefined && options.signal !== undefined) {
      options.signal.removeEventListener('abort', abortListener)
    }
    cdp.close()
  }
}

/** Serialize turns: one official page must never submit two turns at once. */
export function browserRelayChat(prompt: string, options: RelayOptions = {}): Promise<Response> {
  const run = relayQueue.then(
    () => relayOnce(prompt, options),
    () => relayOnce(prompt, options),
  )
  relayQueue = run.catch(() => {})
  return run
}
