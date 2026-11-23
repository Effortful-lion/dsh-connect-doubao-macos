import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { REQUIRED_COOKIE_NAMES, type DoubaoCredentials } from '../src/doubao-auth.ts'
import { streamChat } from '../src/doubao-upstream.ts'

const credentials: DoubaoCredentials = {
  ok: true,
  header: 'sessionid=test',
  pairs: new Map(REQUIRED_COOKIE_NAMES.map(name => [name, 'test-value'])),
}

function frame(event: string, data: unknown): string {
  return `id: 1\nevent: ${event}\ndata: ${JSON.stringify(data)}\n\n`
}

const END = frame('SSE_REPLY_END', {})
const ACK = frame('SSE_ACK', { ack_client_meta: { conversation_id: 'conv-1' } })
const CHUNK = frame('STREAM_CHUNK', {
  content: { content_block: [{ block_type: 10000, content: { text_block: { text: 'ok' } } }] },
})

function successResponse(): Response {
  return new Response(ACK + CHUNK + END, { status: 200 })
}

let directory = ''
let statePath = ''

beforeEach(() => {
  directory = mkdtempSync(join(tmpdir(), 'doubao-risk-controls-'))
  statePath = join(directory, 'circuit.json')
  process.env.DSH_DOUBAO_BROWSER_RELAY = '0'
  process.env.DSH_DOUBAO_RISK_STATE_PATH = statePath
  process.env.DSH_DOUBAO_RISK_COOLDOWN_MS = '0'
  process.env.DSH_DOUBAO_MIN_INTERVAL_MS = '0'
})

afterEach(() => {
  vi.unstubAllGlobals()
  rmSync(directory, { recursive: true, force: true })
  delete process.env.DSH_DOUBAO_BROWSER_RELAY
  delete process.env.DSH_DOUBAO_RISK_STATE_PATH
  delete process.env.DSH_DOUBAO_RISK_COOLDOWN_MS
  delete process.env.DSH_DOUBAO_MIN_INTERVAL_MS
})

describe('direct-Node request controls', () => {
  it('serializes calls and waits a conservative interval between them', async () => {
    process.env.DSH_DOUBAO_MIN_INTERVAL_MS = '25'
    const times: number[] = []
    vi.stubGlobal('fetch', vi.fn(async () => {
      times.push(Date.now())
      return successResponse()
    }))
    const [a, b] = await Promise.all([
      streamChat('first', { credentials }),
      streamChat('second', { credentials }),
    ])
    expect(a.text).toBe('ok')
    expect(b.text).toBe('ok')
    expect(times).toHaveLength(2)
    expect(times[1]! - times[0]!).toBeGreaterThanOrEqual(15)
  })

  it('opens a persistent circuit after 710022004 and blocks the next upstream call', async () => {
    process.env.DSH_DOUBAO_RISK_COOLDOWN_MS = '10000'
    const fetchMock = vi.fn(async () => new Response(
      frame('STREAM_ERROR', { error_code: 710022004, error_msg: 'rate limit' }),
      { status: 200 },
    ))
    vi.stubGlobal('fetch', fetchMock)
    await expect(streamChat('first', { credentials })).rejects.toMatchObject({ code: 710022004 })
    expect(fetchMock).toHaveBeenCalledTimes(1)

    // The next request is rejected locally; it must not reach fetch again.
    await expect(streamChat('second', { credentials })).rejects.toMatchObject({
      code: 710022004,
      message: expect.stringContaining('没有向上游发送请求'),
    })
    expect(fetchMock).toHaveBeenCalledTimes(1)

    // Simulate expiry, then a healthy turn is allowed and clears the circuit.
    writeFileSync(statePath, JSON.stringify({ until: Date.now() - 1 }), 'utf8')
    vi.stubGlobal('fetch', vi.fn(async () => successResponse()))
    const result = await streamChat('third', { credentials })
    expect(result.text).toBe('ok')
  })
})
