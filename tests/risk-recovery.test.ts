/**
 * Risk-control recovery semantics.
 *
 * Two failures share the code 710022004 and must NOT share a message:
 *
 *  - the server challenged the turn  -> a human has to clear the slider;
 *  - the plugin refused locally      -> nothing was sent, only a reset helps.
 *
 * These tests pin the distinction, the actionable text, and the reset itself.
 */
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { REQUIRED_COOKIE_NAMES, type DoubaoCredentials } from '../src/doubao-auth.ts'
import {
  clearRiskCircuit,
  describeDoubaoFailure,
  riskCircuitRemainingMs,
  streamChat,
} from '../src/doubao-upstream.ts'

const credentials: DoubaoCredentials = {
  ok: true,
  header: 'sessionid=test',
  pairs: new Map(REQUIRED_COOKIE_NAMES.map(name => [name, 'test-value'])),
}

let directory = ''
let statePath = ''

function challengeResponse(): Response {
  return new Response(
    'id: 1\nevent: STREAM_ERROR\ndata: ' + JSON.stringify({ error_code: 710022004, error_msg: 'rate limit' }) + '\n\n',
    { status: 200 },
  )
}

beforeEach(() => {
  directory = mkdtempSync(join(tmpdir(), 'doubao-risk-recovery-'))
  statePath = join(directory, 'circuit.json')
  process.env.DSH_DOUBAO_BROWSER_RELAY = '0'
  process.env.DSH_DOUBAO_RISK_STATE_PATH = statePath
  process.env.DSH_DOUBAO_RISK_COOLDOWN_MS = '0'
  process.env.DSH_DOUBAO_MIN_INTERVAL_MS = '0'
  delete process.env.DSH_DOUBAO_TASK
})

afterEach(() => {
  vi.unstubAllGlobals()
  rmSync(directory, { recursive: true, force: true })
  for (const name of [
    'DSH_DOUBAO_BROWSER_RELAY',
    'DSH_DOUBAO_RISK_STATE_PATH',
    'DSH_DOUBAO_RISK_COOLDOWN_MS',
    'DSH_DOUBAO_MIN_INTERVAL_MS',
    'DSH_DOUBAO_TASK',
  ]) delete process.env[name]
})

describe('risk-control recovery', () => {
  it('marks a locally blocked turn as local and sends nobody to the web page', async () => {
    writeFileSync(statePath, JSON.stringify({ until: Date.now() + 10 * 60_000 }), 'utf8')
    expect(riskCircuitRemainingMs()).toBeGreaterThan(0)

    const fetchMock = vi.fn(async () => challengeResponse())
    vi.stubGlobal('fetch', fetchMock)

    const error = await streamChat('hello', { credentials }).catch((caught: unknown) => caught)
    expect(error).toMatchObject({ code: 710022004, local: true })
    expect(fetchMock).not.toHaveBeenCalled()
    expect(describeDoubaoFailure(error)).toContain('--resume')
    expect(describeDoubaoFailure(error)).not.toContain('--verify')
  })

  it('reports a real challenge with the verification command, and is not marked local', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => challengeResponse()))

    const error = await streamChat('hello', { credentials }).catch((caught: unknown) => caught)
    expect(error).toMatchObject({ code: 710022004, local: false })
    const message = describeDoubaoFailure(error)
    expect(message).toContain('--verify')
    expect(message).toContain('710022004')
  })

  it('clears the cooldown so the next turn can reach the network again', async () => {
    writeFileSync(statePath, JSON.stringify({ until: Date.now() + 10 * 60_000 }), 'utf8')
    clearRiskCircuit()
    expect(riskCircuitRemainingMs()).toBe(0)
  })
})
