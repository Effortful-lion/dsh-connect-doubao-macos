/**
 * Keep the suite independent of the machine's real Doubao account.
 *
 * The risk-control circuit and the request throttle are PERSISTED/global state
 * with production defaults: on a machine that recently hit `710022004` every
 * test that streams a turn is blocked before its mocked fetch is reached, and
 * the 8s default interval times tests out. Tests must opt out explicitly
 * instead of inheriting whatever the account happens to be doing.
 */
import { tmpdir } from 'node:os'
import { join } from 'node:path'

process.env.DSH_DOUBAO_RISK_STATE_PATH = join(tmpdir(), `dsh-doubao-test-circuit-${process.pid}.json`)
process.env.DSH_DOUBAO_RISK_COOLDOWN_MS = '0'
process.env.DSH_DOUBAO_MIN_INTERVAL_MS = '0'
// A test must never drive (or spawn) a real browser.
process.env.DSH_DOUBAO_BROWSER_RELAY = '0'
