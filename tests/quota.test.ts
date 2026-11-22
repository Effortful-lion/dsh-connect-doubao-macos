import { describe, expect, it } from 'vitest'

import { findWindow, millisUntilReset, normalizeWindow, type DoubaoQuota } from '../src/doubao-quota.ts'

/**
 * The payload shapes this account actually receives, captured from the live
 * quota endpoint and read off the Doubao panel.
 *
 * - `window_limit_section` → one weekly window, `start_time`/`end_time` both 0,
 *   amounts "0" / "2,100". The app renders this as 「近 7 天 · 开始使用后计时」,
 *   i.e. the window opens on first use and has NO reset instant to show.
 * - `incentive_quota_section` → the 「活动赠送额度」 grant: 782 of 1,600 used,
 *   an `end_time` (11月21日 09:46) but no `start_time`.
 *
 * The old normalizer only read the first section (so the grant being consumed
 * was invisible) and invented a reset instant from the nominal window length
 * (so the card counted down to a moment the server never sent).
 */
const WEEKLY_ONLY = {
  end_time: 0,
  start_time: 0,
  item_type: 0,
  less_than_one_percent: false,
  total_amount: '2,100',
  used_amount: '0',
  used_percent: 0,
  window_type: 2,
}

/** The package-credit allowance Doubao switched to in 2026-11. */
const PACKAGE_WINDOW = {
  end_time: 1_795_505_409_041,
  start_time: 0,
  item_type: 1,
  less_than_one_percent: false,
  total_amount: '9,000',
  used_amount: '449',
  used_percent: 4,
  window_type: 4,
}

const BONUS_GRANT = {
  end_time: 1_795_225_599_150,
  start_time: 0,
  item_type: 0,
  less_than_one_percent: false,
  total_amount: '1,600',
  used_amount: '782',
  used_percent: 48,
  window_type: 3,
}

function quotaOf(...windows: ReturnType<typeof normalizeWindow>[]): DoubaoQuota {
  return {
    exhausted: false,
    windows: windows.filter((window) => window !== undefined),
    fetchedAt: 1,
  }
}

describe('normalizeWindow', () => {
  it('keeps the weekly window and never invents a reset instant', () => {
    const window = normalizeWindow(WEEKLY_ONLY)
    expect(window).toBeDefined()
    expect(window?.type).toBe('weekly')
    expect(window?.usedPercent).toBe(0)
    expect(window?.remainingPercent).toBe(100)
    // No timestamps means the instant is unknown — not "seven days from now".
    expect(window?.resetUnknown).toBe(true)
    expect(window?.resetsAt).toBe(0)
    expect(window?.windowMs).toBe(0)
  })

  it('marks a not-yet-started window as starting on first use', () => {
    const window = normalizeWindow(WEEKLY_ONLY)
    expect(window?.startsOnUse).toBe(true)
    expect(millisUntilReset(window!, 1_000)).toBe(0)
  })

  it('reads the promotional grant, with its expiry but no start', () => {
    const window = normalizeWindow(BONUS_GRANT, '活动赠送额度')
    expect(window?.type).toBe('incentive')
    expect(window?.label).toBe('活动赠送额度')
    expect(window?.usedPercent).toBe(48)
    expect(window?.usedAmount).toBe(782)
    expect(window?.totalAmount).toBe(1600)
    // The expiry IS real: only the opening instant is missing.
    expect(window?.resetUnknown).toBeUndefined()
    expect(window?.startsOnUse).toBe(true)
    expect(window?.resetsAt).toBe(BONUS_GRANT.end_time)
    expect(window?.windowMs).toBe(0)
    expect(millisUntilReset(window!, 1_000)).toBe(BONUS_GRANT.end_time - 1_000)
  })

  it('parses the formatted amounts', () => {
    const window = normalizeWindow(WEEKLY_ONLY)
    expect(window?.usedAmount).toBe(0)
    expect(window?.totalAmount).toBe(2100)
  })

  it('derives the percentage from amounts when used_percent is absent', () => {
    const window = normalizeWindow({ ...BONUS_GRANT, used_percent: undefined, used_amount: '800' })
    expect(window?.usedPercent).toBeCloseTo(50)
    expect(window?.remainingPercent).toBeCloseTo(50)
  })

  it('prefers a reported used_percent over the amounts', () => {
    const window = normalizeWindow({ ...BONUS_GRANT, used_percent: 12, used_amount: '800' })
    expect(window?.usedPercent).toBe(12)
  })

  it('clamps a percentage derived from amounts into 0-100', () => {
    const window = normalizeWindow({ ...BONUS_GRANT, used_percent: undefined, used_amount: '9,999' })
    expect(window?.usedPercent).toBe(100)
  })

  it('keeps the reported window when both timestamps are real', () => {
    const start = 1_000
    const end = 604_801_000
    const window = normalizeWindow({ ...WEEKLY_ONLY, start_time: start, end_time: end })
    expect(window?.resetUnknown).toBeUndefined()
    expect(window?.startsOnUse).toBeUndefined()
    expect(window?.resetsAt).toBe(end)
    expect(window?.startedAt).toBe(start)
    expect(window?.windowMs).toBe(end - start)
    expect(millisUntilReset(window!, 2_000)).toBe(end - 2_000)
  })

  it('maps the package-credit window that replaced the rolling limits', () => {
    const window = normalizeWindow(PACKAGE_WINDOW)
    expect(window?.type).toBe('package')
    expect(window?.windowType).toBe(4)
    expect(window?.usedAmount).toBe(449)
    expect(window?.totalAmount).toBe(9000)
    expect(window?.usedPercent).toBe(4)
    // Only an expiry is sent: the window bills from first use.
    expect(window?.resetsAt).toBe(PACKAGE_WINDOW.end_time)
    expect(millisUntilReset(window!, 1_000)).toBe(PACKAGE_WINDOW.end_time - 1_000)
  })

  it('keeps reading the retired 5-hour and weekly types', () => {
    expect(normalizeWindow({ ...WEEKLY_ONLY, window_type: 1 })?.type).toBe('five_hour')
    expect(normalizeWindow(WEEKLY_ONLY)?.type).toBe('weekly')
  })

  it('ignores window types it does not model', () => {
    expect(normalizeWindow({ ...WEEKLY_ONLY, window_type: 9 })).toBeUndefined()
  })
})

describe('findWindow', () => {
  it('reports a missing five-hour bucket as undefined, not as zero usage', () => {
    const quota = quotaOf(normalizeWindow(WEEKLY_ONLY), normalizeWindow(BONUS_GRANT, '活动赠送额度'))
    expect(findWindow(quota, 'five_hour')).toBeUndefined()
    expect(findWindow(quota, 'weekly')?.totalAmount).toBe(2100)
  })

  it('finds the package window and the grant side by side', () => {
    const quota = quotaOf(normalizeWindow(PACKAGE_WINDOW), normalizeWindow(BONUS_GRANT, '活动赠送额度'))
    expect(findWindow(quota, 'package')?.totalAmount).toBe(9000)
    expect(findWindow(quota, 'incentive')?.usedAmount).toBe(782)
    // No 5-hour bucket in this account shape.
    expect(findWindow(quota, 'five_hour')).toBeUndefined()
  })

  it('finds the promotional grant in the same list', () => {
    const quota = quotaOf(normalizeWindow(WEEKLY_ONLY), normalizeWindow(BONUS_GRANT, '活动赠送额度'))
    const grant = findWindow(quota, 'incentive')
    expect(grant?.usedAmount).toBe(782)
    expect(grant?.label).toBe('活动赠送额度')
  })
})