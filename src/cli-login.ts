#!/usr/bin/env node
/**
 * `dsh-connect-doubao-macos login` — one interactive browser sign-in, from the terminal.
 *
 * The settings card has the same button, and for a desktop user it is the
 * natural place to click. This exists anyway because a terminal sign-in is
 * easier to script and to debug on macOS: it prints the browser it picked, the
 * cookie count it harvested and which sealing backend stored the result — none
 * of which fit on a card.
 *
 * Nothing here prints a cookie value. The session goes straight to the sealed
 * file; the only output is counts, paths and booleans.
 */
import { browserLogin, findBrowser, BROWSER_ENV } from './doubao-auth-browser.ts'
import { saveBrowserCredentials, invalidateCredentialCache, credentialSealLabel, browserCachePath } from './doubao-auth.ts'
import { invalidateDiscovery } from './doubao-discovery.ts'
import { invalidateQuotaCache } from './doubao-quota.ts'

/** Parse `--timeout <seconds>`. */
function timeoutMsOf(argv: string[]): number {
  const at = argv.findIndex((entry) => entry === '--timeout')
  const value = at >= 0 ? Number(argv[at + 1]) : NaN
  return Number.isFinite(value) && value > 0 ? value * 1000 : 300_000
}

export async function main(argv = process.argv.slice(2)): Promise<number> {
  const exe = findBrowser()
  if (exe === undefined) {
    process.stderr.write(
      `没找到 Chrome / Edge / Chromium。装一个 Chromium 内核的浏览器，或用 ${BROWSER_ENV}=<可执行文件路径> 指定。\n`,
    )
    return 1
  }

  process.stdout.write(`登录窗口: ${exe}\n请在弹出来的窗口里扫码或短信登录…\n`)
  const result = await browserLogin({
    timeoutMs: timeoutMsOf(argv),
    onProgress: (message) => { process.stdout.write(`${String(message)}\n`) },
  })

  if (result.ok !== true || result.pairs === undefined) {
    process.stderr.write(`${result.reason ?? '浏览器登录未完成'}\n`)
    return 1
  }

  try {
    saveBrowserCredentials(result.pairs)
  } catch (error: unknown) {
    process.stderr.write(`登录成功但凭据保存失败：${(error as Error).message}\n`)
    return 1
  }

  invalidateCredentialCache()
  invalidateDiscovery()
  invalidateQuotaCache()
  process.stdout.write(
    `已保存 ${String(result.pairs.size)} 条 cookie\n` +
    `密封方式: ${credentialSealLabel()}\n` +
    `凭据文件: ${browserCachePath()}\n`,
  )
  return 0
}

// Windows consoles default to a legacy code page; force UTF-8 so the progress
// lines are not mangled. Harmless on macOS.
process.stdout.setDefaultEncoding('utf8')

// Only self-execute when this module is the process entrypoint, matching
// `cli-probe.ts`, so `bin.ts` can import `main` without signing in by accident.
if (process.argv[1] && /cli-login\.(js|ts|mjs)$/.test(process.argv[1])) {
  main().then(
    (code) => { process.exitCode = code },
    (error: unknown) => {
      process.stderr.write(`login crashed: ${(error as Error).message}\n`)
      process.exitCode = 1
    },
  )
}
