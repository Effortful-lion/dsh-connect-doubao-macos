/**
 * Where the Doubao app keeps its Chromium profile.
 *
 * Windows: the app installs wherever the user wants (`E:\Doubao` is normal), but
 * its profile normally lands under `%LOCALAPPDATA%\Doubao\User Data`. Plenty of
 * people move it — the installer offers a "data directory" choice, and some
 * move it after the fact to keep C: small. A hardcoded `AppData` path then
 * fails with "profile not found" on an otherwise perfectly working install.
 *
 * macOS: the same Chromium layout, without the `User Data` level —
 * `~/Library/Application Support/Doubao/Default`. The app has no installer-time
 * data-directory choice there, so the default covers almost every install, but
 * the running-client probe and the bounded scan still exist for the rest.
 *
 * Strategies, most explicit first (identical on both platforms):
 *
 *   0. the directory the user picked in the settings card — stored in this
 *      plugin's own settings file and applied through {@link setProfileOverride}
 *   1. `DSH_DOUBAO_PROFILE`  — escape hatch, for scripted setups.
 *   2. platform defaults     — the default layout, and free (a few `existsSync`)
 *   3. process command line  — `Doubao --user-data-dir=…`, authoritative but
 *                              costs a child process (`powershell.exe` ≈0.8 s on
 *                              Windows, `ps` a few ms on macOS), so it is only
 *                              consulted once the cheap paths miss
 *   4. bounded scan          — time-boxed walk of the plausible roots for a
 *                              `Default/` profile; on macOS filtered to
 *                              directories whose name mentions Doubao
 *
 * Order is cheapest-first rather than strongest-first on purpose: the common
 * case must not pay for a process probe on every cold start.
 *
 * The result is a LIST, not a single path, because a stale leftover profile can
 * shadow the live one — someone who copied rather than moved leaves an empty
 * directory behind. Callers walk the list and keep the first usable entry.
 *
 * @module dsh-connect-doubao/profile
 */
import { existsSync, readdirSync } from 'node:fs'
import { basename, dirname, join } from 'node:path'
import { homedir } from 'node:os'
import { spawnSync } from 'node:child_process'

/** Where a candidate path came from. Reported by `doctor` so failures are diagnosable. */
export type ProfileSource = 'manual' | 'env' | 'process' | 'appdata' | 'scan'

export interface DoubaoProfileLocation {
  /** Absolute path of the `User Data` directory (the one containing `Default`). */
  dir: string
  source: ProfileSource
}

export interface ProfileProbeDeps {
  /** Defaults to `process.env`. */
  env?: NodeJS.ProcessEnv
  /** Defaults to `process.platform`. */
  platform?: string
  /** Overrides the `powershell.exe` / `ps` probe. Returns raw command lines. */
  processCommandLines?: () => string[]
  /** Profile directories to try in place of the platform defaults. */
  appDataBases?: string[]
  /** Roots for the fallback scan. Defaults to the drives on Windows, `~/Library/Application Support` and `/Applications` on macOS. */
  scanRoots?: string[]
  /** Wall-clock budget for the scan, in ms. Defaults to 1500. */
  scanBudgetMs?: number
  /** Injectable clock, for tests. */
  now?: () => number
  /** Overrides {@link setProfileOverride}, for tests. */
  manual?: string
}

/** Env var a user can set to point at their profile (the folder holding `Default`). */
export const PROFILE_ENV = 'DSH_DOUBAO_PROFILE'

/**
 * The directory the user picked in the settings card, if any.
 *
 * Module-level because the card's choice has to reach every caller of
 * `loadDoubaoCredentials` (quota, shim, upstream) without threading a parameter
 * through four layers. `apply` seeds it once at startup from the settings file
 * and re-seeds it whenever the card saves a new path.
 */
let manualOverride: string | undefined

/**
 * Point the resolver at a user-chosen directory.
 *
 * Call with `undefined` to go back to automatic detection. Invalid paths are
 * ignored here rather than stored, so a folder that was later deleted or
 * renamed falls back to detection instead of breaking sign-in outright.
 */
export function setProfileOverride(raw: string | undefined): void {
  if (raw === undefined) {
    manualOverride = undefined
    return
  }
  const resolved = resolveUserProvided(raw)
  manualOverride = resolved
}

/** The active override after validation, or `undefined`. */
export function currentProfileOverride(): string | undefined {
  return manualOverride
}

/**
 * A directory is a profile only if the Doubao Chromium data is really there.
 *
 * `Default/Preferences` is the file the model catalog is read from and exists
 * on both platforms; the cookie jar sits at `Default/Network/Cookies` on
 * Windows and at `Default/Cookies` inside the mac app. Accepting any of the
 * three keeps one predicate for both layouts without needing the platform
 * argument in every caller.
 */
export function looksLikeProfile(dir: string): boolean {
  const profile = join(dir, 'Default')
  return (
    existsSync(join(profile, 'Preferences')) ||
    existsSync(join(profile, 'Network', 'Cookies')) ||
    existsSync(join(profile, 'Cookies'))
  )
}

/**
 * Resolve one user-supplied path.
 *
 * Accepts the `User Data` directory itself, its parent (`E:\Doubao`,
 * `/Applications/Doubao`), or the `Default` profile folder inside it — all three
 * are reasonable readings of "where my data is", and on macOS the app nests
 * nothing (`~/Library/Application Support/Doubao/Default`).
 */
export function resolveUserProvided(raw: string): string | undefined {
  const trimmed = raw.trim().replace(/^"|"$/g, '')
  if (trimmed === '') return undefined
  if (looksLikeProfile(trimmed)) return trimmed
  const nested = join(trimmed, 'User Data')
  if (looksLikeProfile(nested)) return nested
  // Pointed at `.../Default` instead of its parent.
  if (basename(trimmed).toLowerCase() === 'default') {
    const parent = dirname(trimmed)
    if (looksLikeProfile(parent)) return parent
  }
  return undefined
}

/**
 * Pull `--user-data-dir=` out of one command line.
 *
 * The argument arrives in two shapes and both occur in real Doubao output:
 *
 *   --user-data-dir=C:\path\to\User Data        (cut at whitespace)
 *   "--user-data-dir=C:\path with space"        (quoted as a whole)
 *
 * An empty value is treated as absent: `--user-data-dir=""` means "use the
 * Chromium default", not "the current directory".
 */
export function extractUserDataDir(commandLine: string): string | undefined {
  const key = '--user-data-dir='
  const at = commandLine.indexOf(key)
  if (at < 0) return undefined
  const start = at + key.length
  let value: string
  if (commandLine[start] === '"') {
    // `--user-data-dir="C:\..."` — the value itself is quoted.
    const end = commandLine.indexOf('"', start + 1)
    if (end < 0) return undefined
    value = commandLine.slice(start + 1, end)
  } else if (commandLine[at - 1] === '"') {
    // `"--user-data-dir=C:\..."` — the whole argument is quoted.
    const end = commandLine.indexOf('"', start)
    if (end < 0) return undefined
    value = commandLine.slice(start, end)
  } else {
    const end = commandLine.indexOf(' ', start)
    value = end < 0 ? commandLine.slice(start) : commandLine.slice(start, end)
  }
  const cleaned = value.trim()
  return cleaned === '' ? undefined : cleaned
}

/**
 * Read the live client's `--user-data-dir`, if the client is running.
 *
 * Windows uses `Get-CimInstance` rather than `Get-Process`: the latter only
 * exposes `CommandLine` on PowerShell 7, and Windows still ships 5.1. macOS
 * uses `ps -axo args`, which needs no elevation and prints one full command
 * line per process.
 */
function probeProcessCommandLines(platform: string): string[] {
  if (platform === 'darwin') {
    try {
      const result = spawnSync('ps', ['-axo', 'args'], { encoding: 'utf8', timeout: 5_000 })
      if (result.status !== 0 || typeof result.stdout !== 'string') return []
      return result.stdout
        .split('\n')
        .filter((line) => /Doubao/i.test(line) && line.includes('--user-data-dir='))
    } catch {
      return []
    }
  }

  const script =
    "Get-CimInstance Win32_Process -Filter \"Name='Doubao.exe'\" | ForEach-Object { $_.CommandLine }"
  try {
    const result = spawnSync(
      'powershell.exe',
      ['-NoProfile', '-NonInteractive', '-Command', script],
      { encoding: 'utf8', timeout: 8000, windowsHide: true },
    )
    if (result.status !== 0 || typeof result.stdout !== 'string') return []
    return result.stdout.split(/\r?\n/).filter((line) => line.trim() !== '')
  } catch {
    return []
  }
}

/** Default candidates on Windows: the documented layout, plus every user profile. */
function windowsProfileCandidates(env: NodeJS.ProcessEnv): string[] {
  const bases = [env.LOCALAPPDATA, env.APPDATA].filter(
    (entry): entry is string => typeof entry === 'string' && entry !== '',
  )
  const candidates = bases.map((base) => join(base, 'Doubao', 'User Data'))
  // Roaming first, then every other user's Local: a second account on the same
  // machine is a real setup, and `C:\Users` is cheap to list.
  const usersRoot = 'C:\\Users'
  if (existsSync(usersRoot)) {
    try {
      for (const user of readdirSync(usersRoot)) {
        candidates.push(join(usersRoot, user, 'AppData', 'Local', 'Doubao', 'User Data'))
      }
    } catch {
      /* unreadable C:\Users — nothing to add */
    }
  }
  return candidates
}

/**
 * Default candidates on macOS.
 *
 * The mac app keeps its Chromium data at `~/Library/Application Support/Doubao`
 * with `Default/` directly inside — there is no extra `User Data` level like
 * Windows has. Both spellings are listed because a hand-migrated profile often
 * gains one.
 */
function macosProfileCandidates(): string[] {
  const support = join(homedir(), 'Library', 'Application Support')
  return [
    join(support, 'Doubao'),
    join(support, 'Doubao', 'User Data'),
    join(support, 'Doubao', 'Doubao'),
  ]
}

/** Best-effort candidates for whichever platform this is. */
function defaultProfileCandidates(platform: string, env: NodeJS.ProcessEnv): string[] {
  if (platform === 'darwin') return macosProfileCandidates()
  return windowsProfileCandidates(env)
}

/** Directories that never contain a Doubao profile and are expensive to walk. */
const SCAN_SKIP = new Set([
  'windows',
  'windows.old',
  '$recycle.bin',
  'system volume information',
  'node_modules',
  '.git',
  'programdata',
  'recovery',
  'perflogs',
  'msocache',
])

/** Every existing fixed-drive root, `C:\` style. */
function defaultScanRoots(platform: string): string[] {
  if (platform === 'darwin') {
    // Scanning `/` on macOS is both slow and privacy-hostile (it walks every
    // mounted volume, Time Machine snapshot and network share). The app's data
    // can only sensibly live in one of these, and anything else is covered by
    // the env override or the running-client probe. `~/Applications` and
    // `/Applications` are NOT roots: those hold app BUNDLES, and the scan
    // accepts only directories whose name mentions Doubao, so an app bundle
    // could never qualify.
    const support = join(homedir(), 'Library', 'Application Support')
    return [support, homedir()]
  }
  const roots: string[] = []
  for (let code = 65 /* A */; code <= 90 /* Z */; code += 1) {
    const root = `${String.fromCharCode(code)}:\\`
    if (existsSync(root)) roots.push(root)
  }
  return roots
}

/**
 * Bounded breadth-first search for a Doubao profile directory.
 *
 * Depth 4 covers `D:\Doubao\User Data` (2) and `D:\Apps\Doubao\User Data` (3)
 * with slack, and a directory-name check keeps it from examining every file.
 * The clock check runs per directory so a sprawling D: cannot stall startup.
 *
 * `onlyDoubao` narrows a candidate to names that mention Doubao. macOS needs
 * that: `~/Library/Application Support` holds a `Default/` folder for every
 * Chromium app on the machine, so an unfiltered walk would happily "find" the
 * Chrome profile and then read model catalogs out of it.
 */
function scanForProfiles(
  roots: string[],
  budgetMs: number,
  now: () => number,
  onlyDoubao = false,
): DoubaoProfileLocation[] {
  const deadline = now() + budgetMs
  const found: DoubaoProfileLocation[] = []
  const seen = new Set<string>()
  const queue: Array<{ dir: string; depth: number }> = roots.map((root) => ({ dir: root, depth: 0 }))
  while (queue.length > 0) {
    if (now() > deadline) break
    const item = queue.shift()
    if (item === undefined) break
    let entries
    try {
      entries = readdirSync(item.dir, { withFileTypes: true })
    } catch {
      continue
    }
    for (const entry of entries) {
      if (!entry.isDirectory()) continue
      const name = entry.name.toLowerCase()
      if (SCAN_SKIP.has(name)) continue
      if (onlyDoubao && !name.includes('doubao')) continue
      const child = join(item.dir, entry.name)
      const key = child.toLowerCase()
      if (seen.has(key)) continue
      seen.add(key)
      if (looksLikeProfile(child)) {
        found.push({ dir: child, source: 'scan' })
        continue
      }
      if (item.depth + 1 < 4) queue.push({ dir: child, depth: item.depth + 1 })
    }
  }
  return found
}

/**
 * Every plausible profile, best first.
 *
 * Deduplicated case-insensitively (Windows paths are case-insensitive, and the
 * process probe and scan can easily report the same directory). A later source
 * never overrides an earlier one, so `env` always wins.
 *
 * Both desktop platforms are supported: Windows (AppData layout, `--user-data-dir`
 * from the running `Doubao.exe`) and macOS (`~/Library/Application Support/Doubao`,
 * `--user-data-dir` from the running app). Other platforms return nothing — the
 * browser sign-in does not need a profile, and model discovery falls back to
 * the live menu.
 */
export function listDoubaoProfiles(deps: ProfileProbeDeps = {}): DoubaoProfileLocation[] {
  const platform = deps.platform ?? process.platform
  if (platform !== 'win32' && platform !== 'darwin') return []
  const env = deps.env ?? process.env
  const now = deps.now ?? Date.now
  const out: DoubaoProfileLocation[] = []
  const seen = new Set<string>()
  const push = (dir: string | undefined, source: ProfileSource): void => {
    if (dir === undefined) return
    const key = dir.toLowerCase().replace(/[\\/]+$/, '')
    if (seen.has(key)) return
    seen.add(key)
    out.push({ dir, source })
  }

  // 0. what the user picked in the settings card. The stored value is already
  //    validated, but the injected one may come straight from a test or a
  //    stale pick, so both paths re-resolve: a pick that no longer holds any
  //    Doubao data falls through to automatic detection instead of wedging
  //    credential loading on a folder the user has since moved.
  const manual = deps.manual ?? manualOverride
  if (manual !== undefined) push(resolveUserProvided(manual), 'manual')

  // 1. explicit environment variable
  const override = env[PROFILE_ENV]
  if (typeof override === 'string') push(resolveUserProvided(override), 'env')

  // 2. the documented layout (free)
  for (const candidate of deps.appDataBases ?? defaultProfileCandidates(platform, env)) {
    if (looksLikeProfile(candidate)) push(candidate, 'appdata')
  }

  // 3. the running client tells us where it really lives
  const lines = deps.processCommandLines ? deps.processCommandLines() : probeProcessCommandLines(platform)
  for (const line of lines) {
    const dir = extractUserDataDir(line)
    if (dir !== undefined && looksLikeProfile(dir)) push(dir, 'process')
  }

  // 4. last resort: walk the plausible roots
  if (out.length === 0) {
    const roots = deps.scanRoots ?? defaultScanRoots(platform)
    for (const hit of scanForProfiles(roots, deps.scanBudgetMs ?? 1500, now, platform === 'darwin')) {
      push(hit.dir, hit.source)
    }
  }

  return out
}

/** Best guess for the profile directory, or `undefined`. */
export function findDoubaoUserDataDir(deps: ProfileProbeDeps = {}): string | undefined {
  return listDoubaoProfiles(deps)[0]?.dir
}

/** Where the profile was found and how — what `doctor` prints. */
export function describeProfileLocation(deps: ProfileProbeDeps = {}): string {
  const profile = listDoubaoProfiles(deps)[0]
  return profile === undefined ? '<not found>' : `${profile.dir} (via ${profile.source})`
}
