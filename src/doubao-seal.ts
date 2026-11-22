/**
 * Sealing one small secret for the current user — the platform layer.
 *
 * WHAT IT IS FOR. The only thing this plugin ever seals is the Doubao session it
 * just harvested from a browser sign-in: about 30 cookies, a few kilobytes, one
 * file. That shape decides the design: no streaming, no multi-user storage, no
 * rotation schedule.
 *
 * BACKENDS
 *
 *   win32   Windows DPAPI (`CryptProtectData`, current-user scope) through a
 *           short-lived PowerShell child. Unchanged from the original plugin.
 *
 *   darwin  AES-256-GCM with a 32-byte key that lives in the LOGIN KEYCHAIN as a
 *           generic password (`security add-generic-password`). The ciphertext
 *           goes to `~/.dsh/...` at mode 0600. This is the closest macOS
 *           equivalent of DPAPI's "current user scope": the key is protected by
 *           the keychain's own ACL, and copying the sealed file to another
 *           machine or account does not open it.
 *
 *           Fallback, only when the keychain refuses to cooperate (locked
 *           keychain, headless SSH without an unlocked session, a policy that
 *           blocks `security`): a key file next to the sealed file at 0600. It
 *           is weaker — the key travels with the ciphertext — so
 *           {@link sealBackend} reports which one is in use and `doctor` prints
 *           it instead of pretending both are equal.
 *
 *   other   Reported as `none`; sealing throws with an actionable message
 *           rather than silently writing a plaintext session to disk.
 *
 * WHY NOT JUST WRITE A 0600 JSON FILE AND CALL IT DONE. Because then "sealed"
 * would be a lie in every message and test that mentions it. The keychain path
 * costs one `security` call per cold read (cached in memory by the caller), and
 * it is what makes a copied file useless elsewhere.
 *
 * SECURITY NOTES
 *  - The plaintext travels over stdin for DPAPI and never through argv or the
 *    environment (a child's env is world-readable to the same user).
 *  - On macOS the KEY travels through `security`'s argv once per key creation,
 *    which is the only interface `security add-generic-password` offers. It is
 *    visible to the same user's `ps` for that one call, and never written to
 *    disk in the clear.
 *  - Nothing here logs a secret. Errors name the failure, not the payload.
 *
 * @module dsh-connect-doubao/seal
 */
import { createCipheriv, createDecipheriv, createHash, randomBytes } from 'node:crypto'
import { spawnSync } from 'node:child_process'
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { homedir, tmpdir } from 'node:os'
import { dirname, join } from 'node:path'

/** Which mechanism actually protects the payload on this machine. */
export type SealBackend = 'dpapi' | 'keychain' | 'keyfile' | 'none'

/** Keychain service name for the data key. Stable across upgrades. */
export const KEYCHAIN_SERVICE = 'dsh-connect-doubao'

/** Keychain account: the current login user, so each account gets its own key. */
function keychainAccount(): string {
  const user = process.env.USER
  return typeof user === 'string' && user !== '' ? user : 'dsh'
}

/**
 * Absolute path to `security`, or the bare name as a last resort.
 *
 * Same reasoning as the PowerShell path below: resolving through PATH means a
 * planted `security` earlier in the search order receives the data key. The
 * system binary lives at a fixed location, so ask for it.
 */
function securityPath(): string {
  return existsSync('/usr/bin/security') ? '/usr/bin/security' : 'security'
}

/* ------------------------------------------------------------------ *
 * Windows DPAPI
 * ------------------------------------------------------------------ */

interface DataBlob {
  cbData: number
  pbData: Buffer
}

/**
 * Absolute path to Windows PowerShell, or the bare name as a last resort.
 *
 * Resolving through PATH means a planted `powershell.exe` earlier in the search
 * order receives this call's input on stdin — which is a session cookie or the
 * DPAPI master key. The system copy lives at a fixed location, so ask for it.
 */
function powershellPath(): string {
  const root = process.env.SystemRoot ?? process.env.windir ?? 'C:\\Windows'
  const direct = join(root, 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe')
  return existsSync(direct) ? direct : 'powershell.exe'
}

/**
 * The environment handed to the DPAPI helper.
 *
 * An explicit allow-list rather than a spread of the host environment: that
 * environment carries every API key this DSH install has, and none of them has
 * any business in a process whose only job is one crypt32 call.
 */
function dpapiChildEnv(): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = {}
  for (const name of ['SystemRoot', 'windir', 'SystemDrive', 'ComSpec', 'PATH', 'PATHEXT', 'TEMP', 'TMP', 'USERPROFILE']) {
    const value = process.env[name]
    if (value !== undefined) env[name] = value
  }
  if (env.SystemRoot === undefined && env.windir !== undefined) env.SystemRoot = env.windir
  return env
}

/**
 * Call CryptProtectData / CryptUnprotectData via a short-lived PowerShell child.
 *
 * Node has no built-in DPAPI binding and the plugin must not pull in a native
 * addon, so we shell out to the Windows Data Protection API. The payload travels
 * over stdin and stdout and never touches disk.
 */
function dpapiCall(mode: 'protect' | 'unprotect', blob: Buffer): Buffer {
  // The script is written to a temp .ps1 and run with `-File`, not passed via
  // -Command/-EncodedCommand: the C# P/Invoke source needs real newlines, and
  // any inline form flattens the here-string header into a parse error.
  const script = [
    // A param block must be the first statement in the file.
    'param([string]$Mode = "unprotect")',
    "$ErrorActionPreference = 'Stop'",
    '$ProgressPreference = "SilentlyContinue"',
    // The C# source is built with -TypeDefinition rather than -MemberDefinition.
    //
    // Two constraints drive that choice, both learned the hard way:
    //  * -MemberDefinition demands -Name, which then moves the struct into a
    //    nested namespace where PowerShell cannot resolve `[DshCrypt.DshDataBlob]`;
    //  * declaring the out-param as `ref IntPtr` is WRONG. The native
    //    DATA_BLOB is { DWORD cbData; pbData } = 16 bytes, but `ref IntPtr`
    //    only writes 8, so the pointer half stays zero and the following
    //    Marshal.Copy reads freed memory and faults the process.
    //    The struct below is the only correct shape.
    // PowerShell single-quoted string, C# double quotes — one level only.
    '$cs = \'using System; using System.Runtime.InteropServices; [StructLayout(LayoutKind.Sequential)] public struct DshDataBlob { public int cbData; public IntPtr pbData; } public static class DshCrypt { [DllImport("crypt32.dll", SetLastError = true)] public static extern bool CryptUnprotectData(ref DshDataBlob pDataIn, IntPtr szDataDescr, IntPtr pOptionalEntropy, IntPtr pvReserved, IntPtr pPromptStruct, int dwFlags, ref DshDataBlob pDataOut); [DllImport("crypt32.dll", SetLastError = true)] public static extern bool CryptProtectData(ref DshDataBlob pDataIn, IntPtr szDataDescr, IntPtr pOptionalEntropy, IntPtr pvReserved, IntPtr pPromptStruct, int dwFlags, ref DshDataBlob pDataOut); }\'',
    'Add-Type -TypeDefinition $cs',
    // The payload arrives on STDIN, never in the environment: `env` of a child
    // process is visible to every other process of the same user (Task Manager,
    // WMI, a crashed-process dump), and this payload is a plaintext session —
    // the whole point of sealing it is that it does not travel in the clear.
    '$in = [Console]::In.ReadToEnd()',
    '$bytes = [System.Convert]::FromBase64String($in.Trim())',
    '$len = [int]$bytes.Length',
    '$mem = [Runtime.InteropServices.Marshal]::AllocHGlobal($len)',
    '[Runtime.InteropServices.Marshal]::Copy($bytes, 0, $mem, $len)',
    '$inBlob = New-Object DshDataBlob',
    '$inBlob.cbData = $len',
    '$inBlob.pbData = $mem',
    '$outBlob = New-Object DshDataBlob',
    // CRYPTPROTECT_UI_FORBIDDEN = 0x1. Protect and unprotect share every
    // argument shape except the entry point, so the mode is one branch.
    "if ($Mode -eq 'protect') {",
    '  $ok = [DshCrypt]::CryptProtectData([ref]$inBlob, [IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero, 1, [ref]$outBlob)',
    '} else {',
    '  $ok = [DshCrypt]::CryptUnprotectData([ref]$inBlob, [IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero, 1, [ref]$outBlob)',
    '}',
    "if (-not $ok) { [Console]::Out.Write('DPAPI_CALL_FAILED'); exit 3 }",
    '$res = New-Object byte[] $outBlob.cbData',
    '[Runtime.InteropServices.Marshal]::Copy($outBlob.pbData, $res, 0, $outBlob.cbData)',
    '[Console]::Out.Write([System.Convert]::ToBase64String($res))',
    '',
  ].join('\r\n')

  const scratch = mkdtempSync(join(tmpdir(), 'dsh-doubao-dpapi-'))
  const scriptPath = join(scratch, 'unprotect.ps1')
  try {
    // UTF8 without a BOM: a BOM in a -File script makes PowerShell choke on the
    // very first line, which surfaces as a bare non-zero exit with no stderr.
    writeFileSync(scriptPath, script, 'utf8')
    // spawnSync rather than execFileSync: PowerShell writes a CLIXML preamble to
    // stderr even on success, and execFileSync discards stdout when that happens.
    const result = spawnSync(
      powershellPath(),
      ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', scriptPath, mode],
      {
        encoding: 'utf8',
        maxBuffer: 1 << 24,
        windowsHide: true,
        // The payload rides on stdin (see the script above); the environment is
        // narrowed to what PowerShell needs to start.
        input: blob.toString('base64'),
        env: dpapiChildEnv(),
      },
    )
    const stdout = result.stdout ?? ''
    if (stdout.trim() === '') {
      const stderr = result.stderr ?? ''
      throw new Error(
        `Windows DPAPI helper produced no output (status=${String(result.status)}, ` +
        `stdout=${JSON.stringify(stdout.slice(0, 120))}, ` +
        `stderr=${JSON.stringify(stderr.slice(-400))})`,
      )
    }
    for (const line of stdout.split(/\r?\n/).reverse()) {
      const candidate = line.trim()
      if (!candidate || candidate.startsWith('#') || candidate.startsWith('<')) continue
      if (candidate === 'DPAPI_CALL_FAILED') {
        throw new Error('Windows DPAPI rejected the blob (CryptUnprotectData returned false)')
      }
      const decoded = Buffer.from(candidate, 'base64')
      if (decoded.length > 0) return decoded
    }
    throw new Error('DPAPI helper returned no usable output')
  } finally {
    rmSync(scratch, { recursive: true, force: true })
  }
}

/* ------------------------------------------------------------------ *
 * macOS keychain + AES-256-GCM
 * ------------------------------------------------------------------ */

/**
 * Where the fallback key file lives when the keychain is unavailable.
 *
 * Only created on the fallback path; when the keychain works this file never
 * exists at all, which is what makes `sealBackend()` answer truthfully.
 */
export function fallbackKeyPath(): string {
  return join(homedir(), '.dsh', 'dsh-connect-doubao.key')
}

/** Read the data key out of the login keychain, or `undefined`. */
function readKeyFromKeychain(): Buffer | undefined {
  const result = spawnSync(
    securityPath(),
    ['find-generic-password', '-a', keychainAccount(), '-s', KEYCHAIN_SERVICE, '-w'],
    { encoding: 'utf8', timeout: 10_000 },
  )
  if (result.status !== 0) return undefined
  const value = (result.stdout ?? '').trim()
  if (value === '') return undefined
  const key = Buffer.from(value, 'base64')
  return key.length === 32 ? key : undefined
}

/**
 * Store a new data key in the login keychain.
 *
 * `-U` updates an existing item instead of failing, so a delete-then-create
 * race between two plugin instances cannot leave the second one keyless.
 * The key is passed through argv because that is the only interface
 * `security add-generic-password` has; it is not written anywhere else.
 */
function writeKeyToKeychain(key: Buffer): boolean {
  const result = spawnSync(
    securityPath(),
    [
      'add-generic-password',
      '-a', keychainAccount(),
      '-s', KEYCHAIN_SERVICE,
      '-U',
      '-l', 'dsh-connect-doubao session key',
      '-w', key.toString('base64'),
    ],
    { encoding: 'utf8', timeout: 10_000 },
  )
  return result.status === 0
}

/** Read the fallback key file, or `undefined`. */
function readKeyFromFile(): Buffer | undefined {
  try {
    const raw = readFileSync(fallbackKeyPath(), 'utf8').trim()
    const key = Buffer.from(raw, 'base64')
    return key.length === 32 ? key : undefined
  } catch {
    return undefined
  }
}

/** Write a key to the fallback file at 0600. */
function stashKeyInFile(key: Buffer): void {
  const path = fallbackKeyPath()
  mkdirSync(dirname(path), { recursive: true })
  writeFileSync(path, `${key.toString('base64')}\n`, { mode: 0o600 })
  try { chmodSync(path, 0o600) } catch { /* mode already applied by the writer */ }
}

/** Which backend the current key came from; set by {@link dataKey}. */
let keySource: 'keychain' | 'keyfile' | undefined

/**
 * The data key, created on first use.
 *
 * Order: keychain → fallback file. A key that exists in one place is never
 * duplicated into the other, so there is exactly one answer to "which key
 * sealed this file" on any given machine.
 */
function dataKey(): Buffer {
  const inKeychain = readKeyFromKeychain()
  if (inKeychain !== undefined) { keySource = 'keychain'; return inKeychain }

  // A key file left over from an earlier fallback session is authoritative: it
  // is what sealed everything already on disk. Promote nothing, just reuse it.
  const inFile = readKeyFromFile()
  if (inFile !== undefined) { keySource = 'keyfile'; return inFile }

  const fresh = randomBytes(32)
  if (writeKeyToKeychain(fresh)) { keySource = 'keychain'; return fresh }
  stashKeyInFile(fresh)
  keySource = 'keyfile'
  return fresh
}

/** Envelope shape written to disk. Versioned so a future format can be refused. */
interface SealedEnvelope {
  v: 1
  alg: 'aes-256-gcm'
  /** First 16 hex of SHA-256(key): a wrong key fails loudly, not as garbage. */
  keyId: string
  iv: string
  tag: string
  ct: string
}

function keyIdOf(key: Buffer): string {
  return createHash('sha256').update(key).digest('hex').slice(0, 16)
}

/** AES-256-GCM one-shot encrypt of a small payload. */
function macSeal(bytes: Buffer): Buffer {
  const key = dataKey()
  const iv = randomBytes(12)
  const cipher = createCipheriv('aes-256-gcm', key, iv, { authTagLength: 16 })
  const ct = Buffer.concat([cipher.update(bytes), cipher.final()])
  const envelope: SealedEnvelope = {
    v: 1,
    alg: 'aes-256-gcm',
    keyId: keyIdOf(key),
    iv: iv.toString('base64'),
    tag: cipher.getAuthTag().toString('base64'),
    ct: ct.toString('base64'),
  }
  return Buffer.from(JSON.stringify(envelope), 'utf8')
}

/** AES-256-GCM one-shot decrypt; throws when the key or the bytes are wrong. */
function macUnseal(sealed: Buffer): Buffer {
  let envelope: SealedEnvelope
  try {
    envelope = JSON.parse(sealed.toString('utf8')) as SealedEnvelope
  } catch {
    throw new Error('sealed session is not a JSON envelope (was it written by another platform?)')
  }
  if (envelope.v !== 1 || envelope.alg !== 'aes-256-gcm') {
    throw new Error(`sealed session uses unsupported format v${String(envelope.v)}/${String(envelope.alg)}`)
  }
  const key = dataKey()
  if (envelope.keyId !== keyIdOf(key)) {
    throw new Error('sealed session was sealed with a different key (keychain item or key file changed)')
  }
  const decipher = createDecipheriv('aes-256-gcm', key, Buffer.from(envelope.iv, 'base64'), { authTagLength: 16 })
  decipher.setAuthTag(Buffer.from(envelope.tag, 'base64'))
  return Buffer.concat([decipher.update(Buffer.from(envelope.ct, 'base64')), decipher.final()])
}

/* ------------------------------------------------------------------ *
 * Public surface
 * ------------------------------------------------------------------ */

/** The backend this machine will use. Costs at most one keychain lookup. */
export function sealBackend(): SealBackend {
  if (process.platform === 'win32') return 'dpapi'
  if (process.platform !== 'darwin') return 'none'
  try {
    dataKey()
    return keySource ?? 'none'
  } catch {
    return 'none'
  }
}

/** Human-readable backend name, for `doctor` and failure messages. */
export function sealBackendLabel(): string {
  switch (sealBackend()) {
    case 'dpapi': return 'Windows DPAPI (current-user scope)'
    case 'keychain': return 'macOS login keychain key + AES-256-GCM'
    case 'keyfile': return 'local 0600 key file + AES-256-GCM (keychain unavailable)'
    default: return 'unavailable on this platform'
  }
}

/** Seal a small payload for this user on this machine. */
export function seal(bytes: Buffer): Buffer {
  if (process.platform === 'win32') return dpapiCall('protect', bytes)
  if (process.platform === 'darwin') return macSeal(bytes)
  throw new Error(`credential sealing is not supported on ${process.platform}; macOS or Windows only`)
}

/** Open a payload produced by {@link seal} on this user's machine. */
export function unseal(sealed: Buffer): Buffer {
  if (process.platform === 'win32') return dpapiCall('unprotect', sealed)
  if (process.platform === 'darwin') return macUnseal(sealed)
  throw new Error(`credential sealing is not supported on ${process.platform}; macOS or Windows only`)
}
