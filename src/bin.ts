#!/usr/bin/env node
/**
 * `dsh-connect-doubao` — command dispatcher.
 *
 * A bare `dsh-connect-doubao` keeps behaving like the smoke probe (as it always
 * did), and this macOS port adds one explicit subcommand with no equivalent on
 * the settings card: `login`, a terminal-driven browser sign-in.
 */
import { main as probe } from './cli-probe.ts'
import { main as login } from './cli-login.ts'

const argv = process.argv.slice(2)
const run = argv[0] === 'login' ? login(argv.slice(1)) : probe()

run.then(
  (code) => { process.exitCode = code },
  (error: unknown) => {
    process.stderr.write(`${(error as Error).message}\n`)
    process.exitCode = 1
  },
)
