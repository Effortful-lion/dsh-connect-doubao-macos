/**
 * The capture must read a REAL app request off the page, not any doubao.com
 * traffic: upload/CDN calls carry a different query shape, and taking one would
 * poison every later request with the wrong identity.
 */
import { createServer, type Server } from 'node:http'
import { afterEach, describe, expect, it } from 'vitest'
import { WebSocketServer } from 'ws'
import { captureFingerprintFromPort } from '../src/doubao-auth-browser.ts'

let server: Server | undefined
let wss: WebSocketServer | undefined

afterEach(async () => {
  wss?.close()
  if (server !== undefined) {
    await new Promise<void>((resolve) => {
      server!.close(() => { resolve() })
      server!.closeAllConnections()
    })
  }
  server = undefined
  wss = undefined
})

function event(url: string, headers: Record<string, string>): string {
  return JSON.stringify({
    method: 'Network.requestWillBeSent',
    params: { request: { url, headers } },
  })
}

describe('captureFingerprintFromPort', () => {
  it('takes the same-origin app call and ignores other doubao hosts', async () => {
    let port = 0

    server = createServer((req, res) => {
      if (req.url !== '/json/list') {
        res.writeHead(404)
        res.end()
        return
      }
      res.writeHead(200, { 'content-type': 'application/json' })
      res.end(JSON.stringify([{
        type: 'page',
        url: 'https://www.doubao.com/chat/',
        webSocketDebuggerUrl: `ws://127.0.0.1:${String(port)}/`,
      }]))
    })

    wss = new WebSocketServer({ server })
    wss.on('connection', (socket) => {
      // Upload traffic arrives first and must not become the identity.
      setTimeout(() => {
        socket.send(event(
          'https://mcs.doubao.com/upload?aid=1&device_id=wrong',
          { 'User-Agent': 'upload-agent', Referer: 'https://www.doubao.com/chat/' },
        ))
      }, 20)
      setTimeout(() => {
        socket.send(event(
          'https://www.doubao.com/alice/slot/action_bar_v3/brief_list'
            + '?aid=497858&device_id=7123456789&device_platform=web&msToken=SECRET',
          {
            'User-Agent': 'Mozilla/5.0 Chrome/157',
            Referer: 'https://www.doubao.com/chat/123',
            'sec-ch-ua': '"Chromium";v="157"',
          },
        ))
      }, 80)
    })

    await new Promise<void>((resolve) => { server!.listen(0, '127.0.0.1', () => { resolve() }) })
    const address = server.address()
    port = typeof address === 'object' && address !== null ? address.port : 0

    const fingerprint = await captureFingerprintFromPort(port, 3_000)
    expect(fingerprint).toBeDefined()
    expect(fingerprint!.userAgent).toContain('Chrome/157')
    expect(fingerprint!.query.aid).toBe('497858')
    expect(fingerprint!.query.device_platform).toBe('web')
    expect(fingerprint!.secChUa).toContain('Chromium')
    expect(JSON.stringify(fingerprint)).not.toContain('SECRET')
  })
})
