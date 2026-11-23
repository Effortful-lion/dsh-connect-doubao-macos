/**
 * The relay must submit through the official page and return the page's own
 * response, not synthesize a Node fetch. A fake CDP endpoint keeps that contract
 * testable without a Doubao account or network traffic.
 */
import { createServer, type Server } from 'node:http'
import { afterEach, describe, expect, it } from 'vitest'
import { WebSocketServer } from 'ws'
import { browserRelayChat } from '../src/doubao-browser-relay.ts'

let server: Server | undefined
let wss: WebSocketServer | undefined

afterEach(async () => {
  wss?.close()
  if (server !== undefined) {
    await new Promise<void>(resolve => {
      server!.close(() => resolve())
      server!.closeAllConnections()
    })
  }
  server = undefined
  wss = undefined
})

describe('official browser relay', () => {
  it('types into the official composer and returns the captured response', async () => {
    const frames = [
      'id: 1\nevent: SSE_HEARTBEAT\ndata: {}\n\n',
      'id: 2\nevent: SSE_REPLY_END\ndata: {}\n\n',
    ].join('')
    let inserted = ''
    let keyUps = 0
    let readIndex = 0

    server = createServer((req, res) => {
      if (req.url !== '/json/list') { res.writeHead(404); res.end(); return }
      const address = server!.address()
      const port = typeof address === 'object' && address !== null ? address.port : 0
      res.writeHead(200, { 'content-type': 'application/json' })
      res.end(JSON.stringify([{
        type: 'page',
        url: 'https://www.doubao.com/chat/',
        webSocketDebuggerUrl: `ws://127.0.0.1:${port}/`,
      }]))
    })
    wss = new WebSocketServer({ server })
    wss.on('connection', socket => {
      socket.on('message', raw => {
        const message = JSON.parse(String(raw)) as {
          id?: number
          method?: string
          params?: Record<string, unknown>
        }
        const id = message.id
        if (id === undefined) return
        if (message.method === 'Runtime.evaluate') {
          socket.send(JSON.stringify({ id, result: { result: { value: true } } }))
          return
        }
        if (message.method === 'Input.insertText') {
          inserted = String(message.params?.text ?? '')
        }
        if (message.method === 'Fetch.takeResponseBodyAsStream') {
          socket.send(JSON.stringify({ id, result: { stream: 'stream-1' } }))
          return
        }
        if (message.method === 'IO.read') {
          const parts = frames.split('\n\n').filter(Boolean)
          const data = readIndex < parts.length ? parts[readIndex] + '\n\n' : ''
          const eof = readIndex >= parts.length - 1
          readIndex += 1
          socket.send(JSON.stringify({ id, result: { data, base64Encoded: false, eof } }))
          return
        }
        socket.send(JSON.stringify({ id, result: {} }))
        if (message.method === 'Input.dispatchKeyEvent' && message.params?.type === 'keyUp') {
          keyUps += 1
          if (keyUps === 1) {
            const requestId = 'chat-1'
            socket.send(JSON.stringify({
              method: 'Fetch.requestPaused',
              params: {
                requestId,
                responseStatusCode: 200,
                responseStatusText: 'OK',
                responseHeaders: [{ name: 'content-type', value: 'text/event-stream' }],
              },
            }))
          }
          return
        }
      })
    })
    await new Promise<void>(resolve => server!.listen(0, '127.0.0.1', resolve))
    const address = server.address()
    const port = typeof address === 'object' && address !== null ? address.port : 0

    const response = await browserRelayChat('只发这一句', { port, timeoutMs: 5000 })
    expect(response.status).toBe(200)
    expect(await response.text()).toBe(frames)
    expect(inserted).toBe('只发这一句')
    expect(response.headers.get('content-type')).toBe('text/event-stream')
  })
})
