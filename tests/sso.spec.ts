import { createServer, type Server } from 'node:http'
import type { AddressInfo } from 'node:net'
import type { IncomingMessage, ServerResponse } from 'node:http'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { pathToFileURL } from 'node:url'
import { afterEach, describe, expect, it } from 'vitest'
import { Context } from '@deepseek-ai/cordis'
import { credentialRef } from '@deepseek-ai/dsh-credentials'
import { MemoryCredentials } from './memory-credentials.ts'
import { SessionStore } from '../src/session.ts'
import { UserStore } from '../src/users.ts'
import { createSsoAuthorizeHandler, createSsoCallbackHandler, upsertSsoUser } from '../src/sso-api.ts'
import { buildAuthorizeUrl, SsoStateStore, type SsoConfig } from '../src/sso.ts'

let root: string | undefined
let context: Context | undefined

afterEach(async () => {
  await context?.fiber.dispose()
  context = undefined
  if (root !== undefined) await rm(root, { recursive: true, force: true })
  root = undefined
})

/** Minimal writable response stub matching the handlers' write surface. */
function fakeRes(): { status: number | undefined; location: string | undefined; cookie: string | undefined } {
  const res = {
    status: undefined as number | undefined,
    location: undefined as string | undefined,
    cookie: undefined as string | undefined,
  }
  return Object.assign(res, {
    writeHead(code: number, headers?: Record<string, string>): void {
      res.status = code
      if (headers?.Location !== undefined) res.location = headers.Location
    },
    end(): void {},
    setHeader(name: string, value: string): void {
      if (name.toLowerCase() === 'set-cookie') res.cookie = value
    },
  })
}

/** Minimal request stub: only url + headers are read. */
function fakeReq(url: string): IncomingMessage {
  return {
    url,
    headers: { host: '127.0.0.1:3080' },
  } as unknown as IncomingMessage
}

describe('SsoStateStore', () => {
  it('accepts a freshly issued state exactly once', () => {
    const states = new SsoStateStore()
    const state = states.issue()
    expect(states.consume(state)).toBe(true)
    expect(states.consume(state)).toBe(false)
  })

  it('rejects an unknown state', () => {
    const states = new SsoStateStore()
    expect(states.consume('deadbeef')).toBe(false)
  })

  it('rejects an expired state', async () => {
    const states = new SsoStateStore(0)
    const state = states.issue()
    await new Promise<void>(r => setTimeout(r, 10))
    expect(states.consume(state)).toBe(false)
  })
})

describe('buildAuthorizeUrl', () => {
  it('carries response_type, client_id, redirect_uri and state with URL encoding', () => {
    const cfg: SsoConfig = {
      ssoEnabled: true,
      ssoClientId: 'S007627-RAG',
      ssoClientSecret: 'DSH_LOGIN_SSO_CLIENT_SECRET',
      ssoAuthorizeUrl: 'https://login.huawei.com/idp/oauth2/authorize',
      ssoTokenUrl: 'https://login.huawei.com/idp/oauth2/token',
      ssoUserInfoUrl: 'https://login.huawei.com/idp/oauth2/userinfo',
      ssoRedirectUri: 'http://10.1.2.3:3080/api/auth/sso/callback',
      ssoUidField: 'uid',
    }
    const url = new URL(buildAuthorizeUrl(cfg, 'st ate/1', 'http://h/callback?a=1&b=2'))
    expect(url.origin).toBe('https://login.huawei.com')
    expect(url.pathname).toBe('/idp/oauth2/authorize')
    expect(url.searchParams.get('response_type')).toBe('code')
    expect(url.searchParams.get('client_id')).toBe('S007627-RAG')
    expect(url.searchParams.get('redirect_uri')).toBe('http://h/callback?a=1&b=2')
    expect(url.searchParams.get('state')).toBe('st ate/1')
  })
})

describe('upsertSsoUser auto-provisioning', () => {
  it('makes the first SSO login the admin and later ones ordinary users', async () => {
    root = await mkdtemp(join(tmpdir(), 'dsh-sso-provision-'))
    context = new Context()
    context.baseUrl = pathToFileURL(root).href + '/'
    await context.plugin(MemoryCredentials)
    const users = new UserStore(context.credentials, credentialRef('DSH_LOGIN_PASSWORD_USERS'))

    const first = await upsertSsoUser(users, 'zhangsan01')
    expect(first.isAdmin).toBe(true)
    const second = await upsertSsoUser(users, 'lisi02')
    expect(second.isAdmin).toBe(false)

    // Repeat login: no duplicate account, admin flag preserved.
    const again = await upsertSsoUser(users, 'zhangsan01')
    expect(again.username).toBe('zhangsan01')
    expect(again.isAdmin).toBe(true)
    expect((await users.list()).length).toBe(2)
  })
})

describe('SSO callback integration (fake IDaaS)', () => {
  it('exchanges code, auto-provisions, issues a session and rejects state replay', async () => {
    root = await mkdtemp(join(tmpdir(), 'dsh-sso-integration-'))
    context = new Context()
    context.baseUrl = pathToFileURL(root).href + '/'
    await context.plugin(MemoryCredentials, { DSH_LOGIN_SSO_CLIENT_SECRET: 'Huawei@123' })
    const store = new SessionStore(3600)
    const users = new UserStore(context.credentials, credentialRef('DSH_LOGIN_PASSWORD_USERS'))
    const states = new SsoStateStore()

    const idaas = startFakeIdaas()
    await new Promise<void>(resolve => { idaas.listen(0, '127.0.0.1', resolve) })
    const idaasPort = String((idaas.address() as AddressInfo).port)
    const base = `http://127.0.0.1:${idaasPort}`

    const cfg: SsoConfig = {
      ssoEnabled: true,
      ssoClientId: 'S007627-RAG',
      ssoClientSecret: 'DSH_LOGIN_SSO_CLIENT_SECRET',
      ssoAuthorizeUrl: `${base}/authorize`,
      ssoTokenUrl: `${base}/token`,
      ssoUserInfoUrl: `${base}/userinfo`,
      ssoRedirectUri: 'http://127.0.0.1:3080/api/auth/sso/callback',
      ssoUidField: 'uid',
    }
    const handler = createSsoCallbackHandler({
      cfg,
      users,
      store,
      sessionTtl: 3600,
      states,
      resolveSecret: async () => 'Huawei@123',
    })

    // Happy path: code exchange succeeds, first SSO login provisions an admin.
    const ok = fakeRes()
    const state = states.issue()
    await handler(fakeReq(`/api/auth/sso/callback?code=good-code&state=${state}`), ok)
    expect(ok.status).toBe(302)
    expect(ok.location).toBe('/')
    expect(ok.cookie).toContain('dsh_session=')
    const records = await users.list()
    expect(records.length).toBe(1)
    expect(records[0]?.username).toBe('zhangsan01')
    expect(records[0]?.isAdmin).toBe(true)

    // State replay: consumed once → CSRF bounce.
    const replay = fakeRes()
    await handler(fakeReq(`/api/auth/sso/callback?code=good-code&state=${state}`), replay)
    expect(replay.status).toBe(302)
    expect(replay.location).toBe('/login?error=sso_bad_state')

    // Tampered state never existed: same bounce.
    const tampered = fakeRes()
    await handler(fakeReq('/api/auth/sso/callback?code=two&state=deadbeef'), tampered)
    expect(tampered.location).toBe('/login?error=sso_bad_state')

    // Bad secret: token endpoint 500 → coarse error, no cookie, no account.
    states.issue()
    const badSecret = fakeRes()
    const badHandler = createSsoCallbackHandler({
      cfg,
      users,
      store,
      sessionTtl: 3600,
      states,
      resolveSecret: async () => 'wrong-secret',
    })
    const badState = states.issue()
    await badHandler(fakeReq(`/api/auth/sso/callback?code=good-code&state=${badState}`), badSecret)
    expect(badSecret.status).toBe(302)
    expect(badSecret.location).toBe('/login?error=sso_exchange_failed')
    expect((await users.list()).length).toBe(1)

    idaas.close()
  })
})

/** Fake IDaaS: /token (JSON body, verifies secret) and /userinfo (Bearer). */
function startFakeIdaas(): Server {
  return createServer((req, res) => {
    let raw = ''
    req.on('data', (chunk: Buffer) => { raw += chunk.toString() })
    req.on('end', () => {
      const path = req.url ?? ''
      if (path.startsWith('/token')) {
        let body: Record<string, unknown> = {}
        try { body = JSON.parse(raw) as Record<string, unknown> } catch { /* fall through */ }
        if (
          body.grant_type !== 'authorization_code' ||
          body.client_id !== 'S007627-RAG' ||
          body.client_secret !== 'Huawei@123' ||
          body.code !== 'good-code'
        ) {
          res.writeHead(500)
          res.end()
          return
        }
        res.writeHead(200, { 'content-type': 'application/json' })
        res.end(JSON.stringify({ access_token: 'at-123', token_type: 'Bearer' }))
        return
      }
      if (path.startsWith('/userinfo')) {
        if (req.headers.authorization !== 'Bearer at-123') {
          res.writeHead(401)
          res.end()
          return
        }
        res.writeHead(200, { 'content-type': 'application/json' })
        res.end(JSON.stringify({ uid: 'zhangsan01', name: '张三' }))
        return
      }
      res.writeHead(404)
      res.end()
    })
  })
}
