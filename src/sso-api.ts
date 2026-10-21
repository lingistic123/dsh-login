/**
 * SSO channel route handlers: authorize redirect + callback exchange.
 *
 * Flow (minimal closed loop):
 *   GET /api/auth/sso/authorize  → 302 IDaaS authorize (state minted server-side)
 *   IDaaS 302 back               → GET /api/auth/sso/callback?code&state
 *     ① state compared + consumed once (CSRF)
 *     ② backend POST token endpoint (JSON body client_id/secret — the secret
 *        never leaves the server process)
 *     ③ userinfo → 工号 → auto-provision the UserStore record on first login
 *        (the first SSO login ever becomes the admin; later ones are ordinary)
 *     ④ dsh-login session issued, cookie set, 302 to /
 *
 * Every failure bounces to /login?error=sso_<code> — coarse codes only, never
 * tokens/codes/secret values.
 */
import { randomBytes } from 'node:crypto'
import type { ServerResponse, IncomingMessage } from 'node:http'
import type { WebRoute } from '@deepseek-ai/dsh-host-webserver'
import type { SessionStore } from './session.ts'
import type { UserStore, UserRecord } from './users.ts'
import { buildCookieHeader } from './auth.ts'
import {
  buildAuthorizeUrl,
  exchangeCode,
  fetchUserInfo,
  resolveRedirectUri,
  resolveUid,
  type SsoConfig,
  type SsoErrorCode,
  type SsoStateStore,
} from './sso.ts'

/** Shared dependencies for the callback handler. */
export interface SsoCallbackDeps {
  cfg: SsoConfig
  users: UserStore
  store: SessionStore
  /** Session lifetime in seconds; stamped onto the Set-Cookie Max-Age. */
  sessionTtl: number
  states: SsoStateStore
  /** Resolve the client secret from the DSH credentials system. */
  resolveSecret: () => Promise<string | undefined>
}

/**
 * GET /api/auth/sso/authorize — mint a one-time state and 302 to the IDaaS
 * authorize endpoint. No session required: this is the front door.
 */
export function createSsoAuthorizeHandler(cfg: SsoConfig, states: SsoStateStore): WebRoute['handler'] {
  return (req: IncomingMessage, res: ServerResponse) => {
    const state = states.issue()
    const redirectUri = resolveRedirectUri(cfg, req)
    res.writeHead(302, { Location: buildAuthorizeUrl(cfg, state, redirectUri) })
    res.end()
  }
}

/**
 * Auto-provision the UserStore record for an SSO identity. Existing usernames
 * log straight in; a first-ever SSO login becomes the admin. The scrypt
 * password is random and unknowable — the SSO channel is the only way in for
 * provisioned accounts (password login remains for locally created users).
 */
export async function upsertSsoUser(users: UserStore, uid: string): Promise<UserRecord> {
  const records = await users.list()
  const existing = records.find(u => u.username === uid)
  if (existing !== undefined) return existing
  const isAdmin = records.length === 0
  const random = randomBytes(24).toString('hex')
  try {
    return await users.create(uid, random, isAdmin)
  } catch {
    // Race with a concurrent first login, or a uid outside the username
    // pattern — re-lookup, then fail loudly (error redirect, no silent account).
    const again = (await users.list()).find(u => u.username === uid)
    if (again !== undefined) return again
    throw new Error(`cannot provision sso user "${uid}"`)
  }
}

/** GET /api/auth/sso/callback — consume state, exchange the code, log in. */
export function createSsoCallbackHandler(deps: SsoCallbackDeps): WebRoute['handler'] {
  return async (req: IncomingMessage, res: ServerResponse) => {
    const fail = (code: SsoErrorCode): void => {
      res.writeHead(302, { Location: `/login?error=${code}` })
      res.end()
    }
    const url = new URL(req.url ?? '/', 'http://x')
    const code = url.searchParams.get('code')
    const state = url.searchParams.get('state')
    if (code === null || code.length === 0 || state === null || !deps.states.consume(state)) {
      return fail('sso_bad_state')
    }
    let secret: string | undefined
    try {
      secret = await deps.resolveSecret()
    } catch {
      secret = undefined
    }
    if (secret === undefined || secret.length === 0) return fail('sso_not_configured')
    const redirectUri = resolveRedirectUri(deps.cfg, req)
    let accessToken: string
    try {
      accessToken = await exchangeCode(deps.cfg, secret, code, redirectUri)
    } catch {
      return fail('sso_exchange_failed')
    }
    let info: Record<string, unknown>
    try {
      info = await fetchUserInfo(deps.cfg, accessToken)
    } catch {
      return fail('sso_userinfo_failed')
    }
    const uid = resolveUid(info, deps.cfg.ssoUidField)
    if (uid === undefined) return fail('sso_no_uid')
    let record: UserRecord
    try {
      record = await upsertSsoUser(deps.users, uid)
    } catch {
      return fail('sso_provision_failed')
    }
    const session = deps.store.create(record.username, record.isAdmin)
    res.setHeader('Set-Cookie', buildCookieHeader(session.token, deps.sessionTtl))
    res.writeHead(302, { Location: '/' })
    res.end()
  }
}

