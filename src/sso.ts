/**
 * Huawei intranet SSO (IDaaS 2.0 / uniportal OAuth2.0) client for the
 * authorization-code flow.
 *
 * Protocol notes (from the intranet SSO integration guide):
 * - Only the authorization-code grant is supported by the platform.
 * - The token/userinfo endpoints are NON-standard: the token request carries
 *   client_id/client_secret as a JSON body (not Basic Auth, not form-encoding),
 *   so a hand-rolled POST is used instead of a generic OIDC client library.
 * - `state` must be stored server-side and compared + consumed once on the
 *   callback (CSRF).
 * - `redirect_uri` must be URL-encoded in the authorize query string.
 * - Secrets/tokens/codes never reach the browser and never reach the logs:
 *   failures surface as coarse error codes (`sso_*`), and only status codes /
 *   field names are logged, never values.
 */
import { randomBytes } from 'node:crypto'
import type { IncomingMessage } from 'node:http'

/** Well-known error codes surfaced to the login page via `?error=`. */
export type SsoErrorCode =
  | 'sso_bad_state'
  | 'sso_not_configured'
  | 'sso_exchange_failed'
  | 'sso_userinfo_failed'
  | 'sso_no_uid'
  | 'sso_provision_failed'
  | 'sso_pending_activation'

/** SSO channel configuration (flat keys in the plugin Config). */
export interface SsoConfig {
  /** Master switch; false registers no SSO routes. */
  ssoEnabled: boolean
  /** OAuth2 client_id registered in the IDaaS console. */
  ssoClientId: string
  /** Credential ref name holding the client secret (value never in config). */
  ssoClientSecret: string
  /** IDaaS authorize endpoint. */
  ssoAuthorizeUrl: string
  /** IDaaS token endpoint. */
  ssoTokenUrl: string
  /** IDaaS userinfo endpoint. */
  ssoUserInfoUrl: string
  /** Pre-registered callback URL; '' derives it from the request Host. */
  ssoRedirectUri: string
  /** Userinfo field holding the 工号; falls back to standard OIDC names. */
  ssoUidField: string
  /** 工号 allowlist: listed uids provision/promote as admin. */
  ssoAdminUids: string[]
}

export const SsoDefaults = {
  ssoEnabled: false,
  ssoClientId: '',
  ssoClientSecret: 'DSH_LOGIN_SSO_CLIENT_SECRET',
  ssoAuthorizeUrl: 'https://login.huawei.com/idp/oauth2/authorize',
  ssoTokenUrl: 'https://login.huawei.com/idp/oauth2/token',
  ssoUserInfoUrl: 'https://login.huawei.com/idp/oauth2/userinfo',
  ssoRedirectUri: '',
  ssoUidField: 'uid',
  ssoAdminUids: [],
} satisfies Record<keyof SsoConfig, unknown>

/**
 * One-time state store for the authorize/callback round trip. Server-side
 * only (in-memory): a state is valid for `ttlSeconds` and consumable exactly
 * once, which is what the CSRF check needs.
 */
export class SsoStateStore {
  private readonly store = new Map<string, number>()

  constructor(private readonly ttlSeconds = 300) {}

  /** Mint a fresh state bound to the current time window. */
  issue(): string {
    this.sweep()
    const state = randomBytes(24).toString('hex')
    this.store.set(state, Date.now() + this.ttlSeconds * 1000)
    return state
  }

  /** Accept a state exactly once; expired/unknown/replayed states are rejected. */
  consume(state: string): boolean {
    const expiresAt = this.store.get(state)
    if (expiresAt === undefined || Date.now() > expiresAt) return false
    this.store.delete(state)
    return true
  }

  private sweep(): void {
    const now = Date.now()
    for (const [state, expiresAt] of this.store) {
      if (now > expiresAt) this.store.delete(state)
    }
  }
}

/** Build the IDaaS authorize redirect URL (redirect_uri/state URL-encoded). */
export function buildAuthorizeUrl(cfg: SsoConfig, state: string, redirectUri: string): string {
  const url = new URL(cfg.ssoAuthorizeUrl)
  url.searchParams.set('response_type', 'code')
  url.searchParams.set('client_id', cfg.ssoClientId)
  url.searchParams.set('redirect_uri', redirectUri)
  url.searchParams.set('state', state)
  return url.toString()
}

/**
 * Resolve the callback URL for this request. Explicit `ssoRedirectUri` wins;
 * otherwise derive from the request Host (protocol+domain, as the IDaaS
 * console registers them — no path guessing behind proxies).
 */
export function resolveRedirectUri(cfg: SsoConfig, req: IncomingMessage): string {
  if (cfg.ssoRedirectUri !== '') return cfg.ssoRedirectUri
  const host = req.headers.host ?? 'localhost'
  const forwarded = req.headers['x-forwarded-proto']
  const proto = typeof forwarded === 'string' && forwarded.length > 0
    ? forwarded.split(',')[0]?.trim() || 'http'
    : 'http'
  return `${proto}://${host}/api/auth/sso/callback`
}

/**
 * Exchange the one-time authorization code for an access token.
 * Non-standard body: JSON carrying client_id/secret (NOT Basic Auth, NOT
 * form-encoding) per the IDaaS token endpoint.
 */
export async function exchangeCode(
  cfg: SsoConfig,
  clientSecret: string,
  code: string,
  redirectUri: string,
  fetchImpl: typeof fetch = fetch,
): Promise<string> {
  const res = await fetchImpl(cfg.ssoTokenUrl, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      grant_type: 'authorization_code',
      client_id: cfg.ssoClientId,
      client_secret: clientSecret,
      code,
      redirect_uri: redirectUri,
    }),
    signal: AbortSignal.timeout(10_000),
  })
  if (!res.ok) throw new Error(`token endpoint ${String(res.status)}`)
  const body = (await res.json()) as { access_token?: unknown }
  if (typeof body.access_token !== 'string' || body.access_token.length === 0) {
    throw new Error('token response missing access_token')
  }
  return body.access_token
}

/**
 * Fetch the SSO user info with the access token. Bearer header first; a single
 * `?access_token=` retry covers IDaaS deployments whose userinfo endpoint
 * rejects the standard header.
 */
export async function fetchUserInfo(
  cfg: SsoConfig,
  accessToken: string,
  fetchImpl: typeof fetch = fetch,
): Promise<Record<string, unknown>> {
  let res = await fetchImpl(cfg.ssoUserInfoUrl, {
    headers: { authorization: `Bearer ${accessToken}` },
    signal: AbortSignal.timeout(10_000),
  })
  if (res.status === 401) {
    const url = new URL(cfg.ssoUserInfoUrl)
    url.searchParams.set('access_token', accessToken)
    res = await fetchImpl(url, { signal: AbortSignal.timeout(10_000) })
  }
  if (!res.ok) throw new Error(`userinfo endpoint ${String(res.status)}`)
  const info = (await res.json()) as unknown
  if (typeof info !== 'object' || info === null) throw new Error('userinfo response is not an object')
  return info as Record<string, unknown>
}

/**
 * Resolve the 工号 from the userinfo payload: the configured field first,
 * then the standard OIDC subject claims. `uuid` is deliberately NOT a
 * fallback — silently registering a uuid as username hides a misconfigured
 * console (附加信息 must tick uid).
 */
export function resolveUid(info: Record<string, unknown>, uidField: string): string | undefined {
  const keys = uidField === '' ? ['uid'] : [uidField, 'uid']
  for (const key of [...keys, 'sub', 'username', 'preferred_username']) {
    const value = info[key]
    if (typeof value === 'string' && value.length > 0) return value
  }
  return undefined
}
