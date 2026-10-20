/**
 * Pure physical-layer permission predicates for the dsh-login gateway.
 *
 * In DSH ≥ 0.1.5-alpha.1 dsh-login no longer takes over the `/api` carrier
 * (see docs/adapt-dsh-0.1.5.md, option A): the native `connection` +
 * `api-gateway` transport owns `/api`, and dsh-login composes its login wall
 * and — via the remote/controller layer — its per-user ownership enforcement on
 * top. The old `createUserProxy` (a per-method decorator over the removed
 * `@deepseek-ai/dsh-host-apiproxy` `ApiProxy`) is gone with that package; what
 * remains here is the pure, package-independent predicate surface that
 * `capabilities.ts` and the admission layer still rely on.
 */
export interface AuthUser { username: string; isAdmin: boolean }

/**
 * Physical-layer allow-list: every RpcMethodMap key (exact spellings copied
 * from the removed packages/host/apiproxy rpc-map — `session.list` singular,
 * etc.) an ordinary user may call through the /api carrier. Kept as the shared
 * source of truth for capability discovery (`deriveCapabilities`); in option A
 * the transport no longer hard-gates on it (upstream owns /api), but the
 * surface it describes is what the per-user admission seam must honor.
 */
export const USER_ALLOWED: ReadonlySet<string> = new Set([
  'session.list', 'session.search', 'session.create', 'session.selectModel',
  'session.rename', 'session.fork', 'session.prompt', 'session.attachment',
  'session.updateQueue', 'session.cancel',
  // DSH 0.2.1-rc.2 wire surface: the model picker reads the per-session model
  // catalog; history pagination moved from `session.history` to `session.page`;
  // the account page initializes the default model. All read-only or
  // own-account flows.
  'session.modelCatalog', 'session.page', 'session.initializeDefaultModel',
  'session.canOpenWorkspacePath', 'session.openWorkspacePath',
  'session.workspacePathApplications',
  // DSH 0.2.1-rc.2: the subagent runtime namespace is plural `subagents` with
  // renamed methods (`prompt`, `interruptByParent`) — the old singular
  // `subagent.list/history/prompt/interrupt` spellings no longer exist.
  'subagents.prompt', 'subagents.interruptByParent',
  'workspace.create', 'workspace.rename', 'workspace.delete',
  'workspace.insertBefore', 'workspace.insertSessionBefore', 'workspace.archiveSession',
  // DSH 0.1.6: restore one archived Session (pairs with archiveSession above).
  'workspace.unarchiveSession',
  // DSH 0.1.7: sidebar session pinning (pinned sessions ride the workspace
  // tree like rename/archive; both carry the workspace/session ids the guard's
  // GUARDED_ID_FIELDS already ownership-check).
  'workspace.pinSession', 'workspace.unpinSession',
  // DSH 0.1.7: the job controller (`dsh-api-job-controller`, typert namespace
  // `job`; SessionJob moved here out of `session`). `list`/`follow` are
  // reconnect-safe streams and `kill` is the human stop button — the same
  // trust boundary as `session.prompt`. Every request carries `sessionId`
  // (JobFollowRequest omits it only for unowned jobs, which any caller may
  // observe), ownership-checked through the guard's GUARDED_ID_FIELDS. Note:
  // `jobId` must NOT be added to the guarded fields — job ids are not in the
  // ownership sidecar and every id collected must resolve owned, which would
  // deny legitimate kills.
  'job.list', 'job.follow', 'job.kill',
  // DSH 0.1.6: the sidebar terminal (`dsh-api-terminal-controller`, typert
  // namespace `terminal`). Every method is session-agent-scoped by the Gateway
  // (the `agent` argument is supplied by the Gateway itself, never by the
  // browser), so it stays inside the caller's own agent subtree — the same
  // trust boundary as `session.prompt` (an agent can already run shell for the
  // user). `terminal.list` addresses a session explicitly and is ownership-
  // checked through the guard's GUARDED_ID_FIELDS (`sessionId`).
  'terminal.environment', 'terminal.shells', 'terminal.list', 'terminal.create',
  // DSH 0.2.1-alpha.3: `terminal.follow` became the bidirectional
  // `terminal.attach` stream — uplink write/resize now ride the attach stream
  // itself as sequenced commands, so the standalone `terminal.write` and
  // `terminal.resize` methods no longer exist on the wire.
  'terminal.attach', 'terminal.rename', 'terminal.close',
  // DSH 0.1.6-alpha.2: terminal retention across reconnects. `terminal.retain`
  // addresses a session explicitly (`sessionId`) and is ownership-checked
  // through GUARDED_ID_FIELDS like terminal.list. NOTE: since alpha.2 user
  // terminals run with the execution environment's system-user permissions
  // (no Agent sandbox), a deployment wanting stricter posture subtracts the
  // terminal.* entries from this set before wrapping (see docs/adapt-dsh-0.1.6-alpha.2.md).
  'terminal.retain',
  // DSH 0.2.1-alpha.3: the native remote-access client mounts on every page
  // and opens its `remoteAccess/follow` snapshot stream. The gateway always
  // allows this method and the answer only ever contains the caller's own
  // grants (an owner principal gets the owner baseline), so admitting it
  // here just keeps that mount silent instead of surfacing a denied-stream
  // error on every page load.
  'remoteAccess.follow',
  // DSH 0.1.6-alpha.2: the right Sidebar's document preview. The read surface
  // of `workspaceFiles` + the Office→PDF converter (`officeToPdf`) are what
  // every user's document/Office preview tab calls; each method's first wire
  // argument is the scoped session identity (`workspaceFileScopeId`), resolved
  // by the Gateway's workspaceFileScope lookup and ownership-checked through
  // GUARDED_ID_FIELDS. Read-only: no write/convert-bytes method is exposed to
  // the wire surface listed here.
  'workspaceFiles.read', 'workspaceFiles.readBytes', 'workspaceFiles.stat',
  'workspaceFiles.list', 'workspaceFiles.changes',
  'officeToPdf.render', 'officeToPdf.generation',
  // DSH 0.2.1-rc.2: the skill catalog (`skills.list`, plural namespace) backs
  // the composer's @-mention menu — a read-only catalog scoped to one session.
  'skills.list',
  // DSH 0.2.1-rc.2: the LLM directory moved from `llm.providers`/`llm.models`
  // to explicit method names; all three are read-only provider/model catalog
  // reads the 模型设置页 loads for every signed-in user.
  'llm.listProviders', 'llm.listConfigurableProviders', 'llm.discoverModels',
  // DSH 0.2.1-rc.2: the goal panel namespace is plural `goals` (was singular
  // `goal`), plus the `goals.get` read. Every method addresses the caller's
  // own session (`agentId`), ownership-checked through GUARDED_ID_FIELDS.
  'goals.create', 'goals.edit', 'goals.pause', 'goals.resume', 'goals.complete',
  'goals.clear', 'goals.get',
  // DSH 0.2.1-rc.2: the references panel (`fileReferences.list`) and the
  // composer attachment upload (`fileUploads.upload`) are ordinary-user
  // flows — both carry the session identity the guard ownership-checks.
  'fileReferences.list', 'fileUploads.upload',
  // DSH 0.2.1-rc.2: the add-workspace dialog (`ui-workspace/src/client/
  // navigation.ts`) drives `directoryPicker.pick`, and the picker page
  // browses via `directoryPicker.list` / creates via
  // `directoryPicker.createDirectory`. Denying these is what surfaced
  // "not permitted for this user" on 添加工作区. NOTE the tradeoff: the
  // picker browses the server filesystem, so deployments that want
  // strict per-user isolation keep these admin-only and rely on
  // `defaultWorkspace` provisioning instead.
  'directoryPicker.pick', 'directoryPicker.list', 'directoryPicker.createDirectory',
  // AICO console: the resource-probe/SSH/skills-suites plugin registers one
  // exact route under /api (`openlab-console`) and multiplexes db.get/db.save/
  // db.test, probe.*, ssh.*, suites.*, skills.* over it — one key admits the
  // whole plugin channel.
  'openlab-console',
  // AICO backflow: the right sidebar's 回流到 RAG button posts to one exact
  // route under /api (`openlab-backflow`) — same one-key-per-channel pattern
  // as the console.
  'openlab-backflow',
  // Live deny-log keys (wall diagnostic): the console panel's own channel
  // plus the two harness wire methods its client drives for the resource
  // probe — commands listing and the Cordis manifest sync probe.
  'console',
  'commands.list',
  'dynamicCordisRunner.syncInspectManifest',
])

/** May an ordinary (non-admin) user call this wire method? (Information surface only.) */
export function isUserAllowed(method: string): boolean {
  return USER_ALLOWED.has(method)
}