# DSH 域名入口 403 问题 — 复盘报告

> 日期：2026-10-22
> 部署：DSH Harness 运行于 `100.102.191.200`（单进程 `--profile web --port 3080`），nginx 反向代理运行于 `100.102.191.161`，对外入口 `http://aiinside.service.huawei.com:3080/`

---

## 一、问题现象

用户 zhangzhengrui 在 IE 中输入 `100.102.191.200:3080` → 自动跳转到 `aiinside.service.huawei.com:3080` 登录页 → 登录成功进入 GUI 后，页面各类接口报错：

```
client api: directoryPicker/list failed: transport failure for /api/directoryPicker/list: HTTP 403
```

而直接通过 `100.102.191.200:3080` 登录使用，一切正常。

## 二、排查过程中的关键判据（三种"拒绝"的形状）

DSH 的 `/api` 桥接前面有三道独立的闸门，**拒绝的响应形态各不相同**，这是定位根因的核心线索：

| 闸门 | 层 | 拒绝形态 | 说明 |
|---|---|---|---|
| ① Trust Fence | `@deepseek-ai/dsh-client-connection`（harness 源码） | **裸 403 `forbidden`** | Host/Origin 信任校验，在 dsh-login 之前 |
| ② Browser-Auth | connection 进程内浏览器 cookie 校验 | 裸 401 `unauthorized` | cookie 是 authority-bound（绑定 Host） |
| ③ dsh-login Wall | dsh-login 插件（`connection/request` 监听器） | 401 / 或 200 + JSON 信封 `{ok:false, code:'forbidden'}`（quiet deny） | 会话校验 + `USER_ALLOWED` 白名单 |

用户看到的 **"transport failure … HTTP 403"** 正是 ① 的形状 —— 请求死在 fence，根本没到 dsh-login。

## 三、根因（两个，叠加出现）

### 根因 1：Origin fence 与 nginx Host 改写冲突（HTTP 403 的直接原因）

nginx（161）`proxy_pass http://100.102.191.200:3080/;` **默认会把 Host 改写为上游地址**，而浏览器发出的 Origin 头仍是域名：

```
浏览器 → Origin: http://aiinside.service.huawei.com:3080
                 ↓ nginx（Host 改写为上游地址）
DSH   ←  Host: 100.102.191.200:3080   Origin: http://aiinside.service.huawei.com:3080
```

`isTrustedApiRequest`（`packages/client/connection/src/api-request-trust.ts`）的 Origin fence 要求 **Origin 与 Host 的 authority 完全一致**，二者不一致 → 403。

直连 IP 入口时浏览器 Host == Origin == `100.102.191.200:3080`，所以通过；经域名入口时二者分叉，所以失败。

### 根因 2：nginx 不转发 WebSocket 升级头（WS 断连的原因）

修完 ① 后，F12 仍报：

```
socket.ts:58 WebSocket connection to 'ws://aiinside.service.huawei.com:3080/api/remote.mux' failed
```

`/api/remote.mux` 是 Remote 流复用的 **WebSocket 升级通道**（GUI 实时事件流）。实测矩阵：

| 请求形态 | 经 nginx 161 | 直连 200:3080 |
|---|---|---|
| WS 升级（带 Upgrade 头） | **404 Not Found** | 101 Switching Protocols ✓ |

经代理的 WS 握手到达 DSH 时 **`Upgrade`/`Connection` 头被 nginx 剥掉**（nginx 默认行为，`proxy_http_version` 默认 1.0），变成普通 GET → 落到 fallback 404。HTTP `/api` 与 WS 走的是两条不同的闸门路径，所以 HTTP 修好后 WS 仍断。

## 四、修复

### 修复 1（harness 侧，2026-10-22 20:10）：放宽 Origin fence

`packages/client/connection/src/api-request-trust.ts` — Origin fence 增加第二条通过路径：Origin 的 authority 命中 `trustedHosts`（与 Host fence 同一套规范化）时放行；`null`、非 http(s) scheme、陌生 Origin 依旧 fail-closed。`sec-fetch-site: cross-site` 拒绝不变。

- 文件：`packages/client/connection/src/api-request-trust.ts`（新增 `isTrustedOriginAuthority`）
- spec：`packages/client/connection/tests/api-request-trust.host.spec.ts`（14/14 通过）
- 前置配置：`/root/.dsh/profiles/web/cordis.patch.yml` 的 `connection.trustedHosts` 列出四个入口 authority（`aiinside.service.huawei.com`、`100.102.191.161`、`100.102.191.200`、`141.186.205.48`）

### 修复 2（nginx 侧，2026-10-23 08:37）：161 上补 WS 代理头

`/etc/nginx/nginx.conf`（已备份 `nginx.conf.bak-20261022`）3080 server 块：

```nginx
location / {
    proxy_pass http://100.102.191.200:3080/;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header Host $host;
    proxy_set_header Origin $scheme://$host;
    proxy_read_timeout 3600s;
    proxy_buffering off;
}
```

`nginx -t` 通过，`nginx -s reload` 生效。

## 五、最终验证矩阵

| 探测 | 修复前 | 修复后 |
|---|---|---|
| `GET /` 经域名 → 302 `/?token=…` → 303（种 cookie）→ `GET /` | 302 循环 | **200**（SPA 正常） |
| `POST /api/directoryPicker/list` 经域名 + 双 cookie | 403 | **200** |
| WS `/api/remote.mux` 经 nginx | 404 | **101 Switching Protocols** |
| 伪造 Origin（`http://evil.example`） | 403 | 403（防线仍有效） |
| 直连 `100.102.191.200:3080` | 200 | 200（无回归） |

## 六、遗留与注意事项

1. **浏览器端缓存**：fence 修复后需 Ctrl+F5 强刷或清除站点 cookie 重登，旧的重定向链缓存会干扰验证。
2. **非管理员静默拒绝 ≠ 故障**：zhangzhengrui（isAdmin=false）会看到 `agentPresets.list`、`schedule.catalog`、`settings.describe`、`permissionPresets.catalog`、`dynamicCordisRunner.inventory`、`schedule.list` 等接口的 denied 错误 —— 这是 `USER_ALLOWED` 白名单的预期行为（HTTP 200 + denied 信封），不是 403 transport failure。管理员不受影响。
3. **161 的 nginx 配置不在本机版本控制内**，备份在 161 的 `/etc/nginx/nginx.conf.bak-20261022`。
4. 访问 161：ssh 用户 `AiInside`（密码 `AiInside#user@1`），sudo 同密码。
