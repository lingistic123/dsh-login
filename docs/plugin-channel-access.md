# 普通用户插件通道授权指南（临时方案）

> 面向维护者。遇到「普通用户点插件功能报 not permitted for this user」时，按本文补键。
> 当前是**临时方案**：白名单硬编码；终局方向见文末。

## 机制：为什么新插件默认拒

dsh-login 0.3.5 起，普通用户的 `/api` 流量全部过桥墙（`src/api-bridge-auth.ts`）：

- 墙从请求 URL 提取键：`/api/<segment>[/<method>]` → `<segment>[.<method>]`（`endpointFromUrl`）
- 未命中 `USER_ALLOWED` 集合 → 静默拒绝包络：`{ok:false, error:{code:'forbidden', message:'not permitted for this user'}}`
- admin 无条件放行——所以「admin 测了没问题」不等于普通用户没问题

新插件自带的路由与方法**不在集合里**，普通用户默认全拒。这是设计行为，不是 bug。

## 症状

普通账号点插件功能报错，文案固定是 `not permitted for this user`；admin 账号一切正常。

## 诊断：读墙日志（第一现场）

墙的拒绝分支会打一行日志：

```
[dsh-login] wall deny endpoint=<键> user=<用户名> isAdmin=<角色>
```

`endpoint=` 的值就是**要补的键**。一次复现往往蹦出多条日志（一个面板会发多个请求），全部收集、一次补齐。

已知有两类键：

| 键形态 | 来源 | 例 |
|---|---|---|
| `<segment>`（单词） | 插件自有通道：`fetch.register` 挂到 `/api/<segment>`，整个通道一个键 | `console`、`backflow` |
| `<namespace>.<method>`（两点式） | harness 线方法（typert wire method），插件客户端直调 | `commands.list`、`dynamicCordisRunner.inventory`、`permissionPresets.catalog`、`schedule.catalog`、`schedule.list`、`messageFeedback.list` |

## 修法（四步）

1. **src 同步**：`src/api-filter.ts` 的 `USER_ALLOWED` 数组尾部加键，每个键带一行注释（哪个插件、哪个通道）。
2. **dist 同步**：`dist/index.js` 是编译产物，Host 实际加载的是它——同样的键加到同样的集合。**只改 src 不改 dist = 无效**。
3. **语法校验**：`node --check dist/index.js`（npm registry 403、装不了 vitest 的环境里的替代门）。
4. **落库 + 生效**：`git commit`（直推 master，本仓约定）→ `git push origin master` → **重启 DSH**。插件代码改动必须重启生效，热改无效。

## 已收录键速查（2026-10-20 状态）

| 键 | 归属 | 轮次 | 状态 |
|---|---|---|---|
| `openlab-console` / `openlab-backflow` | console、backflow 插件通道（旧版路由名） | 第 1 轮 | 生效 |
| `console` / `commands.list` / `dynamicCordisRunner.syncInspectManifest` | 资源探测/SSH/skills 面板 | 第 1 轮 | 生效 |
| `backflow` / `dynamicCordisRunner.inventory` / `permissionPresets.catalog` / `schedule.catalog` / `schedule.list` / `messageFeedback.list` | 回流按钮、Cordis 清单、权限预设、计计划、反馈列表 | 第 2 轮 | **已回撤**（跨用户数据面：实例级清单、他人反馈、全局目录——见 917bc23） |

新增键一律追加到表尾，保持「键 → 归属 → 轮次」三列。

## 排障经验

- **改了没生效先查两件事**：dist 是否同步、Host 是否重启。二者缺一即复现。
- 拒绝日志是唯一事实源——不要靠猜键名，跑一轮复现拿日志。
- 同一插件的通道键与线方法键是两个维度，都可能要补。

## 临时方案，终局方向

现状是白名单硬编码：新插件 = 新键 = 手动一轮。终局是**声明式自动适配**：

- 插件 manifest 声明 `userAccess: true`（或按 role 声明）；
- 插件安装/启用时，dsh-login 自动从 manifest 派生键并热加载；
- profile patch 留一处总控（允许/禁止某插件对普通用户开放）。

迁移路径：把 `USER_ALLOWED` 从 Set 字面量改成「内置基线 + manifest 派生 + patch 覆盖」三层合成，第一层先承载现存键，行为不变，再逐插件迁到派生层。
