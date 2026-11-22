# macOS 移植说明

上游：[Wahwayhale/dsh-connect-doubao](https://github.com/Wahwayhale/dsh-connect-doubao)（MIT，v0.8.0）。
本仓库是它的 macOS 移植版，**协议实现一行未改**：`doubao-upstream.ts`（豆包方言、SSE 帧解析、
生图 skill、任务模式 `tool_local` 桥接）、`doubao-shim.ts`（回环 shim、工具模拟、会话续接）、
`doubao-adapter.ts`（pi-ai provider 装配）、`doubao-catalog.ts` / `doubao-discovery.ts`
（模型目录与 Preferences 里那份 V8 structured clone 的解析）全部原样保留。

上游把「仅 Windows」写进了设计：会话用 DPAPI 密封、Chrome 路径写死成 `Program Files`、
数据目录按 `%LOCALAPPDATA%` 找、结束进程用 `taskkill`。这四处就是移植的全部改动范围，
另外补了一个「Linux 明确拒绝」的出口，避免在没密钥库的平台上偷偷明文落盘。

## 改了什么

| 文件 | 改动 |
| --- | --- |
| `src/doubao-seal.ts`（新增） | 平台密封层。Windows 保留原 DPAPI 实现（PowerShell + crypt32、payload 走 stdin、子进程环境白名单）；macOS 用登录钥匙串里的 32 字节密钥做 AES-256-GCM，密文写 `~/.dsh/doubao-credentials-browser.sealed`（0600），信封带 `keyId` 校验；Linux 直接抛错 |
| `src/doubao-auth.ts` | 只保留「一个来源」的凭据逻辑，DPAPI 代码搬去 `doubao-seal.ts`；文件名改为 `.sealed`，同时只读兼容旧的 `.dpapi`；新增 `credentialSealLabel()` 给 `doctor` 用 |
| `src/doubao-auth-browser.ts` | Chromium 探测按平台分支：macOS 走 `Google Chrome.app` / `Edge.app` / `Chromium.app` / `Brave Browser.app`，二进制名从各 bundle 的 `Info.plist`（`CFBundleExecutable`）读，不猜路径；新增 `DSH_DOUBAO_BROWSER` 覆盖；结束进程 macOS 用 `pkill -f <profile目录>` 连渲染进程一起收 |
| `src/doubao-profile.ts` | `listDoubaoProfiles` 支持 `darwin`：默认路径 `~/Library/Application Support/Doubao`（mac 没有 `User Data` 一层）；进程探测从 PowerShell 换成 `ps -axo args`；扫描只认名字里带 `doubao` 的目录，避免把 Chrome 的 `Default/` 误判成本机豆包；`looksLikeProfile` 同时接受 `Default/Preferences`、`Default/Network/Cookies`、`Default/Cookies` |
| `src/doubao-upstream.ts` | `general_task_param.client_option.os` 在 macOS 上报 `Mac`。请求头指纹仍是抓包得到的 Windows 那套——那是唯一端到端验证过的形状，没有必要改 |
| `src/cli-login.ts`（新增）+ `src/bin.ts` | 新增 `dsh-connect-doubao login` 子命令，终端里也能完成那次扫码；不打印任何 cookie 值 |
| `src/cli-doctor.ts`、`src/doubao-config.ts`、`package.json` | 文案与平台说明；`@earendil-works/pi-ai` peer 范围放宽到 `>=0.85.0 <2.0.0`（宿主 0.2.2-rc.5 带的是 1.3.0） |
| `tests/` | DPAPI 断言改指向 `doubao-seal.ts`，补 macOS 密封与 mac 目录布局用例 |

## 为什么用钥匙串而不是「0600 文件就算密封」

DPAPI 的承诺是「换个 Windows 账户、换台机器都解不开」。单纯 0600 文件只做到「同机其他用户
读不到」，一旦文件被拷走就等于明文。macOS 的等价物是登录钥匙串：密钥在钥匙串里，密文在
`~/.dsh`。所以默认路径是钥匙串，只有钥匙串不可用（被锁、SSH 无解锁会话、策略禁止 `security`）
时才回落到 0600 密钥文件，并且 `doctor` / `login` 会**如实打出当前用的是哪一种**，不把两者
说成一样。

代价是每次冷读多一次 `security` 调用（进程内缓存 10 分钟后基本可以忽略）；`security
add-generic-password` 只支持把密钥写在 argv 里，所以密钥创建那一刻会短暂出现在同用户的
`ps` 里，而不会以明文落盘。

## 在这台机器上验证过什么

| 项 | 结果 |
| --- | --- |
| `npm run typecheck` | 通过（node 侧 + browser 侧两套 tsconfig） |
| `npm run build` | 通过（ESM 宿主侧 + CJS 客户端半；客户端仍是 `client.js` 的 loader 契约） |
| 密封闭环 | `seal → unseal` 往返一致；篡改密文被 GCM tag 拒绝；钥匙串条目 32 字节，无回落密钥文件 |
| `dsh-connect-doubao-doctor` | provider 装配 ok（shim 绑定回环、错 bearer 401、adapter 构造成功）；**模型发现读到本机豆包客户端的 15 个模型**；credentials 未登录（尚未扫码） |
| 单测 | 22 个文件 263 个用例，256 通过；7 个失败与上游同一份代码在同一环境下的失败完全一致（都是「本机还没有登录态」导致的 401 `session_dead`），非移植引入 |

**没验证的部分（如实说）**：真实对话 / 生图 / 额度读数需要先扫码登录，那一步只能由你本人完成。
登录后再跑一次 `dsh-connect-doubao-doctor`，五项应当全绿；上面那 7 个用例也会随之转绿。

## 安装 / 卸载

```bash
# 安装（已在本机 desktop profile 里执行过一次）
dsh plugin --profile desktop add "$HOME/workspace/dsh-workspace/plugins/dsh-connect-doubao"

# 卸载
dsh plugin --profile desktop remove dsh-connect-doubao

# 改完源码重新构建即可，link: 依赖不需要重装
npm run build
```

装完要重启一次 DeepSeek Harness，插件才会被加载；「豆包」会出现在设置左栏与模型选择器里。

## 本地开发的两个坑

1. **宿主包是软链，不是 npm 依赖。** `@deepseek-ai/*` 与 `@earendil-works/pi-ai` 在公共 npm 上
   只有 `0.0.1-rc.1`，版本对不上，所以本仓库把它们从 devDependencies 里摘出来，用软链指向
   本机 `~/workspace/opensource/deepseek-harness` 的构建产物。**别在该目录里跑 `npm install`**：
   它会把软链换成 registry 上的旧版本，类型检查立刻红。要重建软链：

   ```bash
   H=~/workspace/opensource/deepseek-harness/packages
   for p in client/locale:dsh-client-locale client/ui-renderer:dsh-client-ui-renderer \
            client/ui-settings:dsh-client-ui-settings client/ui-settings-plugins:dsh-client-ui-settings-plugins \
            client/ui-slots:dsh-client-ui-slots host/webserver:dsh-host-webserver \
            llm/llm:dsh-llm llm/llm-pi-ai:dsh-llm-pi-ai; do
     ln -sfn "$H/${p%%:*}" "node_modules/@deepseek-ai/${p##*:}"
   done
   ```

2. **不要再提交 `package-lock.json`。** 上游那份锁文件钉的是公共 npm 上并不存在的版本，
   留着只会让 `npm ci` 当场失败。运行期依赖全部由宿主提供，构建期只需要
   `tsdown` / `typescript` / `vitest`。

## 已知限制（mac 侧新增的）

1. **钥匙串授权**：首次写入会在登录钥匙串里创建一个 `dsh-connect-doubao`（account=当前用户名）
   的通用密码条目。若系统策略要求交互授权，`login` 会报错并回落到密钥文件——不会静默失败。
2. **浏览器必须是 Chromium 内核**：Safari / Firefox 不行（CDP 需要 Chromium）。豆包自有浏览器
   没有列入默认候选，必要时用 `DSH_DOUBAO_BROWSER` 指过去。
3. **Intel 与 Apple Silicon 都支持**：没有任何原生依赖，`security` 与内置 `crypto` 都是系统自带。
4. 上游原有的限制照旧：非官方接口、`model_item_key` 服务端不校验、不转发图片输入、风控滑块
   要人工完成。
