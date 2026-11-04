# StandarReader 2.56.1 WebView 逆向基线（静态）

适用范围：仅香色闺阁（StandarReader）2.56.1。  
目标：把“WebView 相关字段语义”从经验规则升级为可追溯基线，并映射到 `tools/validator` 执行模型。

---

## 1. 样本与证据来源

- App 包路径（仓库内置，2026-07-05 复扫）：
  - `Tg@TrollstoreKios.app/`
- 主二进制：
  - `Tg@TrollstoreKios.app/Tg@TrollstoreKios`
- 版本：`2.56.1`（`香色闺阁Plus` / `StandarReader`）
- 关键静态提取命令（示例）：
  - `plutil -p Info.plist`
  - `strings Tg@TrollstoreKios | rg -n "webView|webViewJs|webViewJsDelay|webViewSkipUrls|requestInfo|parserID|responseFormatType"`

---

## 2. 关键字段证据矩阵（静态）

| 证据编号 | 字段/符号 | 结论 |
|---|---|---|
| WV-001 | `webView` | 存在于主二进制字符串，属于正式请求链路开关候选。 |
| WV-002 | `webViewJs` | 存在，说明客户端支持 WebView 页面内 JS 注入/执行能力。 |
| WV-003 | `webViewJsDelay` | 存在，说明注入执行前存在延迟控制语义。 |
| WV-004 | `webViewSkipUrls` | 存在，说明导航中可按 URL 过滤/跳过子资源。 |
| WV-005 | `webViewSkipUrlsUnless` | 存在，为 `webViewSkipUrls` 的白名单覆盖规则（字符串或数组）。 |
| WV-006 | `webViewSniff` | 存在，客户端具备 WebView 嗅探/资源探测链路（`arrWebViewSniff`、`canLoadUrl:fromSniff:`）。 |
| WV-007 | `wkwebview_post` | 内置 JS 辅助函数，可在 WebView 内构造 form 并 `POST` 提交（`%@wkwebview_post("%@", "%@", %@)`）。 |
| WV-008 | `requestInfo` | 与 `parserID/responseFormatType` 同时出现，符合“请求构建 -> 解析”统一动作模型。 |
| WV-009 | `WKWebView` 相关字符串 | 存在 WebView 回调与导航上下文，WebView 非边缘功能。 |
| WV-010 | `params.requestUrls` / `params.responseUrl` | 日志/调试字符串存在，WebView 导航会累积 `requestUrls`，`responseUrl` 取最后一次响应对应 URL。 |
| WV-011 | `webViewForbidUrls` | 存在；配套符号 `LPNetWork_ForbidUrls` 与资源 `dir_res/plist_webviewforbidurls.plist`。语义为 WebView 导航禁止加载的 URL 列表（黑名单，与 `webViewSkipUrls` 同类）。2026-08-11 复扫新增，模拟器已并入 skip 过滤。 |
| WV-012 | `LPWebViewManager` 双实例池 (`0x100091be4`) | 官方 `StandarReader.app` 指令级确认：维护标准池 `_arrWebViews` 与嗅探池 `_arrSniffWebViews`（挂载 `LPURLSchemeHandler` `0x1000dccb4` 拦截 `http`/`https`），每个池最多缓存 **9 个** `LPWebView` 实例。 |
| WV-013 | `sourceRegex` (`0x100093eb4`) | 官方指令级确认：不区分大小写正则。在 `canLoadUrl:fromSniff:` (`0x100093b40`) 中一旦请求 URL 匹配 `sourceRegex`，立即调用 `onCallBack:` 将该匹配到的资源 URL 字符串直接作为本次请求响应返回。 |
| WV-014 | `webViewJs` / `webViewJsDelay` (`0x100094200`) | 官方指令级确认：`webViewJs` 缺省值为 `"document.documentElement.outerHTML"`；`webViewJsDelay` 在配置了 `sourceRegex` 时缺省为 **`3.0` 秒**，未配置时缺省为 **`1.0` 秒**；单次加载总超时定时器为 **`60.0` 秒** (`0x100093530`)。 |
| WV-015 | `webViewContentRules` (`0x100092af4`) | 官方指令级确认：自定义 `WKContentRuleList` JSON 规则；未设置时默认编译内置规则屏蔽 `image` 与 `style-sheet` 资源以加速渲染。 |

---

## 3. 模拟器映射规则（唯一真值）

本仓将上表映射为以下执行契约（`tools/validator`）：

1. 引擎路由：
   - `--engine auto`（默认）：动作命中 WebView 信号键时走 `webview`，否则走 `http`。
   - `--engine webview`：强制 WebView 执行。
   - `--engine http`：强制 HTTP 执行。

2. 字段行为：
   - `webView=true`：触发 WebView 路径。
   - `webViewJs`：在页面可执行后注入。
   - `webViewJsDelay`：注入前等待（秒）。
   - `webViewSkipUrls`：导航请求 URL 过滤规则（黑名单）。
    - `webViewSkipUrlsUnless`：白名单覆盖；命中时即使匹配 skip 规则也继续加载。
    - `webViewForbidUrls`：禁止加载的 URL 列表；模拟器将其并入 skip 过滤（`shouldSkipUrl` 合并 `webViewSkipUrls` 与 `webViewForbidUrls`）。
    - `webViewSniff`：启用嗅探模式（仅在高可信场景使用；默认优先 API/HTTP）。
   - `wkwebview_post(path, charset, params)`：WebView 内表单 POST 辅助，适合挑战页/登录页二次提交。

3. 结构化报告新增：
   - `runtime_engine`
   - `webview_applied_keys`
   - `webview_trace`

4. 归因规则：
   - `403/429/challenge` 归类为 `blocked`。
   - `blocked` 与 parser 失败分离，不混淆为“规则写错”。

---

## 4. 执行验证模板

```bash
python tools/scripts/xbs_tool.py simulate-live \
  -i /abs/source.xbs \
  --engine auto \
  --webview-timeout 25 \
  --report /abs/source.simulate.json
```

验收最小要求：
- 报告中四步都出现 `runtime_engine`。
- WebView 源至少一个步骤出现 `runtime_engine=webview` 且有 `webview_trace` 事件。
- 若阻断，`simulation_verdict=blocked` 且 `blocked_reason` 非空。

