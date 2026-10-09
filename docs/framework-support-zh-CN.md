# 框架检测范围

[使用参考](./reference-zh-CN.md) · [English](./framework-support.md)

本文描述开发分支的静态识别能力，不认证框架版本兼容性。扫描不执行框架、依赖或项目代码；以下为代表性写法，不是完整 SDK 清单。

## 通用边界

- 入口识别、鉴权证据和请求输入追踪分别判断。识别入口不代表理解其中每个操作；即使没有报告分析超限，未识别的语法仍可能漏检。
- 鉴权证据须覆盖相关操作并拒绝未认证请求。请求自带身份、中间件名称、Schema 校验和 OpenAPI 安全声明本身均不构成证明。间接或未解析证据可能保留 `likely` 结果，而不是消除结果。
- 输入追踪有界地跟进赋值、解构、字符串构造及可解析的透传函数，为 SQL/命令注入、外部请求和重定向检查提供来源；不等同于通用数据流或业务授权分析。
- Express、Hono、Fastify 的项目函数数据库写入最多跟进两层调用；文件约定路由不使用此类委托写入展开。鉴权辅助函数和输入辅助函数另有解析边界。
- 凭据、公开环境变量、Firebase/Supabase 配置及 CORS 检查仍按各自的文件和内容条件运行，不因项目未列入路由清单而停用。

测试：[身份校验](https://github.com/Tasomei/canship/blob/main/test/claimed-identity.test.ts)、[委托写入边界](https://github.com/Tasomei/canship/blob/main/test/delegated-writes.test.ts)、[输入追踪回归](https://github.com/Tasomei/canship/blob/main/test/request-input-regressions.test.ts)。

## Next.js

- **入口：**`pages/api/**`；App Router 的 `route.*`，包含 `app/api` 之外由 HTTP 导出识别的处理函数；以 `use server` 标记的导出或内联 Server Function。App Router 路径不计入路由组，并排除私有路由目录。
- **鉴权：**已识别的函数内拒绝逻辑；解析后的 Next.js middleware/proxy 范围可保护覆盖的处理函数。Server Function 须独立检查，不以中间件证明其受保护。
- **输入：**`req.query`、`req.body`、`request.json()`、`request.nextUrl.searchParams` 和 Server Function 参数。未导出且无自身指令的辅助函数、普通字符串中的指令不会创建 Server Function。
- **跨文件边界：**可解析的客户端、鉴权及输入辅助函数可提供证据；不按 Node 路由的委托写入方式展开服务函数中的数据库写入。

测试：[入口及 Server Function](https://github.com/Tasomei/canship/blob/main/test/frameworks.test.ts)、[中间件边界](https://github.com/Tasomei/canship/blob/main/test/middleware-boundaries.test.ts)、[请求输入](https://github.com/Tasomei/canship/blob/main/test/injection.test.ts)。

## SvelteKit

- **入口：**`src/routes/**/+server.*`，以及 `+page.server.*` 中的 `actions` 对象。
- **鉴权：**针对可信身份的已识别拒绝逻辑，包括 `locals.user`。`hooks.server.*` 中的鉴权迹象可降低置信度，不证明覆盖每个端点。
- **输入：**解构的 `request`、`url`、`params`，包括 `request.formData()` 和 `url.searchParams`。
- **边界：**页面 `load` 和 remote function 不进入路由分析。已识别的 `locals.supabase` 客户端可能交由数据库策略约束；没有 API 鉴权结果不代表 RLS 已验证。

测试：[端点、表单 action 及 load 排除](https://github.com/Tasomei/canship/blob/main/test/frameworks.test.ts)、[请求输入](https://github.com/Tasomei/canship/blob/main/test/injection.test.ts)。

## Nuxt / Nitro

- **入口：**`server/api/**` 和 `server/routes/**` 中含已识别 h3 处理函数的文件，例如 `defineEventHandler`。仅目录名不足以识别路由；显示的 URL 去掉方法后缀。
- **鉴权：**已识别的局部拒绝逻辑，包括支持的 `requireUserSession` 调用。`server/middleware` 中的鉴权迹象可降低置信度，不直接消除结果。
- **输入：**支持的事件读取函数，例如 `getQuery(event)`、`readBody(event)`、`getRouterParam(event)`。
- **边界：**不执行任意自动导入行为。仅位于 `server/api` 下的 tRPC router 不按 Nuxt 端点处理。已识别的 `serverSupabaseClient` 与管理员客户端区分，但不因此验证 RLS。

测试：[路由与鉴权正反例](https://github.com/Tasomei/canship/blob/main/test/frameworks.test.ts)、[事件读取](https://github.com/Tasomei/canship/blob/main/test/injection.test.ts)。

## Remix / React Router

- **入口：**`app/routes/**` 中的 `loader`、`action` 导出，包含已识别的扁平及文件夹约定。
- **鉴权：**处理函数或可解析辅助函数中的已识别拒绝逻辑。没有上述导出的纯组件模块不作为 API 入口。
- **输入：**处理函数的 `request` 及解构的 `params`，包括查询和请求体读取。
- **边界：**不凭框架名称推断自定义运行时路由配置。支持的 `~/` 解析仅提供项目证据，不执行任意依赖包。

测试：[路由模块及排除项](https://github.com/Tasomei/canship/blob/main/test/frameworks.test.ts)、[请求读取](https://github.com/Tasomei/canship/blob/main/test/injection.test.ts)。

## Astro

- **入口：**`src/pages/**` 下含已识别 HTTP 方法导出且无默认导出的脚本，包括 `src/pages/api` 以外的端点。
- **鉴权：**已识别的局部检查，包括可信的 `locals.user`，或覆盖该路由的 Astro 中间件。Next.js 风格的 `proxy.ts` 不提供 Astro 中间件证据。
- **输入：**已识别的 `context.request`、`context.url.searchParams` 及解构请求参数。
- **边界：**不将组件页面、没有端点导出的脚本推断为请求处理函数。非约定入口的中间件辅助文件不证明全局保护。

测试：[端点区分及中间件](https://github.com/Tasomei/canship/blob/main/test/frameworks.test.ts)、[请求读取](https://github.com/Tasomei/canship/blob/main/test/injection.test.ts)。

## Express

- **入口：**导入或 require 的 Express app/router、方法注册、`.route()` 链、挂载的路由及可解析控制器函数。
- **鉴权：**函数内检查、拒绝请求的中间件及支持的鉴权库调用，结合注册顺序和挂载范围。会话初始化、`passport.initialize()` 和安全响应头中间件本身不等于鉴权。
- **输入：**已识别处理函数中的 `req.query`、`req.body`、`req.params`、请求头和 Cookie。
- **边界：**缺少框架来源证据的同名方法不作为路由。路由之后注册或属于其他实例的中间件不能保护该路由。跨文件控制器及委托写入使用有界的项目解析。

测试：[路由、中间件及输入](https://github.com/Tasomei/canship/blob/main/test/express.test.ts)、[委托写入](https://github.com/Tasomei/canship/blob/main/test/delegated-writes.test.ts)、[条件注册](https://github.com/Tasomei/canship/blob/main/test/registration-context.test.ts)。

## Hono

- **入口：**Hono 方法路由、构造器/方法链、字面量 `basePath()`、`route()` 子应用及支持的 OpenAPI 注册。
- **鉴权：**处理函数或中间件的拒绝逻辑，以及支持的 `hono/jwt`、`hono/jwk`、`hono/bearer-auth`、`hono/basic-auth` 调用；证据限定于实例和匹配路径。
- **输入：**`c.req.query()`、`c.req.param()`、请求体/请求头读取及相关写法。`c.req.valid()` 仍以待复核置信度追踪，不假定 Schema 校验消除了全部风险。
- **边界：**OpenAPI 的 `security` 声明及校验回调不等于鉴权。`openapiRoutes()` 支持静态数组、展开项和可解析处理函数；仅字面量 `addRoute: false` 禁用条目。无法解析的批量条目标记路由分析不完整。

测试：[路由、鉴权及输入](https://github.com/Tasomei/canship/blob/main/test/hono.test.ts)、[OpenAPI 配置](https://github.com/Tasomei/canship/blob/main/test/hono-openapi.test.ts)、[OpenAPI 批量入口](https://github.com/Tasomei/canship/blob/main/test/hono-openapi-batch.test.ts)。

## Fastify

- **入口：**简写与 `route()` 声明、可解析的 `register()` 插件/前缀，以及已识别的 `@fastify/autoload` 目录约定。
- **鉴权：**拒绝请求的 hook、支持的装饰器及鉴权插件组合，限定于已识别的实例/插件作用域。父级、子级和兄弟实例的证据不能混用。
- **输入：**已识别处理函数中的 `request.query`、`request.body`、参数及支持的请求成员。
- **边界：**不求值任意插件执行和动态装饰器。局部插件/控制器解析及委托写入均有边界；未解析的鉴权证据不足以隐藏结果。

测试：[插件、hook、兄弟实例及输入](https://github.com/Tasomei/canship/blob/main/test/fastify.test.ts)、[鉴权组合](https://github.com/Tasomei/canship/blob/main/test/auth-chains.test.ts)、[条件注册](https://github.com/Tasomei/canship/blob/main/test/registration-context.test.ts)。

## 解析与排除范围

项目路由工厂支持返回新实例的同步无参调用。可跟进静态导入/重导出、部分路径映射及显式关联的工作区包；不推断配置继承、歧义条件导出、异步工厂、共享实例或任意包装链。识别字面量分支和简单短路，不按部署环境求值。

详见[入口解析](./reference-zh-CN.md#服务端入口)和[资源上限](./reference-zh-CN.md#隐私与限制)。测试覆盖[工厂](https://github.com/Tasomei/canship/blob/main/test/router-factories.test.ts)、[模块映射](https://github.com/Tasomei/canship/blob/main/test/factory-modules.test.ts)及[注册上限](https://github.com/Tasomei/canship/blob/main/test/registration-context-unit.test.ts)。

Vite、CRA、Expo、Gatsby、Vue CLI 的公开前缀参与内容层面的暴露检查，不代表具备专用服务端路由支持。未支持的框架语法、登录之外的授权、框架运行行为及部署设置不在本清单的认证范围内。
