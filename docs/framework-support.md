# Framework coverage

[Reference](./reference.md) · [简体中文](./framework-support-zh-CN.md)

This describes the development branch's static recognition, not framework-version certification. No framework, dependency or application code is executed. The examples below are representative, not an exhaustive SDK list.

## Shared boundaries

- Entry recognition, authentication evidence and request-input tracking are separate checks. A recognised entry does not mean every operation in it is understood. Unrecognised syntax can remain undiscovered even when no analysis limit is reported.
- Authentication evidence must cover the relevant operation and reject unauthenticated requests. Request-supplied identity, middleware names, schema validation and OpenAPI security metadata alone are not proof. Indirect or unresolved evidence can retain a `likely` finding rather than suppress it.
- Input tracking follows bounded assignments, destructuring, string construction and resolvable passthrough helpers. It feeds SQL/shell injection, outbound-request and redirect checks; it is not general data-flow or business-authorisation analysis.
- Project-function database writes are followed two calls deep for Express, Hono and Fastify. File-convention routes do not use this delegated-write expansion. Auth-helper and input-helper resolution have separate bounds.
- Credentials, public environment exposure, Firebase/Supabase configuration and CORS retain their own file/content conditions; the route list does not disable those checks in other projects.

Tests: [identity enforcement](https://github.com/Tasomei/canship/blob/main/test/claimed-identity.test.ts), [delegated-write boundaries](https://github.com/Tasomei/canship/blob/main/test/delegated-writes.test.ts), [input-flow regressions](https://github.com/Tasomei/canship/blob/main/test/request-input-regressions.test.ts).

## Next.js

- **Entries:** `pages/api/**`; App Router `route.*`, including outside `app/api` when HTTP exports identify the handler; exported or inline Server Functions marked by `use server`. App Router paths omit route groups and exclude private route folders.
- **Auth:** recognised handler-local rejecting checks; resolved Next.js middleware/proxy scope may protect covered handlers. Server Functions need their own checks; middleware is not accepted as their protection.
- **Inputs:** `req.query`, `req.body`, `request.json()`, `request.nextUrl.searchParams` and Server Function arguments. An unexported helper without its own directive, or a directive inside an ordinary string, does not create a Server Function.
- **Cross-file limit:** resolvable clients/auth/input helpers can supply evidence; database writes hidden in called services are not expanded as Node-router delegated writes.

Tests: [entries and Server Functions](https://github.com/Tasomei/canship/blob/main/test/frameworks.test.ts), [middleware boundaries](https://github.com/Tasomei/canship/blob/main/test/middleware-boundaries.test.ts), [request inputs](https://github.com/Tasomei/canship/blob/main/test/injection.test.ts).

## SvelteKit

- **Entries:** `src/routes/**/+server.*` and `+page.server.*` files exporting an `actions` object.
- **Auth:** recognised rejecting checks on trusted identity, including `locals.user`. Auth-like logic in `hooks.server.*` can lower confidence; it does not prove coverage of every endpoint.
- **Inputs:** destructured `request`, `url` and `params`, including `request.formData()` and `url.searchParams`.
- **Limits:** page `load` and remote functions are outside route analysis. Recognised `locals.supabase` clients may be left to database policies; absence of an API-auth finding does not verify RLS.

Tests: [endpoints, actions and load exclusions](https://github.com/Tasomei/canship/blob/main/test/frameworks.test.ts), [request inputs](https://github.com/Tasomei/canship/blob/main/test/injection.test.ts).

## Nuxt / Nitro

- **Entries:** `server/api/**` and `server/routes/**` with a recognised h3 handler, such as `defineEventHandler`. The directory name alone is insufficient; method suffixes are removed from displayed URLs.
- **Auth:** recognised rejecting local checks, including supported `requireUserSession` calls. Auth-like logic under `server/middleware` can lower confidence without suppressing the finding.
- **Inputs:** supported event readers such as `getQuery(event)`, `readBody(event)` and `getRouterParam(event)`.
- **Limits:** arbitrary auto-import behaviour is not executed. A tRPC router merely located under `server/api` is not treated as a Nuxt endpoint. Recognised `serverSupabaseClient` use is distinct from an admin client and does not itself verify RLS.

Tests: [route/auth positive and negative cases](https://github.com/Tasomei/canship/blob/main/test/frameworks.test.ts), [event readers](https://github.com/Tasomei/canship/blob/main/test/injection.test.ts).

## Remix / React Router

- **Entries:** `app/routes/**` modules exporting `loader` or `action`, including recognised flat and folder conventions.
- **Auth:** recognised rejecting checks in the handler or resolved helpers. A component-only module without those exports is not an API entry.
- **Inputs:** handler `request` and destructured `params`, including query and body readers.
- **Limits:** custom runtime route configuration is not inferred from the framework name. Supported `~/` resolution supplies project evidence, not arbitrary package execution.

Tests: [route modules and exclusions](https://github.com/Tasomei/canship/blob/main/test/frameworks.test.ts), [request readers](https://github.com/Tasomei/canship/blob/main/test/injection.test.ts).

## Astro

- **Entries:** scripts under `src/pages/**` with recognised HTTP-method exports and no default export, including endpoints outside `src/pages/api`.
- **Auth:** recognised local checks, including trusted `locals.user`, or covered Astro middleware. A Next.js-style `proxy.ts` is not Astro middleware evidence.
- **Inputs:** recognised `context.request`, `context.url.searchParams` and destructured request parameters.
- **Limits:** component pages and scripts without endpoint exports are not inferred as request handlers. Middleware helpers that are not the recognised entry point do not prove global protection.

Tests: [endpoint discrimination and middleware](https://github.com/Tasomei/canship/blob/main/test/frameworks.test.ts), [request readers](https://github.com/Tasomei/canship/blob/main/test/injection.test.ts).

## Express

- **Entries:** imported/required Express apps and routers, method registrations, `.route()` chains, mounted routers and resolvable controller functions.
- **Auth:** handler checks, rejecting middleware and supported auth-library calls, with registration order and mount coverage. Session setup, `passport.initialize()` and security-header middleware are not authentication by themselves.
- **Inputs:** `req.query`, `req.body`, `req.params`, headers and cookies in recognised handlers.
- **Limits:** lookalike methods without framework evidence are not routes. Middleware attached after a route or to another instance cannot protect it. Cross-file controllers and delegated writes use bounded project resolution.

Tests: [routes, middleware and inputs](https://github.com/Tasomei/canship/blob/main/test/express.test.ts), [delegated writes](https://github.com/Tasomei/canship/blob/main/test/delegated-writes.test.ts), [conditional registration](https://github.com/Tasomei/canship/blob/main/test/registration-context.test.ts).

## Hono

- **Entries:** Hono method routes, constructor/method chains, literal `basePath()`, `route()` sub-apps and supported OpenAPI registrations.
- **Auth:** rejecting handler/middleware logic and supported `hono/jwt`, `hono/jwk`, `hono/bearer-auth` and `hono/basic-auth` calls, scoped to the instance and matching paths.
- **Inputs:** `c.req.query()`, `c.req.param()`, body/header readers and related forms. `c.req.valid()` remains tracked at review confidence; schema validation is not assumed to remove all risk.
- **Limits:** OpenAPI `security` metadata and validation hooks are not auth. `openapiRoutes()` supports static arrays/spreads and resolvable handlers; only literal `addRoute: false` disables an entry. Unresolved batch entries mark route analysis incomplete.

Tests: [routes, auth and inputs](https://github.com/Tasomei/canship/blob/main/test/hono.test.ts), [OpenAPI configuration](https://github.com/Tasomei/canship/blob/main/test/hono-openapi.test.ts), [OpenAPI batches](https://github.com/Tasomei/canship/blob/main/test/hono-openapi-batch.test.ts).

## Fastify

- **Entries:** shorthand and `route()` declarations, resolvable `register()` plugins/prefixes, and recognised `@fastify/autoload` layouts.
- **Auth:** rejecting hooks, supported decorators and auth-plugin composition, within the recognised instance/plugin scope. Parent, child and sibling evidence is not interchangeable.
- **Inputs:** `request.query`, `request.body`, parameters and supported request members in recognised handlers.
- **Limits:** arbitrary plugin execution and dynamic decoration are not evaluated. Local plugin/controller resolution and delegated writes are bounded; unresolved auth evidence is not sufficient to hide a finding.

Tests: [plugins, hooks, siblings and inputs](https://github.com/Tasomei/canship/blob/main/test/fastify.test.ts), [auth composition](https://github.com/Tasomei/canship/blob/main/test/auth-chains.test.ts), [conditional registration](https://github.com/Tasomei/canship/blob/main/test/registration-context.test.ts).

## Resolution and exclusions

Project router factories support synchronous, zero-argument calls returning fresh instances. Static imports/re-exports, selected path mappings and explicitly linked workspace packages are followed; configuration inheritance, ambiguous conditional exports, async factories, shared instances and arbitrary wrapper chains are not inferred. Literal branches and simple short circuits are recognised, not evaluated against a deployment environment.

See [entry resolution](./reference.md#server-entry-points) and [resource limits](./reference.md#privacy-and-limits). Tests cover [factories](https://github.com/Tasomei/canship/blob/main/test/router-factories.test.ts), [module mappings](https://github.com/Tasomei/canship/blob/main/test/factory-modules.test.ts) and [registration limits](https://github.com/Tasomei/canship/blob/main/test/registration-context-unit.test.ts).

Vite, CRA, Expo, Gatsby and Vue CLI public prefixes participate in content-based exposure checks; this does not imply dedicated server-route support. Unsupported framework syntax, authorisation beyond sign-in, framework runtime behaviour and deployed settings are not certified by this list.
