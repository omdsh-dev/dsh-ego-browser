import type { IncomingMessage, ServerResponse } from 'node:http'
import type { RegisterRouteOptions, WebServerLike } from './types.ts'

/** DSH's shared web-server auth cookie (legacy hosts only). */
const DSH_AUTH_COOKIE_RE = /(?:^|;\s*)dsh-auth-[^=]+=/

/**
 * One admitted peer identity, as newer web servers hand it to route handlers.
 * Only its presence matters here: the host has already authorized the request.
 */
type AdmittedPeer = unknown

/**
 * Register an HTTP route that requires authentication on every host generation.
 *
 * DSH's web server gained per-route authorization (`auth`, defaulting to
 * `required`) in newer releases. On those hosts a request that reaches our
 * handler has ALREADY been authorized and is dispatched with an admitted peer
 * as the third handler argument. Older hosts have no route auth at all and call
 * handlers with just `(req, res)`.
 *
 * So the presence of the peer is the signal, not a private host method:
 *  - peer present  → the host authenticated the request; skip the legacy cookie
 *                    check (Desktop requests carry no web cookie).
 *  - peer absent   → legacy host; require the DSH auth cookie ourselves.
 *
 * This keeps the fence fail-closed on old hosts while letting authenticated
 * Desktop requests through on new ones.
 *
 * @param server - host web server.
 * @param route - route to register.
 * @param reject - writes the 401 response for an unauthenticated legacy request.
 * @returns the disposer removing the route.
 */
export function registerAuthenticatedRoute(
  server: WebServerLike,
  route: RegisterRouteOptions,
  reject: (res: ServerResponse) => void,
): () => void {
  const register = server.register!.bind(server)
  return register({
    ...route,
    // Harmless on hosts that do not know the option; explicit on hosts that do
    // (their default is already `required`).
    auth: 'required',
    handler(req: unknown, res: unknown, peer?: AdmittedPeer) {
      const peerAdmitted = peer !== undefined && peer !== null
      const hasCookie = DSH_AUTH_COOKIE_RE.test(String((req as IncomingMessage).headers.cookie ?? ''))
      if (!peerAdmitted && !hasCookie) {
        reject(res as ServerResponse)
        return
      }
      return route.handler(req, res)
    },
  })
}
