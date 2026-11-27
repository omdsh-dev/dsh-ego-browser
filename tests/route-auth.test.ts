import { describe, it, expect } from 'vitest'
import { registerAuthenticatedRoute } from '../src/route-auth.ts'
import type { RegisterRouteOptions } from '../src/types.ts'

type Handler = NonNullable<RegisterRouteOptions['handler']>

/**
 * Route auth across host generations (issue #115).
 *
 * Newer DSH web servers authorize a registered route before dispatch
 * (`auth: 'required'`, the host default) and call the handler with the admitted
 * peer. Desktop requests are admitted that way and carry no web cookie, so the
 * legacy cookie fence must not run for them. Older hosts have no route auth and
 * call `(req, res)` only, so the cookie fence must stay.
 */
function bench() {
  let registered: RegisterRouteOptions | undefined
  const server = {
    register(route: RegisterRouteOptions) {
      registered = route
      return () => {}
    },
  }
  const rejected: unknown[] = []
  let handled = 0
  const route: RegisterRouteOptions = {
    kind: 'exact',
    path: '/api/ego/spaces',
    handler: () => { handled += 1 },
  }
  registerAuthenticatedRoute(server as never, route, (res) => { rejected.push(res) })
  if (!registered) throw new Error('route not registered')
  return {
    get route() { return registered as RegisterRouteOptions },
    rejected,
    handled: () => handled,
  }
}

const req = (cookie?: string) => ({ headers: cookie === undefined ? {} : { cookie } })

async function invoke(route: RegisterRouteOptions, request: unknown, peer?: unknown) {
  const handler = route.handler as Handler
  await handler(request, {}, peer)
}

describe('registerAuthenticatedRoute — host generations', () => {
  it('asks the host for route auth explicitly', () => {
    const b = bench()
    expect(b.route.auth).toBe('required')
  })

  it('lets a host-admitted request through without a legacy cookie (Desktop)', async () => {
    const b = bench()
    await invoke(b.route, req(), { peerId: 'desktop' })
    expect(b.handled()).toBe(1)
    expect(b.rejected).toHaveLength(0)
  })

  it('keeps the cookie fence on legacy hosts (no peer)', async () => {
    const b = bench()
    await invoke(b.route, req())
    expect(b.handled()).toBe(0)
    expect(b.rejected).toHaveLength(1)
  })

  it('accepts a DSH auth cookie on legacy hosts', async () => {
    const b = bench()
    await invoke(b.route, req('dsh-auth-abc=1'))
    expect(b.handled()).toBe(1)
    expect(b.rejected).toHaveLength(0)
  })

  it('stays fail-closed when a host admits without a peer', async () => {
    const b = bench()
    await invoke(b.route, req())
    expect(b.handled()).toBe(0)
    expect(b.rejected).toHaveLength(1)
  })
})
