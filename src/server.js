/**
 * OEM OIDC simulator: minimal discovery/JWKS + EdDSA (Ed25519) JWTs.
 * Contract: OEM OIDC Simulator (Applivery); see tmv-proposal.md §3 where applicable.
 */
import express from 'express'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { generateKeyPair, exportJWK, SignJWT } from 'jose'
import { randomUUID } from 'node:crypto'

const __dirname = dirname(fileURLToPath(import.meta.url))

const PORT = Number(process.env.PORT ?? 3847)

/** Audience for Applivery POST /admin/organizations/oem-bootstrap (value provided by Applivery). */
const OEM_PLATFORM_SERVICE_ACCOUNT_ID = process.env.OEM_PLATFORM_SERVICE_ACCOUNT_ID ?? ''

const MOCK_PUBLIC_URL = (process.env.MOCK_PUBLIC_URL ?? '').replace(/\/$/, '')

/** Max token TTL per contract (seconds). */
const MAX_TOKEN_TTL_SEC = 300

/** Default kid for bootstrap JWT signing (workspace key in tenant JWKS). */
const BOOTSTRAP_TENANT_KID =
  process.env.OEM_BOOTSTRAP_TENANT_KID ?? 'tmv-tenant-workspace-2026-04'

/**
 * @typedef {{ privateKey: CryptoKey, publicKey: CryptoKey, kid: string, companyId: string }} CustomerKey
 * @typedef {{ privateKey: CryptoKey, publicKey: CryptoKey, kid: string, scope: string, aud: string }} TenantScopeKey
 */

/** @type {Map<string, CustomerKey[]>} */
const customerKeys = new Map()

/** @type {Map<string, TenantScopeKey>} */
const tenantKeysByKid = new Map()

const DEFAULT_AUD_CUSTOMER = 'applivery'

const TENANT_SCOPE_DEFS = [
  {
    kid: 'tmv-tenant-workspace-2026-04',
    scope: 'workspace:manage',
    aud: 'sa_workspace_manage',
  },
  {
    kid: 'tmv-tenant-billing-2026-04',
    scope: 'billing:manage',
    aud: 'sa_billing_manage',
  },
  {
    kid: 'tmv-tenant-reporting-2026-04',
    scope: 'reporting:read',
    aud: 'sa_reporting_read',
  },
  {
    kid: 'tmv-tenant-audit-2026-04',
    scope: 'audit:read',
    aud: 'sa_audit_read',
  },
]

function clampTtl(seconds) {
  const n = Number(seconds)
  const fallback = MAX_TOKEN_TTL_SEC
  const v = Number.isFinite(n) && n > 0 ? Math.floor(n) : fallback
  return Math.min(v, MAX_TOKEN_TTL_SEC)
}

async function keyPairToJwksEntry(publicKey, kid) {
  const jwk = await exportJWK(publicKey)
  return {
    ...jwk,
    kid,
    alg: 'EdDSA',
    use: 'sig',
  }
}

function publicBaseUrl(req) {
  if (MOCK_PUBLIC_URL) return MOCK_PUBLIC_URL
  const host = req.get('host') ?? `localhost:${PORT}`
  const proto = req.get('x-forwarded-proto') ?? req.protocol ?? 'http'
  return `${proto}://${host}`
}

async function createEd25519Pair() {
  return generateKeyPair('EdDSA', { crv: 'Ed25519', extractable: true })
}

async function initTenantKeys() {
  for (const def of TENANT_SCOPE_DEFS) {
    const { privateKey, publicKey } = await createEd25519Pair()
    tenantKeysByKid.set(def.kid, {
      privateKey,
      publicKey,
      kid: def.kid,
      scope: def.scope,
      aud: def.aud,
    })
  }
}

const app = express()
app.use(express.json())

const startedAt = Date.now()

app.get('/', (_req, res) => {
  res.json({
    service: 'oem-oidc-simulator',
    ok: true,
    openapi: '/openapi.yaml',
    startedAt: new Date(startedAt).toISOString(),
    maxTokenTtlSeconds: MAX_TOKEN_TTL_SEC,
    bootstrapTenantKid: BOOTSTRAP_TENANT_KID,
    platformServiceAccountIdConfigured: Boolean(OEM_PLATFORM_SERVICE_ACCOUNT_ID),
    hint:
      !OEM_PLATFORM_SERVICE_ACCOUNT_ID &&
      'Set OEM_PLATFORM_SERVICE_ACCOUNT_ID to the value from Applivery for /api/tokens/bootstrap',
  })
})

/** OpenAPI 3 — file at repo root `openapi.yaml` */
app.get('/openapi.yaml', (_req, res) => {
  const specPath = join(__dirname, '..', 'openapi.yaml')
  res.type('application/yaml').send(readFileSync(specPath, 'utf8'))
})

/** Register workspace issuer keys; iss = …/oem/{companyId} (must match bootstrap workspaceIssuer). */
app.post('/api/customers/:companyId/keys', async (req, res) => {
  const { companyId } = req.params
  if (!companyId?.length) {
    res.status(400).json({ error: 'companyId is required' })
    return
  }
  const { privateKey, publicKey } = await createEd25519Pair()
  const kid = `tmv-${companyId}-${Date.now()}`
  const entry = { privateKey, publicKey, kid, companyId }
  const list = customerKeys.get(companyId) ?? []
  list.push(entry)
  customerKeys.set(companyId, list)
  const base = publicBaseUrl(req)
  res.status(201).json({
    companyId,
    kid,
    issuer: `${base}/oem/${encodeURIComponent(companyId)}`,
    jwks_uri: `${base}/oem/${encodeURIComponent(companyId)}/.well-known/jwks.json`,
  })
})

app.get('/api/customers/:companyId', (req, res) => {
  const list = customerKeys.get(req.params.companyId)
  if (!list?.length) {
    res.status(404).json({
      error: 'no keys for this customer; call POST /api/customers/:companyId/keys first',
    })
    return
  }
  const base = publicBaseUrl(req)
  res.json({
    companyId: req.params.companyId,
    issuer: `${base}/oem/${encodeURIComponent(req.params.companyId)}`,
    keys: list.map((k) => ({ kid: k.kid })),
  })
})

/** Root / tenant issuer — minimal discovery (OEM OIDC Simulator contract). */
app.get('/oem/.well-known/openid-configuration', (req, res) => {
  const base = publicBaseUrl(req)
  const issuer = `${base}/oem`
  res.json({
    issuer,
    jwks_uri: `${issuer}/.well-known/jwks.json`,
  })
})

app.get('/oem/.well-known/jwks.json', async (_req, res) => {
  const keys = await Promise.all(
    [...tenantKeysByKid.values()].map((k) => keyPairToJwksEntry(k.publicKey, k.kid))
  )
  res.json({ keys })
})

/** Per-workspace/company issuer — minimal discovery. */
app.get('/oem/:companyId/.well-known/openid-configuration', (req, res) => {
  const { companyId } = req.params
  const base = publicBaseUrl(req)
  const issuer = `${base}/oem/${encodeURIComponent(companyId)}`
  res.json({
    issuer,
    jwks_uri: `${issuer}/.well-known/jwks.json`,
  })
})

app.get('/oem/:companyId/.well-known/jwks.json', async (req, res) => {
  const list = customerKeys.get(req.params.companyId)
  if (!list?.length) {
    res.status(404).json({
      error: 'empty JWKS; register keys via POST /api/customers/:companyId/keys',
    })
    return
  }
  const keys = await Promise.all(list.map((k) => keyPairToJwksEntry(k.publicKey, k.kid)))
  res.json({ keys })
})

/**
 * Workspace JWT (operator / owner) for Applivery /v1 calls with this issuer.
 * Claims: iss, aud, sub, wid, uid, iat, exp, jti — contract + validation rules.
 */
app.post('/api/tokens/customer', async (req, res) => {
  const {
    companyId,
    wid,
    uid,
    sub,
    aud = DEFAULT_AUD_CUSTOMER,
    expiresInSec = MAX_TOKEN_TTL_SEC,
    kid: kidRequested,
  } = req.body ?? {}

  if (!companyId || !wid || !uid) {
    res.status(400).json({ error: 'companyId, wid, and uid are required' })
    return
  }

  const list = customerKeys.get(companyId)
  if (!list?.length) {
    res.status(404).json({ error: `no keys registered for companyId=${companyId}` })
    return
  }

  const entry = kidRequested
    ? list.find((k) => k.kid === kidRequested)
    : list[list.length - 1]

  if (!entry) {
    res.status(400).json({ error: `kid not found: ${kidRequested}` })
    return
  }

  const ttl = clampTtl(expiresInSec)
  const base = publicBaseUrl(req)
  const iss = `${base}/oem/${encodeURIComponent(companyId)}`

  const jwt = await new SignJWT({
    wid,
    uid,
    jti: randomUUID(),
  })
    .setProtectedHeader({ alg: 'EdDSA', kid: entry.kid, typ: 'JWT' })
    .setIssuer(iss)
    .setAudience(aud)
    .setSubject(sub ?? uid)
    .setIssuedAt()
    .setExpirationTime(`${ttl} sec`)
    .sign(entry.privateKey)

  res.json({
    token_type: 'Bearer',
    access_token: jwt,
    expires_in: ttl,
    header: { alg: 'EdDSA', kid: entry.kid, typ: 'JWT' },
    expected_issuer: iss,
    note:
      'Applivery expects wid to match the organizationId in the URL and iss to match the stored workspaceIssuer.',
  })
})

/**
 * Bootstrap JWT (Applivery POST /admin/organizations/oem-bootstrap).
 * Strict claims: iss, aud, sub, iat, exp, jti — no scope.
 */
app.post('/api/tokens/bootstrap', async (req, res) => {
  const aud = req.body?.aud ?? OEM_PLATFORM_SERVICE_ACCOUNT_ID
  if (!aud) {
    res.status(400).json({
      error:
        'aud is required: set OEM_PLATFORM_SERVICE_ACCOUNT_ID or send {"aud":"<platformServiceAccountId>"}',
    })
    return
  }

  const kidRequested = req.body?.kid ?? BOOTSTRAP_TENANT_KID
  const entry = tenantKeysByKid.get(kidRequested)
  if (!entry) {
    res.status(404).json({
      error: `tenant kid not found: ${kidRequested}`,
      availableKids: [...tenantKeysByKid.keys()],
    })
    return
  }

  const sub = req.body?.sub ?? 'tmv-uem-simulator-admin'
  const ttl = clampTtl(req.body?.expiresInSec)

  const base = publicBaseUrl(req)
  const iss = `${base}/oem`

  const jwt = await new SignJWT({})
    .setProtectedHeader({ alg: 'EdDSA', kid: entry.kid, typ: 'JWT' })
    .setIssuer(iss)
    .setAudience(aud)
    .setSubject(sub)
    .setJti(randomUUID())
    .setIssuedAt()
    .setExpirationTime(`${ttl} sec`)
    .sign(entry.privateKey)

  res.json({
    token_type: 'Bearer',
    access_token: jwt,
    expires_in: ttl,
    header: { alg: 'EdDSA', kid: entry.kid, typ: 'JWT' },
    issuer: iss,
    aud,
  })
})

/**
 * Tenant JWT with scope claim (dev-only / illustrative TMV §3.5).
 * For bootstrap use POST /api/tokens/bootstrap.
 */
app.post('/api/tokens/tenant', async (req, res) => {
  const { kid, sub = 'tmv-uem-tenant-ops', expiresInSec = MAX_TOKEN_TTL_SEC } = req.body ?? {}
  if (!kid) {
    res.status(400).json({ error: 'kid is required' })
    return
  }
  const entry = tenantKeysByKid.get(kid)
  if (!entry) {
    res.status(404).json({
      error: 'tenant kid not found',
      availableKids: [...tenantKeysByKid.keys()],
    })
    return
  }

  const ttl = clampTtl(expiresInSec)
  const base = publicBaseUrl(req)
  const iss = `${base}/oem`

  const jwt = await new SignJWT({
    scope: entry.scope,
    jti: randomUUID(),
  })
    .setProtectedHeader({ alg: 'EdDSA', kid: entry.kid, typ: 'JWT' })
    .setIssuer(iss)
    .setAudience(entry.aud)
    .setSubject(sub)
    .setIssuedAt()
    .setExpirationTime(`${ttl} sec`)
    .sign(entry.privateKey)

  res.json({
    token_type: 'Bearer',
    access_token: jwt,
    expires_in: ttl,
    scope: entry.scope,
    aud: entry.aud,
    note:
      'Includes scope claim (not part of bootstrap contract); use POST /api/tokens/bootstrap for oem-bootstrap',
  })
})

app.use((_req, res) => {
  res.status(404).json({ error: 'route not found' })
})

await initTenantKeys()

app.listen(PORT, () => {
  console.log(`OEM OIDC simulator listening at http://localhost:${PORT}`)
  console.log(
    'MOCK_PUBLIC_URL: set when the public base URL differs (e.g. reverse proxy / TLS termination)',
  )
  console.log(
    'OEM_PLATFORM_SERVICE_ACCOUNT_ID: bootstrap JWT aud (required unless you pass aud in the request body)',
  )
})
