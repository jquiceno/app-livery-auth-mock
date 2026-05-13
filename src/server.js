/**
 * Simulador OEM OIDC: discovery/JWKS mínimos + JWT EdDSA (Ed25519).
 * Contrato: OEM OIDC Simulator (Applivery) + tmv-proposal §3 donde aplica.
 */
import express from 'express'
import { generateKeyPair, exportJWK, SignJWT } from 'jose'
import { randomUUID } from 'node:crypto'

const PORT = Number(process.env.PORT ?? 3847)

/** Audiencia para POST /admin/organizations/oem-bootstrap (valor que entrega Applivery). */
const OEM_PLATFORM_SERVICE_ACCOUNT_ID = process.env.OEM_PLATFORM_SERVICE_ACCOUNT_ID ?? ''

const MOCK_PUBLIC_URL = (process.env.MOCK_PUBLIC_URL ?? '').replace(/\/$/, '')

/** TTL máximo del contrato (segundos). */
const MAX_TOKEN_TTL_SEC = 300

/** kid por defecto para firmar el JWT de bootstrap (clave workspace en JWKS tenant). */
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
    startedAt: new Date(startedAt).toISOString(),
    maxTokenTtlSeconds: MAX_TOKEN_TTL_SEC,
    bootstrapTenantKid: BOOTSTRAP_TENANT_KID,
    platformServiceAccountIdConfigured: Boolean(OEM_PLATFORM_SERVICE_ACCOUNT_ID),
    hint:
      !OEM_PLATFORM_SERVICE_ACCOUNT_ID &&
      'Definir OEM_PLATFORM_SERVICE_ACCOUNT_ID con el valor de Applivery para /api/tokens/bootstrap',
  })
})

/** Registra claves del emisor workspace: iss = …/oem/{companyId} (debe coincidir con workspaceIssuer del bootstrap). */
app.post('/api/customers/:companyId/keys', async (req, res) => {
  const { companyId } = req.params
  if (!companyId?.length) {
    res.status(400).json({ error: 'companyId requerido' })
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
    res.status(404).json({ error: 'customer sin claves; POST /api/customers/:id/keys primero' })
    return
  }
  const base = publicBaseUrl(req)
  res.json({
    companyId: req.params.companyId,
    issuer: `${base}/oem/${encodeURIComponent(req.params.companyId)}`,
    keys: list.map((k) => ({ kid: k.kid })),
  })
})

/** Emisor raíz / tenant — discovery mínimo (contrato OEM OIDC Simulator). */
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

/** Emisor por workspace/company — discovery mínimo. */
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
    res.status(404).json({ error: 'JWKS vacío: registrar claves con POST /api/customers/:companyId/keys' })
    return
  }
  const keys = await Promise.all(list.map((k) => keyPairToJwksEntry(k.publicKey, k.kid)))
  res.json({ keys })
})

/**
 * JWT workspace (operador / owner) para llamadas Applivery /v1 con ese issuer.
 * Claims: iss, aud, sub, wid, uid, iat, exp, jti — contrato + reglas importante.
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
    res.status(400).json({ error: 'companyId, wid y uid son obligatorios' })
    return
  }

  const list = customerKeys.get(companyId)
  if (!list?.length) {
    res.status(404).json({ error: `sin claves para companyId=${companyId}` })
    return
  }

  const entry = kidRequested
    ? list.find((k) => k.kid === kidRequested)
    : list[list.length - 1]

  if (!entry) {
    res.status(400).json({ error: `kid no encontrado: ${kidRequested}` })
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
      'En Applivery, wid debe coincidir con el organizationId de la URL; iss con workspaceIssuer guardado.',
  })
})

/**
 * JWT de bootstrap (POST /admin/organizations/oem-bootstrap en Applivery).
 * Claims estrictos: iss, aud, sub, iat, exp, jti — sin scope.
 */
app.post('/api/tokens/bootstrap', async (req, res) => {
  const aud = req.body?.aud ?? OEM_PLATFORM_SERVICE_ACCOUNT_ID
  if (!aud) {
    res.status(400).json({
      error:
        'aud obligatorio: configura OEM_PLATFORM_SERVICE_ACCOUNT_ID o envía {"aud":"<platformServiceAccountId>"}',
    })
    return
  }

  const kidRequested = req.body?.kid ?? BOOTSTRAP_TENANT_KID
  const entry = tenantKeysByKid.get(kidRequested)
  if (!entry) {
    res.status(404).json({
      error: `kid tenant no encontrado: ${kidRequested}`,
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
 * JWT tenant con claim scope (solo desarrollo / propuesta TMV §3.5 ilustrativa).
 * Para bootstrap usa /api/tokens/bootstrap.
 */
app.post('/api/tokens/tenant', async (req, res) => {
  const { kid, sub = 'tmv-uem-tenant-ops', expiresInSec = MAX_TOKEN_TTL_SEC } = req.body ?? {}
  if (!kid) {
    res.status(400).json({ error: 'kid es obligatorio' })
    return
  }
  const entry = tenantKeysByKid.get(kid)
  if (!entry) {
    res.status(404).json({
      error: 'kid de tenant no encontrado',
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
    note: 'Incluye claim scope (no forma parte del contrato bootstrap); usar /api/tokens/bootstrap para oem-bootstrap',
  })
})

app.use((_req, res) => {
  res.status(404).json({ error: 'ruta no encontrada' })
})

await initTenantKeys()

app.listen(PORT, () => {
  console.log(`OEM OIDC simulator http://localhost:${PORT}`)
  console.log(`MOCK_PUBLIC_URL: URL pública si hay proxy/TLS`)
  console.log(`OEM_PLATFORM_SERVICE_ACCOUNT_ID: aud JWT bootstrap (requerido salvo pasar aud en body)`)
})
