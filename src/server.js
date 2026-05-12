/**
 * Mock OIDC / JWKS + emisor de JWT (EdDSA / Ed25519) alineado con tmv-proposal.md §3.
 * Almacenamiento en memoria; URLs públicas derivadas del Host de la petición.
 */
import express from 'express'
import { generateKeyPair, exportJWK, SignJWT } from 'jose'
import { randomUUID } from 'node:crypto'

const PORT = Number(process.env.PORT ?? 3847)
/** Si se define, sustituye protocolo/host para iss / jwks_uri en JSON (útil detrás de proxy). */
const MOCK_PUBLIC_URL = (
  process.env.MOCK_PUBLIC_URL ?? ''
).replace(/\/$/, '')

/**
 * @typedef {{ privateKey: CryptoKey, publicKey: CryptoKey, kid: string, companyId: string }} CustomerKey
 * @typedef {{ privateKey: CryptoKey, publicKey: CryptoKey, kid: string, scope: string, aud: string }} TenantScopeKey
 */

/** @type {Map<string, CustomerKey[]>} */
const customerKeys = new Map()

/** kid -> TenantScopeKey */
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

/**
 * Genera un par Ed25519 (EdDSA) — algoritmo recomendado en la propuesta §3.3 / §3.7.
 */
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
  res.json({ service: 'tmv-mock-auth', ok: true, startedAt: new Date(startedAt).toISOString() })
})

/** Registra un cliente (company) y genera un nuevo kid (rotación = llamar de nuevo con mismo companyId añade clave). */
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

/** Lista claves públicas por company (sin materiales privados). */
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

/** Tenant-level OIDC discovery — §3.5 (antes de /oem/:companyId para no capturar ".well-known" como id). */
app.get('/oem/.well-known/openid-configuration', (req, res) => {
  const base = publicBaseUrl(req)
  const issuer = `${base}/oem`
  res.json({
    issuer,
    jwks_uri: `${issuer}/.well-known/jwks.json`,
    id_token_signing_alg_values_supported: ['EdDSA'],
    subject_types_supported: ['public'],
    response_types_supported: ['id_token'],
  })
})

/** Tenant-level JWKS (todos los scopes ilustrativos) */
app.get('/oem/.well-known/jwks.json', async (_req, res) => {
  const keys = await Promise.all(
    [...tenantKeysByKid.values()].map((k) => keyPairToJwksEntry(k.publicKey, k.kid))
  )
  res.json({ keys })
})

/** Per-customer OIDC discovery — §3.4 */
app.get('/oem/:companyId/.well-known/openid-configuration', (req, res) => {
  const { companyId } = req.params
  const base = publicBaseUrl(req)
  const issuer = `${base}/oem/${encodeURIComponent(companyId)}`
  res.json({
    issuer,
    jwks_uri: `${issuer}/.well-known/jwks.json`,
    id_token_signing_alg_values_supported: ['EdDSA'],
    subject_types_supported: ['public'],
    response_types_supported: ['id_token'],
  })
})

/** Per-customer JWKS */
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
 * JWT por cliente (workspace) — §3.3
 * Body: { wid, uid, sub?, aud?, expiresInSec?, kid? }
 * Si kid se omite, usa la última clave generada para ese companyId.
 */
app.post('/api/tokens/customer', async (req, res) => {
  const {
    companyId,
    wid,
    uid,
    sub,
    aud = DEFAULT_AUD_CUSTOMER,
    expiresInSec = 300,
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

  let entry = kidRequested
    ? list.find((k) => k.kid === kidRequested)
    : list[list.length - 1]

  if (!entry) {
    res.status(400).json({ error: `kid no encontrado: ${kidRequested}` })
    return
  }

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
    .setExpirationTime(`${Math.min(Math.max(Number(expiresInSec) || 300, 60), 3600)} sec`)
    .sign(entry.privateKey)

  res.json({
    token_type: 'Bearer',
    access_token: jwt,
    expires_in: Math.min(Math.max(Number(expiresInSec) || 300, 60), 3600),
    header: { alg: 'EdDSA', kid: entry.kid, typ: 'JWT' },
  })
})

/**
 * JWT tenant-admin — §3.5
 * Body: { kid, sub?, expiresInSec? }  (aud y scope salen del registro interno para ese kid)
 */
app.post('/api/tokens/tenant', async (req, res) => {
  const { kid, sub = 'tmv-uem-tenant-ops', expiresInSec = 300 } = req.body ?? {}
  if (!kid) {
    res.status(400).json({ error: 'kid es obligatorio (uno de TENANT_SCOPE_DEFS)' })
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
    .setExpirationTime(`${Math.min(Math.max(Number(expiresInSec) || 300, 60), 3600)} sec`)
    .sign(entry.privateKey)

  res.json({
    token_type: 'Bearer',
    access_token: jwt,
    expires_in: Math.min(Math.max(Number(expiresInSec) || 300, 60), 3600),
    scope: entry.scope,
    aud: entry.aud,
  })
})

app.use((_req, res) => {
  res.status(404).json({ error: 'ruta no encontrada' })
})

await initTenantKeys()

app.listen(PORT, () => {
  console.log(`Mock auth escuchando en http://localhost:${PORT}`)
  console.log(`Definir MOCK_PUBLIC_URL si el emisor debe mostrar otra base URL (proxy TLS).`)
})
