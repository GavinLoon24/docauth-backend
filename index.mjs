import { webcrypto } from 'crypto'
globalThis.crypto = webcrypto

import express from 'express'
import cors from 'cors'
import path from 'path'
import crypto from 'crypto'
import fs from 'fs'
import { fileURLToPath } from 'url'
import { dirname } from 'path'
import base64url from 'base64url'
import multer from 'multer'
import { importJWK, SignJWT } from 'jose'

const __filename = fileURLToPath(import.meta.url)
const __dirname = dirname(__filename)

const app = express()
app.use(cors())
app.use(express.json())
app.use(express.urlencoded({ extended: true }))
app.use(express.static(path.join(__dirname, 'public')))

const upload = multer({ storage: multer.memoryStorage() })

// 🧠 In-memory challenge and document storage
const challenges = new Map()
const documents = new Map()

// ✅ Serve login page
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'did-login.html'))
})

// ✅ Generate new DID + private key
app.get('/generate-did', (req, res) => {
  const keyPair = crypto.generateKeyPairSync('ed25519')
  const privateKey = keyPair.privateKey.export({ format: 'jwk' })
  const publicKey = keyPair.publicKey.export({ format: 'jwk' })
  const did = `did:key:z${crypto.randomBytes(16).toString('hex')}`

  res.json({
    did,
    privateKeyJwk: privateKey,
    publicKeyJwk: publicKey
  })
})

// ✅ Challenge API
app.get('/login-challenge/:did', (req, res) => {
  const { did } = req.params
  const challenge = crypto.randomBytes(32).toString('hex')
  challenges.set(did, challenge)
  console.log(`🟢 Challenge issued for ${did}: ${challenge}`)
  res.json({ challenge })
})

// ✅ Sign challenge using private JWK
app.post('/sign-challenge', async (req, res) => {
  const { did, challenge, privateKeyJwk } = req.body

  if (!did || !challenge || !privateKeyJwk) {
    return res.status(400).json({ error: 'Missing fields' })
  }

  try {
    const privateKey = await importJWK(privateKeyJwk, 'EdDSA')

    const jwt = await new SignJWT({ challenge })
      .setProtectedHeader({ alg: 'EdDSA' })
      .setIssuer(did)
      .setSubject(did)
      .setIssuedAt()
      .sign(privateKey)

    res.json({ jwt })
  } catch (err) {
    console.error('❌ Signing error:', err)
    res.status(500).json({ error: 'Failed to sign JWT' })
  }
})

// ✅ Verify signed challenge
app.post('/verify-signature', async (req, res) => {
  const { jwt } = req.body

  try {
    const payload = JSON.parse(base64url.decode(jwt.split('.')[1]))
    const did = payload.iss
    const challenge = payload.challenge
    const expectedChallenge = challenges.get(did)

    console.log('🔍 Verifying Signature')
    console.log('🔑 DID:', did)
    console.log('📨 Challenge in JWT:', challenge)
    console.log('📦 Expected challenge:', expectedChallenge)

    if (challenge !== expectedChallenge) {
      return res.status(401).json({ success: false, error: 'Invalid or expired challenge' })
    }

    challenges.delete(did)
    res.json({ success: true, did })
  } catch (err) {
    console.error('❌ Verification error:', err)
    res.status(500).json({ success: false, error: err.message })
  }
})

// ✅ Add document
app.post('/add-document', upload.single('file'), (req, res) => {
  const token = req.headers.authorization
  if (!token || !req.file) {
    return res.status(400).json({ success: false, error: 'Missing file or DID token' })
  }

  let did = 'unknown'
  try {
    const payload = JSON.parse(base64url.decode(token.split('.')[1]))
    did = payload.iss || payload.sub
  } catch (e) {
    console.warn('❌ Failed to extract DID from JWT:', e.message)
  }

  const hash = crypto.createHash('sha256').update(req.file.buffer).digest('hex')
  let version = 1
  let versionedHash = `${hash}_v${version}`

  while (documents.has(versionedHash)) {
    version++
    versionedHash = `${hash}_v${version}`
  }

  documents.set(versionedHash, {
    did,
    owner: did,
    fileName: req.file.originalname,
    timestamp: new Date().toISOString()
  })

  console.log(`📥 Stored document ${versionedHash} by ${did}`)
  res.json({ success: true, version, versionedHash })
})

// ✅ Verify document
app.post('/verify-document', upload.single('file'), (req, res) => {
  if (!req.file) {
    return res.status(400).json({ success: false, error: 'Missing file' })
  }

  const hash = crypto.createHash('sha256').update(req.file.buffer).digest('hex')
  let version = 1
  let latest = null

  while (true) {
    const key = `${hash}_v${version}`
    if (documents.has(key)) {
      latest = { ...documents.get(key), version }
      version++
    } else {
      break
    }
  }

  if (!latest) {
    return res.json({ success: true, exists: false })
  }

  res.json({
    success: true,
    exists: true,
    version: latest.version,
    document: latest
  })
})

// ✅ Fallback route
app.use((req, res) => {
  res.status(404).send('❌ Route not found')
})

// ✅ Start server
const PORT = 3000
app.listen(PORT, () => {
  console.log(`✅ Server running at http://localhost:${PORT}`)
})
