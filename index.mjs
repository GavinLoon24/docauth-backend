import express from 'express'
import cors from 'cors'
import path from 'path'
import crypto from 'crypto'
import fs from 'fs'
import { fileURLToPath } from 'url'
import { dirname } from 'path'
import base64url from 'base64url'
import { importJWK, SignJWT } from 'jose'
import multer from 'multer'

const __filename = fileURLToPath(import.meta.url)
const __dirname = dirname(__filename)

const app = express()
app.use(cors())
app.use(express.json())
app.use(express.urlencoded({ extended: true }))
app.use(express.static(path.join(__dirname, 'public')))

const upload = multer({ storage: multer.memoryStorage() })

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

// ✅ Upload Document
app.post('/add-document', upload.single('file'), (req, res) => {
  const token = req.headers.authorization
  if (!token) return res.status(401).json({ error: 'Missing token' })

  try {
    const payload = JSON.parse(base64url.decode(token.split('.')[1]))
    const ownerDid = payload.iss
    const fileBuffer = req.file.buffer
    const hash = crypto.createHash('sha256').update(fileBuffer).digest('hex')

    const existing = documents.get(hash)
    const version = existing ? existing.version + 1 : 1
    const versionedHash = `${hash}_v${version}`

    documents.set(hash, {
      hash,
      version,
      versionedHash,
      owner: token,
      did: ownerDid,
      timestamp: new Date().toISOString()
    })

    console.log(`📥 Stored document ${versionedHash} by ${ownerDid}`)

    res.json({ success: true, version, versionedHash, owner: token, did: ownerDid })
  } catch (err) {
    res.status(500).json({ success: false, error: 'Invalid token or upload failed' })
  }
})

// ✅ Verify Document
app.post('/verify-document', upload.single('file'), (req, res) => {
  const fileBuffer = req.file.buffer
  const hash = crypto.createHash('sha256').update(fileBuffer).digest('hex')

  const doc = documents.get(hash)
  if (!doc) {
    return res.json({ exists: false })
  }

  res.json({
    exists: true,
    version: doc.version,
    document: doc
  })
})

// ✅ Fallback route
app.use((req, res) => {
  res.status(404).send('❌ Route not found')
})

const PORT = process.env.PORT || 3000
app.listen(PORT, () => {
  console.log(`✅ Server running at http://localhost:${PORT}`)
})
