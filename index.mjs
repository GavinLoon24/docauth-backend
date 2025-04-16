import express from 'express'
import cors from 'cors'
import path from 'path'
import crypto from 'crypto'
import fs from 'fs'
import { fileURLToPath } from 'url'
import { dirname } from 'path'
import base64url from 'base64url'
import { importJWK, SignJWT } from 'jose'

const __filename = fileURLToPath(import.meta.url)
const __dirname = dirname(__filename)

const app = express()
app.use(cors())
app.use(express.json())
app.use(express.urlencoded({ extended: true }))
app.use(express.static(path.join(__dirname, 'public')))

const challenges = new Map()
const documentStore = new Map()

// ✅ Serve login page
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'did-login.html'))
})

// ✅ Serve main app page
app.get('/index.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'))
})

// ✅ Generate DID + Key
app.get('/generate-did', (req, res) => {
  const keyPair = crypto.generateKeyPairSync('ed25519')
  const privateKey = keyPair.privateKey.export({ format: 'jwk' })
  const publicKey = keyPair.publicKey.export({ format: 'jwk' })
  const did = `did:key:z${crypto.randomBytes(16).toString('hex')}`

  res.json({ did, privateKeyJwk: privateKey, publicKeyJwk: publicKey })
})

// ✅ Login Challenge
app.get('/login-challenge/:did', (req, res) => {
  const { did } = req.params
  const challenge = crypto.randomBytes(32).toString('hex')
  challenges.set(did, challenge)
  console.log(`🟢 Challenge issued for ${did}: ${challenge}`)
  res.json({ challenge })
})

// ✅ Sign Challenge (Server-side signing for demo)
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

// ✅ Verify Signature
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

// ✅ Add Document
app.post('/add-document', async (req, res) => {
  const chunks = []
  req.on('data', chunk => chunks.push(chunk))
  req.on('end', () => {
    const boundary = req.headers['content-type'].split('boundary=')[1]
    const buffer = Buffer.concat(chunks)
    const content = buffer.toString()
    const base64 = content.split('\r\n\r\n')[1].split('\r\n')[0]
    const fileBuffer = Buffer.from(base64, 'binary')

    const hash = crypto.createHash('sha256').update(fileBuffer).digest('hex')
    const versionedHash = `${hash}_v1`

    const did = req.headers['authorization']
    if (!did) return res.status(401).json({ error: 'Missing DID' })

    documentStore.set(versionedHash, {
      hash,
      version: 1,
      owner: did,
      timestamp: new Date().toISOString(),
      did
    })

    console.log(`📥 Stored document ${versionedHash} by ${did}`)
    res.json({ success: true, versionedHash, version: 1, owner: did })
  })
})

// ✅ Verify Document
app.post('/verify-document', async (req, res) => {
  const chunks = []
  req.on('data', chunk => chunks.push(chunk))
  req.on('end', () => {
    const buffer = Buffer.concat(chunks)
    const hash = crypto.createHash('sha256').update(buffer).digest('hex')
    const versionedHash = `${hash}_v1`

    const doc = documentStore.get(versionedHash)
    if (doc) {
      res.json({ exists: true, version: 1, document: doc })
    } else {
      res.json({ exists: false })
    }
  })
})

// ✅ Fallback
app.use((req, res) => {
  res.status(404).send('❌ Route not found')
})

const PORT = process.env.PORT || 3000
app.listen(PORT, () => {
  console.log(`✅ Server running at http://localhost:${PORT}`)
})
