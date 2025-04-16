import { webcrypto } from 'crypto'
globalThis.crypto = webcrypto

import express from 'express'
import cors from 'cors'
import path from 'path'
import crypto from 'crypto'
import fs from 'fs'
import { fileURLToPath } from 'url'
import { dirname } from 'path'
import multer from 'multer'
import base64url from 'base64url'
import { importJWK, SignJWT } from 'jose'

const __filename = fileURLToPath(import.meta.url)
const __dirname = dirname(__filename)
const app = express()
const upload = multer()

app.use(cors())
app.use(express.json())
app.use(express.urlencoded({ extended: true }))
app.use(express.static(path.join(__dirname, 'public')))

const PORT = 3000

// ✅ Document Store (persistent)
const DATA_FILE = path.join(__dirname, 'documents.json')
let documentStore = fs.existsSync(DATA_FILE)
  ? new Map(Object.entries(JSON.parse(fs.readFileSync(DATA_FILE, 'utf-8'))))
  : new Map()

function saveStoreToDisk() {
  fs.writeFileSync(DATA_FILE, JSON.stringify(Object.fromEntries(documentStore)))
}

// ✅ Challenge store
const challenges = new Map()

// ✅ Serve Login Page
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'did-login.html'))
})

// ✅ Generate new DID + Private Key (JWK)
app.get('/generate-did', (req, res) => {
  const keyPair = crypto.generateKeyPairSync('ed25519')
  const privateKey = keyPair.privateKey.export({ format: 'jwk' })
  const publicKey = keyPair.publicKey.export({ format: 'jwk' })
  const did = `did:key:z${crypto.randomBytes(16).toString('hex')}`

  res.json({ did, privateKeyJwk: privateKey, publicKeyJwk: publicKey })
})

// ✅ Issue Challenge
app.get('/login-challenge/:did', (req, res) => {
  const { did } = req.params
  const challenge = crypto.randomBytes(32).toString('hex')
  challenges.set(did, challenge)
  console.log(`🟢 Challenge issued for ${did}: ${challenge}`)
  res.json({ challenge })
})

// ✅ Sign Challenge
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

// ✅ Upload Document
app.post('/add-document', upload.single('file'), (req, res) => {
  const fileBuffer = req.file?.buffer
  if (!fileBuffer) return res.status(400).json({ error: 'No file received' })

  const hash = crypto.createHash('sha256').update(fileBuffer).digest('hex')
  const did = req.headers['authorization']
  if (!did) return res.status(401).json({ error: 'Missing DID' })

  // 🧠 Check versioning
  let version = 1
  while (documentStore.has(`${hash}_v${version}`)) version++
  const versionedHash = `${hash}_v${version}`

  const docMeta = {
    hash,
    version,
    versionedHash,
    timestamp: new Date().toISOString(),
    owner: did,
    did
  }

  documentStore.set(versionedHash, docMeta)
  saveStoreToDisk()

  console.log(`📥 Stored document ${versionedHash} by ${did}`)
  res.json({ success: true, ...docMeta })
})

// ✅ Verify Document
app.post('/verify-document', upload.single('file'), (req, res) => {
  const fileBuffer = req.file?.buffer
  if (!fileBuffer) return res.status(400).json({ error: 'No file received' })

  const hash = crypto.createHash('sha256').update(fileBuffer).digest('hex')

  // Check latest version
  let foundVersion = null
  for (let i = 1; i <= 100; i++) {
    const key = `${hash}_v${i}`
    if (documentStore.has(key)) {
      foundVersion = i
    } else {
      break
    }
  }

  if (foundVersion) {
    const doc = documentStore.get(`${hash}_v${foundVersion}`)
    return res.json({ exists: true, version: foundVersion, document: doc })
  } else {
    return res.json({ exists: false })
  }
})

// ✅ 404 Fallback
app.use((req, res) => {
  res.status(404).send('❌ Route not found')
})

app.listen(PORT, () => {
  console.log(`✅ Server running at http://localhost:${PORT}`)
})
