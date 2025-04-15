async function loginWithDID() {
  const did = document.getElementById('didInput').value.trim()
  const privateKeyRaw = document.getElementById('privateKeyInput').value.trim()

  if (!did || !privateKeyRaw) {
    alert('❗ Please enter both DID and private key')
    return
  }

  try {
    const parsedKey = JSON.parse(privateKeyRaw)

    // Step 1: Get challenge
    const challengeRes = await fetch(`/api/challenge/${encodeURIComponent(did)}`)
    const { challenge } = await challengeRes.json()

    // Step 2: Ask backend to generate signed JWT using challenge
    const signRes = await fetch('/sign-challenge', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ did, challenge, privateKeyJwk: parsedKey })
    })

    const { jwt, error } = await signRes.json()
    if (!jwt) {
      document.getElementById('loginResult').textContent = `❌ Sign Error: ${error}`
      return
    }

    // Step 3: Send JWT + JWK to backend for verification
    const verifyRes = await fetch('/api/verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ jwt, jwk: parsedKey })  // ✅ now includes JWT + JWK
    })

    const result = await verifyRes.json()
    if (result.success) {
      document.getElementById('loginResult').textContent = `✅ DID verified!\nDID: ${result.did}`
      localStorage.setItem('token', 'did-auth')
      localStorage.setItem('did', result.did)
      setTimeout(() => window.location.href = '/index.html', 1000)
    } else {
      document.getElementById('loginResult').textContent = `⚠️ Verification failed:\n\n${JSON.stringify(result, null, 2)}`
    }
  } catch (err) {
    console.error(err)
    document.getElementById('loginResult').textContent = `❌ Error: ${err.message}`
  }
}
