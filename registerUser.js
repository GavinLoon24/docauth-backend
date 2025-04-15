const express = require('express');
const cors = require('cors');
const multer = require('multer');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { Gateway, Wallets } = require('fabric-network');

const app = express();
const port = 3000;

app.use(cors());
app.use(express.json());

const upload = multer({ dest: 'uploads/' });

async function getContract() {
  const ccpPath = path.resolve(__dirname, '../fabric-samples/test-network/organizations/peerOrganizations/org1.example.com/connection-org1.json');
  const ccp = JSON.parse(fs.readFileSync(ccpPath, 'utf8'));

  const walletPath = path.join(__dirname, 'wallet');
  const wallet = await Wallets.newFileSystemWallet(walletPath);

  const gateway = new Gateway();
  await gateway.connect(ccp, {
    wallet,
    identity: 'docUser2',
    discovery: { enabled: true, asLocalhost: true }
  });

  const network = await gateway.getNetwork('mychannel');
  const contract = network.getContract('docauth');

  return { contract, gateway };
}

// Route: Add Document
app.post('/add-document', upload.single('file'), async (req, res) => {
  try {
    const fileBuffer = fs.readFileSync(req.file.path);
    const hash = crypto.createHash('sha256').update(fileBuffer).digest('hex');

    const { contract, gateway } = await getContract();
    await contract.submitTransaction('AddDocument', hash);
    await gateway.disconnect();

    res.json({ success: true, hash, message: 'Document hash stored on blockchain' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// Route: Verify Document
app.post('/verify-document', upload.single('file'), async (req, res) => {
  try {
    const fileBuffer = fs.readFileSync(req.file.path);
    const hash = crypto.createHash('sha256').update(fileBuffer).digest('hex');

    const { contract, gateway } = await getContract();
    const result = await contract.evaluateTransaction('VerifyDocument', hash);
    await gateway.disconnect();

    const exists = result.toString() === 'true';

    res.json({ exists, hash });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, error: err.message });
  }
});

app.listen(port, () => {
  console.log(`✅ Server running at http://localhost:${port}`);
});
