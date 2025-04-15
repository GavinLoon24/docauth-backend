const FabricCAServices = require('fabric-ca-client');
const { Wallets } = require('fabric-network');
const fs = require('fs');
const path = require('path');

async function main() {
  try {
    const ccpPath = path.resolve(__dirname, '../fabric-samples/test-network/organizations/peerOrganizations/org1.example.com/connection-org1.json');
    const ccp = JSON.parse(fs.readFileSync(ccpPath, 'utf8'));

    const caURL = ccp.certificateAuthorities['ca.org1.example.com'].url;
    const ca = new FabricCAServices(caURL);

    const walletPath = path.join(__dirname, 'wallet');
    const wallet = await Wallets.newFileSystemWallet(walletPath);

    const identity = await wallet.get('admin');
    if (identity) {
      console.log('✅ Admin identity already exists in the wallet');
      return;
    }

    const enrollment = await ca.enroll({ enrollmentID: 'admin', enrollmentSecret: 'adminpw' });

    const x509Identity = {
      credentials: {
        certificate: enrollment.certificate,
        privateKey: enrollment.key.toBytes()
      },
      mspId: 'Org1MSP',
      type: 'X.509'
    };

    await wallet.put('admin', x509Identity);
    console.log('🎉 Successfully enrolled admin and imported into the wallet');
  } catch (error) {
    console.error(`❌ Failed to enroll admin: ${error}`);
    process.exit(1);
  }
}

main();

