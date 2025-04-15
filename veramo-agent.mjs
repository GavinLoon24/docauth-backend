import { createAgent } from '@veramo/core'
import { KeyManager, MemoryKeyStore, MemoryPrivateKeyStore } from '@veramo/key-manager'
import { KeyManagementSystem } from '@veramo/kms-local'
import { DIDManager, MemoryDIDStore } from '@veramo/did-manager'
import { KeyDIDProvider, getDidKeyResolver } from '@veramo/did-provider-key'
import { CredentialPlugin } from '@veramo/credential-w3c'
import { DIDResolverPlugin } from '@veramo/did-resolver'
import { Resolver } from 'did-resolver'

// ✅ Setup resolvers properly for use with CredentialPlugin
const didResolver = new Resolver({
  ...getDidKeyResolver()
})

export const agent = createAgent({
  plugins: [
    new KeyManager({
      store: new MemoryKeyStore(),
      kms: {
        local: new KeyManagementSystem(new MemoryPrivateKeyStore())
      }
    }),
    new DIDManager({
      store: new MemoryDIDStore(),
      defaultProvider: 'key',
      providers: {
        key: new KeyDIDProvider({
          defaultKms: 'local',
          keyStore: new MemoryKeyStore()
        })
      }
    }),
    new DIDResolverPlugin({
      resolver: didResolver // ✅ Important for CredentialPlugin
    }),
    new CredentialPlugin()
  ]
})
