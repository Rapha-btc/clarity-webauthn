# clarity-webauthn

**Production-ready WebAuthn/Passkey verification for Clarity 5**

A complete toolkit enabling Stacks smart contracts to verify passkey signatures directly on-chain—no intermediaries, no custody, no per-signature fees.

## Why This Matters

WebAuthn passkeys (Face ID, Touch ID, Windows Hello) are the future of authentication:

- **Device-bound keys** stored in secure enclaves
- **Phishing resistant** by design
- **No seed phrases** to lose or steal
- **Cross-platform** via iCloud Keychain and Google Password Manager

Clarity 5 removes the last barrier to native passkey support by fixing the `secp256r1-verify` double-hash bug ([PR #6763](https://github.com/stacks-network/stacks-core/pull/6763)). This library provides everything developers need to integrate passkeys into their Stacks applications.

## The Problem Today

Before Clarity 5, developers wanting passkey-like UX have two options:

1. **Wait** - No passkey support until the hard fork
2. **Use intermediaries like Turnkey** - $0.10 per signature, custody tradeoffs

Neither is ideal. When Clarity 5 lands, developers will need:

- Battle-tested Clarity contracts for WebAuthn verification
- JavaScript/TypeScript utilities for frontend integration
- Comprehensive documentation and examples
- Reference implementations they can trust

**This library fills that gap.**

## How WebAuthn Signatures Work

When a user signs with a passkey, the authenticator doesn't sign your data directly. It signs:

```
sha256(authenticatorData || sha256(clientDataJSON))
```

Where:

- `authenticatorData` contains flags, counter, and relying party info
- `clientDataJSON` contains your challenge (message hash), origin, and type

To verify on-chain, we must reconstruct exactly what the authenticator signed:

```clarity
(let (
  (client-data-hash (sha256 client-data-json))
  (signed-data (concat authenticator-data client-data-hash))
  (signed-hash (sha256 signed-data))
)
  ;; Clarity 5: secp256r1-verify checks directly against signed-hash
  (secp256r1-verify signed-hash signature pubkey)
)
```

## Repository Structure

```
clarity-webauthn/
├── contracts/
│   ├── webauthn-verifier.clar       # Core verification logic
│   ├── webauthn-account.clar        # Reference account abstraction
│   └── traits/
│       └── webauthn-trait.clar      # Standard trait for interop
├── js/
│   ├── src/
│   │   ├── index.ts                 # Main exports
│   │   ├── webauthn.ts              # WebAuthn API wrapper
│   │   ├── signature.ts             # DER parsing, low-s normalization
│   │   ├── encoding.ts              # Base64url, buffer utilities
│   │   └── clarity.ts               # Clarity value construction
│   ├── package.json
│   └── tsconfig.json
├── tests/
│   ├── webauthn-verifier.test.ts    # Contract tests
│   └── integration.test.ts          # End-to-end tests
├── examples/
│   ├── react-passkey-login/         # React example app
│   └── smart-wallet/                # Smart wallet integration
└── docs/
    ├── ARCHITECTURE.md              # Technical deep-dive
    ├── INTEGRATION.md               # Step-by-step guide
    └── SECURITY.md                  # Security considerations
```

## Clarity Contracts

### webauthn-verifier.clar

Core verification that reconstructs what WebAuthn signed:

```clarity
;; Verify a WebAuthn passkey signature
;; Returns (ok true) if valid, (err u6001) if invalid
(define-read-only (verify-webauthn-signature
    (signature (buff 64))           ;; r||s format, low-s normalized
    (pubkey (buff 33))              ;; Compressed secp256r1 public key
    (authenticator-data (buff 512)) ;; Raw from WebAuthn response
    (client-data-json (buff 1024))  ;; Raw from WebAuthn response
  )
  (let (
    (client-data-hash (sha256 client-data-json))
    (signed-data (concat authenticator-data client-data-hash))
    (signed-hash (sha256 signed-data))
  )
    (ok (asserts! (secp256r1-verify signed-hash signature pubkey) err-invalid-signature))
  )
)
```

### webauthn-trait.clar

Standard trait for WebAuthn-enabled contracts:

```clarity
(define-trait webauthn-auth
  (
    ;; Verify signature and return authorized principal
    (verify-and-get-signer
      ((buff 64) (buff 33) (buff 512) (buff 1024))
      (response principal uint))
  )
)
```

### webauthn-account.clar

Reference implementation of a WebAuthn-authenticated account:

```clarity
;; Account controlled by a passkey
;; Supports key rotation, social recovery, and transaction batching

(define-public (execute
    (action (buff 256))
    (signature (buff 64))
    (authenticator-data (buff 512))
    (client-data-json (buff 1024))
  )
  (begin
    (try! (contract-call? .webauthn-verifier verify-webauthn-signature
      signature
      (var-get owner-pubkey)
      authenticator-data
      client-data-json
    ))
    ;; Execute action...
    (ok true)
  )
)
```

## JavaScript SDK

### Installation

```bash
npm install @clarity-webauthn/sdk
```

### Usage

```typescript
import {
  createPasskeyCredential,
  signWithPasskey,
  prepareForClarity,
} from "@clarity-webauthn/sdk";

// Register a new passkey
const credential = await createPasskeyCredential({
  rpName: "My Stacks App",
  rpId: "myapp.com",
  userName: "user@example.com",
});

// Sign a message
const messageHash = sha256(serializeCV(myTransaction));
const webauthnResponse = await signWithPasskey(credential.id, messageHash);

// Prepare for Clarity contract call
const { signature, authenticatorData, clientDataJSON } =
  prepareForClarity(webauthnResponse);

// Call your contract
await contractCall({
  contractAddress: "SP...",
  contractName: "my-contract",
  functionName: "execute",
  functionArgs: [
    bufferCV(action),
    bufferCV(signature), // 64 bytes, low-s normalized
    bufferCV(authenticatorData), // Variable length
    bufferCV(clientDataJSON), // Variable length
  ],
});
```

### Key Functions

```typescript
// Create a new passkey credential
createPasskeyCredential(options: {
  rpName: string;
  rpId: string;
  userName: string;
  userDisplayName?: string;
}): Promise<PublicKeyCredential>

// Sign with an existing passkey
signWithPasskey(
  credentialId: string,
  challenge: Uint8Array,
  options?: SignOptions
): Promise<WebAuthnSignature>

// Parse DER signature to r||s format
parseSignature(derSignature: Uint8Array): Uint8Array

// Normalize to low-s form (required for secp256r1-verify)
normalizeLowS(signature: Uint8Array): Uint8Array

// Prepare all components for Clarity
prepareForClarity(response: AuthenticatorAssertionResponse): {
  signature: Uint8Array;
  authenticatorData: Uint8Array;
  clientDataJSON: Uint8Array;
  pubkey: Uint8Array;
}
```

## Relayer Patterns

A critical question for passkey-authenticated smart wallets: **who signs and broadcasts the actual Stacks transaction?**

The user's passkey signs the _payload_ (verified on-chain), but someone still needs to submit the transaction to the network. This SDK documents three patterns:

### 1. Self-Relay

User has STX, signs the Stacks transaction with a traditional wallet, passkey signature is included as a parameter.

```
User signs passkey challenge → User signs STX tx → User broadcasts
```

**Pros:** Fully self-custodial, no trust assumptions  
**Cons:** User needs STX for fees, two signatures required

### 2. Sponsored Transactions

App or backend sponsors the transaction fees. User only signs with passkey.

```
User signs passkey challenge → App wraps in sponsored tx → App broadcasts
```

**Pros:** No STX needed, single signature UX  
**Cons:** Trust the app to broadcast, app pays fees

### 3. x402 Facilitation

A reputation-based relayer handles broadcast via [x402](https://x402.org) micropayment endpoint. Relayer can also sponsor fees.

```
User signs passkey challenge → x402 relayer broadcasts → Relayer paid via x402
```

**Pros:** Decentralized relay, aligned incentives, fee sponsorship possible  
**Cons:** Requires x402 infrastructure, relayer availability

For apps targeting new users without STX, patterns 2 or 3 are essential. BitFlow's Keeper architecture is a reference implementation worth studying for pattern 2.

## Security Considerations

### Signature Malleability

secp256r1 signatures have two valid forms: (r, s) and (r, -s mod n). We normalize to low-s form to prevent signature replay with modified s values.

### Challenge Binding

The challenge (message hash) is embedded in clientDataJSON. While we reconstruct the full signed hash for verification, applications should also validate:

- The challenge matches the expected message
- The origin matches your domain
- The type is "webauthn.get"

### Authenticator Data Flags

The authenticatorData contains flags indicating:

- User presence (UP) - was the user physically present?
- User verification (UV) - was biometric/PIN used?

Applications should check these flags match their security requirements.

## Roadmap

### Phase 1: Core Library (Grant Scope)

- [ ] Clarity contracts with comprehensive tests
- [ ] TypeScript SDK with full WebAuthn support
- [ ] Documentation and integration guides
- [ ] Security audit preparation

### Phase 2: Ecosystem Integration

- [ ] Example applications (React, Vue, Svelte)
- [ ] Wallet adapter integration
- [ ] Passkey registry (ENS-style)

### Phase 3: Advanced Features

- [ ] Multi-device passkey sync support
- [ ] Social recovery patterns
- [ ] Session key delegation

## Grant Proposal

See the [full grant proposal](https://gist.github.com/Rapha-btc/38c48d7d10a916c7c381c9ab7c98fa69) for funding details.

### Problem Statement

Clarity 5 will enable native secp256r1 signature verification, unlocking passkey support for Stacks. However, WebAuthn's signing model is complex—developers need production-ready tooling to integrate passkeys safely and correctly.

### Solution

This library provides:

1. **Auditable Clarity contracts** that correctly reconstruct WebAuthn signatures
2. **TypeScript SDK** handling browser APIs, DER parsing, and signature normalization
3. **Comprehensive documentation** explaining the security model
4. **Reference implementations** developers can learn from and extend

### Impact

- **Every Stacks application** can offer passkey authentication
- **Zero per-signature costs** vs intermediary solutions
- **True self-custody** with hardware security module protection
- **Better UX** than seed phrases for mainstream users

## Contributing

Contributions welcome! See [CONTRIBUTING.md](./CONTRIBUTING.md) for guidelines.

## License

MIT

---

_Sign in with your face. Custody your Bitcoin._
