# Grant Proposal: clarity-webauthn

## WebAuthn/Passkey Infrastructure for Clarity 5

**Submitted by:** Rapha ([@RaphaStacks](https://twitter.com/RaphaStacks))  
**Date:** January 2026  
**Requested Amount:** [TBD]

---

## Executive Summary

Clarity 5 will fix the `secp256r1-verify` double-hash bug, finally enabling native passkey verification on Stacks. This grant funds the development of **production-ready tooling** that allows any developer to integrate WebAuthn passkeys into their Stacks application—with zero per-signature costs and true self-custody.

The deliverable is `clarity-webauthn`: battle-tested Clarity contracts, a TypeScript SDK, comprehensive documentation, and reference implementations.

---

## Problem Statement

### The Status Quo

Passkeys (Face ID, Touch ID, Windows Hello) represent the future of authentication:

- No seed phrases to lose
- Phishing-resistant by design
- Hardware-backed security
- Cross-device sync via iCloud/Google

However, integrating passkeys with Stacks smart contracts today requires **expensive intermediaries**.

### The Turnkey Reality

I discovered this building [PillarBTC](https://pillarbtc.com)—a passkey-powered smart wallet for leveraged sBTC positions. Testing alone consumed 55 signatures at $0.10 each.

Turnkey's model:

- 25 free signatures/month
- $0.10 per additional signature
- Keys are custodied by Turnkey (albeit in secure hardware)

For an application with thousands of users making daily transactions, this becomes **prohibitively expensive** and introduces custody tradeoffs.

### Why Not Native WebAuthn Today?

Two technical blockers:

1. **WebAuthn's Signature Wrapper**  
   Browsers sign `sha256(authenticatorData || sha256(clientDataJSON))`, not your raw message. The contract must reconstruct this.

2. **secp256r1-verify Double-Hash Bug**  
   Current Clarity internally hashes input before verifying, making reconstruction impossible.

Clarity 5 ([PR #6763](https://github.com/stacks-network/stacks-core/pull/6763)) fixes #2. This grant delivers the tooling to address #1.

---

## Solution: clarity-webauthn

A complete toolkit enabling native passkey verification on Stacks:

### 1. Clarity Contracts

**webauthn-verifier.clar**

```clarity
(define-read-only (verify-webauthn-signature
    (signature (buff 64))
    (pubkey (buff 33))
    (authenticator-data (buff 512))
    (client-data-json (buff 1024))
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

Plus:

- Flag validation (user presence, user verification)
- Batch verification for gas optimization
- Standard traits for ecosystem interoperability

### 2. TypeScript SDK

```typescript
import { signWithPasskey, prepareForClarity } from "@clarity-webauthn/sdk";

// Sign with Face ID
const response = await signWithPasskey(credentialId, messageHash);

// Prepare for Clarity
const { signature, authenticatorData, clientDataJSON } =
  prepareForClarity(response);

// Call contract
await contractCall("verify-webauthn-signature", [
  bufferCV(signature),
  bufferCV(pubkey),
  bufferCV(authenticatorData),
  bufferCV(clientDataJSON),
]);
```

Handles:

- WebAuthn browser API wrapper
- DER signature parsing to r||s format
- Low-s signature normalization
- COSE public key parsing

### 3. Documentation & Examples

- Security considerations guide
- Step-by-step integration tutorial
- React example application
- Reference smart wallet implementation

---

## Impact

### For Developers

- **Copy-paste integration** instead of months of research
- **Audited contracts** they can trust
- **Clear documentation** explaining the security model

### For Users

- **No seed phrases** - authenticate with Face ID
- **True self-custody** - keys never leave the secure enclave
- **Free forever** - no per-signature costs

### For the Ecosystem

- **Every Stacks app** can offer passkey auth post-Clarity 5
- **Competitive UX** with Web2 applications
- **Security improvement** over seed phrase wallets

---

## Team

### Rapha ([@RaphaStacks](https://twitter.com/RaphaStacks))

Building [PillarBTC](https://pillarbtc.com) - leveraged sBTC with automated deleveraging.

- Deep hands-on experience with WebAuthn integration challenges
- Built and tested passkey flows using Turnkey
- Validated the problem space through production development
- Active contributor to Stacks ecosystem

**From the trenches:**

> "I did my homework on wallet security. WebAuthn appeared solid: device-bound keys, secure enclave signing, no seed phrases, phishing resistance. Then I reviewed the risk model. Clarity 5 will support P-256 natively. Passkeys use P-256. On-chain verification becomes possible without intermediaries. WebAuthn is free and unlimited."

---

## Deliverables

| Milestone | Deliverable                       | Timeline  |
| --------- | --------------------------------- | --------- |
| **M1**    | Core Clarity contracts with tests | Week 1-2  |
| **M2**    | TypeScript SDK (beta)             | Week 3-4  |
| **M3**    | Documentation & security guide    | Week 5-6  |
| **M4**    | Example applications              | Week 7-8  |
| **M5**    | Community review & polish         | Week 9-10 |

### Detailed Deliverables

**Clarity Contracts**

- [ ] webauthn-verifier.clar - Core verification
- [ ] webauthn-trait.clar - Standard interface
- [ ] webauthn-account.clar - Reference implementation
- [ ] Unit tests (Clarinet)
- [ ] Integration tests

**TypeScript SDK**

- [ ] WebAuthn browser API wrapper
- [ ] Signature parsing (DER → r||s)
- [ ] Low-s normalization
- [ ] Public key handling (COSE → compressed)
- [ ] Clarity value construction
- [ ] npm package published

**Documentation**

- [ ] ARCHITECTURE.md - Technical deep-dive
- [ ] INTEGRATION.md - Step-by-step guide
- [ ] SECURITY.md - Threat model & considerations
- [ ] API reference (TypeDoc)

**Examples**

- [ ] React passkey login example
- [ ] Smart wallet reference implementation
- [ ] Multi-sig example

---

## Budget

| Item                 | Hours    | Rate | Cost   |
| -------------------- | -------- | ---- | ------ |
| Clarity Development  | 40h      | $X/h | $X     |
| TypeScript SDK       | 40h      | $X/h | $X     |
| Documentation        | 20h      | $X/h | $X     |
| Examples & Testing   | 20h      | $X/h | $X     |
| Security Review Prep | 10h      | $X/h | $X     |
| **Total**            | **130h** |      | **$X** |

_Note: Actual security audit is out of scope but deliverables will be audit-ready._

---

## Success Metrics

1. **Adoption**

   - NPM downloads of @clarity-webauthn/sdk
   - GitHub stars and forks
   - Projects integrating the library

2. **Quality**

   - Zero critical bugs post-launch
   - Passing security review

3. **Community**
   - Documentation feedback incorporated
   - Community contributions accepted

---

## Risks & Mitigations

| Risk                              | Mitigation                                                |
| --------------------------------- | --------------------------------------------------------- |
| Clarity 5 delays                  | Develop against testnet, adapt as needed                  |
| secp256r1-verify behavior changes | Monitor PRs, maintain communication with core devs        |
| Browser compatibility issues      | Test across Chrome, Safari, Firefox; document limitations |

---

## Why Fund This?

1. **Timing**: Clarity 5 is coming. The ecosystem needs tooling ready at launch.

2. **Expertise**: I've already spent weeks debugging WebAuthn + Stacks integration. This grant funds sharing that knowledge.

3. **Multiplier Effect**: One library enables hundreds of applications. The ROI for ecosystem development is enormous.

4. **Alternative is Worse**: Without good tooling, developers will either use expensive intermediaries or build insecure implementations.

---

## Contact

- Twitter: [@RaphaStacks](https://twitter.com/RaphaStacks)
- GitHub: [Rapha-btc](https://github.com/Rapha-btc)
- Project: [PillarBTC](https://pillarbtc.com)

---

_Ready to make passkeys the default for Stacks._
