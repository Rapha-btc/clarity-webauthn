;; title: webauthn-verifier
;; version: 1.0.0
;; summary: WebAuthn/Passkey signature verification for Clarity 5+
;; description: Verifies WebAuthn passkey signatures by reconstructing 
;;              what the authenticator actually signed.
;;              Requires Clarity 5 where secp256r1-verify no longer double-hashes.

;; ============================================================
;; CONSTANTS
;; ============================================================

(define-constant err-invalid-signature (err u6001))
(define-constant err-invalid-authenticator-data (err u6002))
(define-constant err-user-not-present (err u6003))
(define-constant err-user-not-verified (err u6004))

;; Authenticator data flag bits
(define-constant FLAG_UP u1)   ;; User Present
(define-constant FLAG_UV u4)   ;; User Verified
(define-constant FLAG_AT u64)  ;; Attested Credential Data
(define-constant FLAG_ED u128) ;; Extension Data

;; ============================================================
;; CORE VERIFICATION
;; ============================================================

;; Verify a WebAuthn passkey signature
;;
;; WebAuthn authenticators sign: sha256(authenticatorData || sha256(clientDataJSON))
;; 
;; In Clarity 5, secp256r1-verify(hash, sig, pubkey) verifies directly against hash
;; without internal hashing, so we reconstruct what WebAuthn signed and verify that.
;;
;; Parameters:
;; - signature: 64-byte r||s signature (DER decoded, low-s normalized)
;; - pubkey: 33-byte compressed secp256r1 public key  
;; - authenticator-data: Raw authenticatorData from navigator.credentials.get()
;; - client-data-json: Raw clientDataJSON from navigator.credentials.get()
;;
;; Frontend must:
;; 1. Pass messageHash as the WebAuthn challenge
;; 2. Extract authenticatorData and clientDataJSON from AuthenticatorAssertionResponse
;; 3. Parse DER signature to 64-byte r||s format
;; 4. Normalize s to low-s form (s < n/2)
;;
;; Returns: (ok true) if signature is valid, (err u6001) otherwise
;;
(define-read-only (verify-webauthn-signature
    (signature (buff 64))
    (pubkey (buff 33))
    (authenticator-data (buff 512))
    (client-data-json (buff 1024))
  )
  (let (
    ;; Reconstruct exactly what the WebAuthn authenticator signed
    (client-data-hash (sha256 client-data-json))
    (signed-data (concat authenticator-data client-data-hash))
    (signed-hash (sha256 signed-data))
  )
    ;; Clarity 5: secp256r1-verify checks signature directly against signed-hash
    ;; No internal hashing occurs
    (ok (asserts! (secp256r1-verify signed-hash signature pubkey) err-invalid-signature))
  )
)

;; ============================================================
;; VERIFICATION WITH FLAG CHECKS
;; ============================================================

;; Verify WebAuthn signature with authenticator flag validation
;;
;; Same as verify-webauthn-signature but also checks that required
;; authenticator flags are set. Use this for security-critical operations.
;;
;; Parameters:
;; - signature, pubkey, authenticator-data, client-data-json: Same as above
;; - require-user-present: If true, fail if UP flag not set
;; - require-user-verified: If true, fail if UV flag not set
;;
;; The UV (User Verified) flag indicates biometric or PIN was used.
;; Some authenticators only set UP (User Present) for basic presence check.
;;
(define-read-only (verify-webauthn-signature-with-flags
    (signature (buff 64))
    (pubkey (buff 33))
    (authenticator-data (buff 512))
    (client-data-json (buff 1024))
    (require-user-present bool)
    (require-user-verified bool)
  )
  (let (
    (client-data-hash (sha256 client-data-json))
    (signed-data (concat authenticator-data client-data-hash))
    (signed-hash (sha256 signed-data))
    ;; Extract flags byte (byte 32 of authenticatorData, after rpIdHash)
    (flags-byte (get-flags-byte authenticator-data))
  )
    ;; Check required flags
    (asserts! (or (not require-user-present) (is-flag-set flags-byte FLAG_UP)) 
              err-user-not-present)
    (asserts! (or (not require-user-verified) (is-flag-set flags-byte FLAG_UV)) 
              err-user-not-verified)
    ;; Verify signature
    (ok (asserts! (secp256r1-verify signed-hash signature pubkey) err-invalid-signature))
  )
)

;; ============================================================
;; HELPER FUNCTIONS
;; ============================================================

;; Extract the flags byte from authenticatorData
;; AuthenticatorData structure:
;; - bytes 0-31: rpIdHash (SHA-256 of relying party ID)
;; - byte 32: flags
;; - bytes 33-36: signCount (big-endian uint32)
;; - remaining: optional attestedCredentialData and extensions
(define-private (get-flags-byte (authenticator-data (buff 512)))
  (default-to u0 
    (element-at? 
      (unwrap-panic (as-max-len? authenticator-data u512))
      u32
    )
  )
)

;; Check if a specific flag bit is set
(define-private (is-flag-set (flags uint) (flag uint))
  (> (bit-and flags flag) u0)
)

;; ============================================================
;; BATCH VERIFICATION (Gas Optimization)
;; ============================================================

;; Verify multiple signatures in one call
;; Useful for multi-sig or batched transactions
;;
;; Returns list of verification results
;;
(define-read-only (verify-webauthn-signatures-batch
    (verifications (list 10 {
      signature: (buff 64),
      pubkey: (buff 33),
      authenticator-data: (buff 512),
      client-data-json: (buff 1024)
    }))
  )
  (ok (map verify-single verifications))
)

(define-private (verify-single 
    (v {
      signature: (buff 64),
      pubkey: (buff 33),
      authenticator-data: (buff 512),
      client-data-json: (buff 1024)
    })
  )
  (let (
    (client-data-hash (sha256 (get client-data-json v)))
    (signed-data (concat (get authenticator-data v) client-data-hash))
    (signed-hash (sha256 signed-data))
  )
    (secp256r1-verify signed-hash (get signature v) (get pubkey v))
  )
)

;; ============================================================
;; UTILITIES FOR INTEGRATION
;; ============================================================

;; Compute what the authenticator will sign for a given challenge
;; Useful for debugging and testing
;;
;; Note: In production, you don't call this - the browser handles it.
;; This is just to verify your frontend is constructing things correctly.
;;
(define-read-only (compute-signed-hash
    (authenticator-data (buff 512))
    (client-data-json (buff 1024))
  )
  (let (
    (client-data-hash (sha256 client-data-json))
    (signed-data (concat authenticator-data client-data-hash))
  )
    (sha256 signed-data)
  )
)

;; Extract the rpIdHash from authenticatorData (first 32 bytes)
;; This should match sha256(rpId) where rpId is typically your domain
(define-read-only (get-rp-id-hash (authenticator-data (buff 512)))
  (unwrap-panic (slice? authenticator-data u0 u32))
)

;; Extract sign count from authenticatorData (bytes 33-36, big-endian)
;; Useful for replay protection - count should always increase
(define-read-only (get-sign-count (authenticator-data (buff 512)))
  ;; Note: Clarity doesn't have easy big-endian uint parsing
  ;; This returns raw bytes - parse in frontend or add parsing logic
  (unwrap-panic (slice? authenticator-data u33 u37))
)
