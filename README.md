# 🔐 Open Double Ratchet (TypeScript)

A simple TypeScript implementation of the **Double Ratchet** algorithm, commonly used in secure messaging systems (such as Signal) to provide forward secrecy and asynchronous secure communication.

## ✨ Features

- Asymmetric key generation with `tweetnacl`
- HKDF and SHA256 implementation using `fast-sha256`
- Utility functions for UTF8 and Base64 encoding/decoding
- `DoubleRatchetSession` class to manage secure sessions
- `EncryptedPayload` for encrypted message serialization/deserialization
- Session import/export support
- Replay protection (ratcheting and one-time keys)
- Randomized padding to obfuscate message length

## 📦 Installation

```bash
npm install open-double-ratchet
```

## 🛠️ Basic Usage

```ts
import { createDoubleRatchetSession, decodeUTF8, encodeUTF8 } from "./index";
import nacl from "tweetnacl";

// Initialize identity keys
const aliceId = nacl.sign.keyPair();
const bobId = nacl.sign.keyPair();

// Generate a shared key (e.g. from X3DH)
const preSharedKey = nacl.randomBytes(32);

// Initialize sessions
const bobSession = createDoubleRatchetSession(bobId.secretKey, {
  remoteIdentityKey: aliceId.publicKey,
  preSharedKey
});
const aliceSession = createDoubleRatchetSession(aliceId.secretKey, {
  remoteKey: bobSession.publicKey,
  remoteIdentityKey: bobId.publicKey,
  preSharedKey
});
// Can be used also new DoubleRatchetSession(...)


// Message exchange
const encrypted = aliceSession.encrypt(decodeUTF8("Hello Bob!"));
const decrypted = encodeUTF8(bobSession.decrypt(encrypted)!);

console.log("Decrypted message:", decrypted);
```

## 📚 API Reference

### `createDoubleRatchetSession(identityKey, opts): DoubleRatchetSession`

Creates a new Double Ratchet session.  
- `identityKey: Uint8Array` – signing secret key (64 bytes)
- `opts?: { remoteKey?, remoteIdentityKey?, preSharedKey? }`

> ⚠️ If `remoteKey` is not provided, the sending chain will initialize upon receiving the first message.

### `DoubleRatchetSession`

**Properties:**

- `handshaked: boolean` – whether both sending and receiving chains are active
- `publicKey: Uint8Array` – current ratchet public key
- `remoteKey?: Uint8Array` – last known remote public key

**Methods:**
- `encrypt(payload: Uint8Array): EncryptedPayload | undefined` – encrypts a message.
- `decrypt(payload: Uint8Array | EncryptedPayload): Uint8Array | undefined` – decrypts a message, handling remote key changes and message reordering.
- `export(): string` – exports the session state
- `DoubleRatchetSession.import(json: string): DoubleRatchetSession` - import the session state

### `EncryptedPayload`

A serializable encrypted message format.

**Properties:**
- `count: number` – sending message count
- `previous: number` – count from previous sending chain
- `publicKey: Uint8Array` – sender's public key
- `nonce: Uint8Array` – nonce used in `nacl.secretbox`
- `ciphertext: Uint8Array` – the encrypted message
- `signature?: Uint8Array`

**Methods:**
- `encode(): Uint8Array` – returns the raw byte format.
- `decode(): object` – returns a human-readable decoded object.
- `toString(): string` – UTF-8 string representation.
- `toJSON(): string` – JSON string of the decoded object.
- `setSignature(sig: Uint8Array): this`
- `EncryptedPayload.from(encoded: Uint8Array | EncryptedPayload): EncryptedPayload` – static method to restore from encoded data.

## 💾 Session Import/Export

You can serialize the session with:

```ts
const saved = aliceSession.export();
```

...and restore it later with:

```ts
import { DoubleRatchetSession } from "./index";

const restored = DoubleRatchetSession.import(saved);
```

## 🔐 Remote Identity Management

Message signature verification (optional but recommended) requires the remote party's identity public key:

```ts
const alice = createDoubleRatchetSession(mySecretKey, {
  remoteKey,
  remoteIdentityKey // <- remote signing key
});
```

If omitted, the session will accept unsigned messages, which has **security implications**.

## 🧪 Testing

No automated tests are currently included. You can manually test using the example above. It is recommended to add:

- Unit tests for encryption/decryption
- Ratcheting and out-of-order message handling
- Import/export consistency checks

## 🛡️ Padding and Metadata Protection

Encrypted messages include **random padding** to make actual length less distinguishable.

## 🔐 Security Notice

> This library **has not been audited**. It is intended for **educational or experimental use only**.  
> It is not recommended for use in production or critical systems.


## 📄 License

This project is licensed under the **GNU General Public License v3.0**.

See the [LICENSE](LICENSE) file or visit [gnu.org/licenses/gpl-3.0](https://www.gnu.org/licenses/gpl-3.0).