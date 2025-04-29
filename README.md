# 🔐 Open Double Ratchet (TypeScript)

A simple TypeScript implementation of the **Double Ratchet** protocol, commonly used in secure messaging systems (such as Signal) to provide forward secrecy and asynchronous secure messaging.

## ✨ Features

- Asymmetric key generation with `tweetnacl`
- HKDF and SHA256 implementation using `fast-sha256`
- Utility functions for UTF8 and Base64 encoding/decoding
- `DoubleRatchetSession` class to manage secure sessions
- `EncryptedPayload` for encrypted message serialization/deserialization

## 📦 Installation

```bash
npm install open-double-ratchet
```

## 🛠️ Usage

```js
import { createDoubleRatchetSession, decodeUTF8, encodeUTF8 } from "./index";

// Initialize two sessions (simulating sender and recipient)
const bobSession = createDoubleRatchetSession();
const aliceSession = createDoubleRatchetSession(bobSession.publicKey);

// Bob sets Alice's public key by decrypting a message
bobSession.decrypt(aliceSession.encrypt(decodeUTF8("Hello Alice!")));

// Message exchange
const encrypted = aliceSession.encrypt(decodeUTF8("Hello Bob!"));
const decrypted = encodeUTF8(bobSession.decrypt(encrypted));

console.log("Decrypted message:", decrypted);
```

## 📚 API Reference

### `createDoubleRatchetSession(remoteKey?: Uint8Array): DoubleRatchetSession`

Creates a new Double Ratchet session.

- If `remoteKey` is provided, initializes sending chain.

- If not, it waits for a remote key to be set via decryption.

### `DoubleRatchetSession`

**Properties:**
- `handshaked: boolean` – whether the sending and receiving chains are both initialized.

- `publicKey: Uint8Array` – the local public key.

- `remoteKey?: Uint8Array` – the peer's public key.

**Methods:**
- `encrypt(payload: Uint8Array): EncryptedPayload | undefined` – encrypts a message.

- `decrypt(payload: Uint8Array | EncryptedPayload): Uint8Array | undefined` – decrypts a message, handling remote key changes and message reordering.

### `EncryptedPayload`

A serializable encrypted message format.

**Properties:**
- `count: number` – sending message count.

- `previous: number` – count from previous sending chain.

- `publicKey: Uint8Array` – sender's public key.

- `nonce: Uint8Array` – nonce used in nacl.secretbox.

- `ciphertext: Uint8Array` – the encrypted message.

**Methods:**
- `encode(): Uint8Array` – returns the raw byte format.

- `decode(): object` – returns a human-readable decoded object.

- `toString(): string` – UTF-8 string representation.

- `toJSON(): string` – JSON string of the decoded object.

- `EncryptedPayload.from(Uint8Array)` – static method to restore from encoded data.

## 🔐 Security Notice
This library is not audited and is intended for educational or experimental use only. For production use, please consider audited libraries or protocols with formal security proofs.

## 🧪 Testing
You can test the functionality by simulating a message exchange using the example code provided above. Automated tests are not yet included.

## 📄 License
This project is licensed under the GNU General Public License v3.0.

See the [LICENSE](LICENSE) file or visit [gnu.org/licenses/gpl-3.0](https://www.gnu.org/licenses/gpl-3.0) for more details.