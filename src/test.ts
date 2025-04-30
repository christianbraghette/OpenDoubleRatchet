import nacl from "tweetnacl";
import { createDoubleRatchetSession, decodeUTF8, encodeUTF8, EncryptedPayload } from "./index.js";

const aliceId = nacl.sign.keyPair();
const bobId = nacl.sign.keyPair();

const preSharedKey = nacl.randomBytes(32);

const alice = createDoubleRatchetSession(aliceId.secretKey, { remoteIdentityKey: bobId.publicKey });
const bob = createDoubleRatchetSession(bobId.secretKey, { remoteKey: alice.publicKey, remoteIdentityKey: aliceId.publicKey });

const ping = bob.encrypt(decodeUTF8("Ping"));

console.log(ping?.decode())

console.log(alice.decrypt(ping!));

//const pong = alice.encrypt(decodeUTF8("Pong"));

//console.log(encodeUTF8(bob.decrypt(pong!)));
