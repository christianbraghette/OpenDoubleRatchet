import nacl from "tweetnacl";
import { createDoubleRatchetSession, decodeUTF8, DoubleRatchetSession, encodeUTF8, EncryptedPayload, digestX3DHBundle, initX3DHBundleStore } from "./index.js";

const aliceId = nacl.sign.keyPair();
const bobId = nacl.sign.keyPair();

const x3dh = initX3DHBundleStore(aliceId.secretKey)!;

const bundle = x3dh.generate();
console.log(bundle);

const [bobshared, bobmessage] = digestX3DHBundle(bobId.secretKey, aliceId.publicKey, bundle);

console.log(bobmessage);

const aliceShared = x3dh.digest(bobmessage!);

const alice = createDoubleRatchetSession(aliceId.secretKey, { remoteIdentityKey: bobId.publicKey, preSharedKey: aliceShared });
const bob = createDoubleRatchetSession(bobId.secretKey, { remoteKey: alice.publicKey, remoteIdentityKey: aliceId.publicKey, preSharedKey: bobshared });

const ping = bob.encrypt(decodeUTF8("Ping"));

console.log(encodeUTF8(alice.decrypt(ping!)));

const pong = alice.encrypt(decodeUTF8("Pong"));

console.log(encodeUTF8(bob.decrypt(pong!)));

