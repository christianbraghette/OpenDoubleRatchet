import nacl from "tweetnacl";
import { createSession, decodeUTF8, encodeUTF8, digestMessage, initBundleStore } from "./index.js";

const aliceId = nacl.sign.keyPair();
const bobId = nacl.sign.keyPair();

const x3dh = initBundleStore(aliceId.secretKey)!;

const alicemessage = x3dh.generate();
console.log(alicemessage);

const [bobshared, bobmessage] = digestMessage(bobId.secretKey, aliceId.publicKey, alicemessage);

console.log(bobmessage);

const aliceShared = x3dh.digest(bobmessage!);

const alice = createSession(aliceId.secretKey, { remoteIdentityKey: bobId.publicKey, preSharedKey: aliceShared });
const bob = createSession(bobId.secretKey, { remoteKey: alice.publicKey, remoteIdentityKey: aliceId.publicKey, preSharedKey: bobshared });

const ping = bob.encrypt(decodeUTF8("Ping"));

console.log(encodeUTF8(alice.decrypt(ping!)));

const pong = alice.encrypt(decodeUTF8("Pong"));

console.log(encodeUTF8(bob.decrypt(pong!)));

