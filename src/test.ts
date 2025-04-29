import { createDoubleRatchetSession, decodeUTF8, encodeUTF8 } from "./index.js";

const alice = createDoubleRatchetSession();
const bob = createDoubleRatchetSession(alice.publicKey);

const ping = bob.encrypt(decodeUTF8("Ping"));

console.log(ping?.decode())

console.log(encodeUTF8(alice.decrypt(ping!)));

//const pong = alice.encrypt(decodeUTF8("Pong"), aliceSign.secretKey);

//console.log(encodeUTF8(bob.decrypt(pong!, aliceSign.publicKey)));
