/**
 * Open Double Ratchet Algorithm
 * 
 * Copyright (C) 2025  Christian Braghette
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>
 */

import nacl, { SignKeyPair, BoxKeyPair } from "tweetnacl";
import { decodeUTF8, encodeUTF8, verifyUint8Array } from "./utils.js";
import { hkdf, hash } from "fast-sha256";

type X3DHInstance = {
    SPK: Map<string, BoxKeyPair>,
    OPK: Map<string, BoxKeyPair>
}

type X3DHExportedBundleStore = [
    SignKeyPair,
    [
        Array<[string, BoxKeyPair]>,
        Array<[string, BoxKeyPair]>
    ]
];

enum X3DHBundleType {
    HOST,
    USER
}

export class X3DHBundleStore {
    public static readonly secretIdentityKeyLength = nacl.sign.secretKeyLength;
    public static readonly publicIdentityKeyLength = nacl.sign.publicKeyLength;
    public static readonly secretKeyLength = nacl.box.secretKeyLength;
    public static readonly publicKeyLength = nacl.box.publicKeyLength;
    public static readonly signatureLength = nacl.sign.signatureLength;
    public static readonly keyLength = nacl.secretbox.keyLength;
    public static readonly hashLength = nacl.hash.hashLength;
    public static readonly maxOPK = 10;
    public static readonly hkdfInfo = decodeUTF8("X3DH");
    public static readonly version = 1;

    private signKeyPair: SignKeyPair;
    private IK: BoxKeyPair;
    private bundleStore: X3DHInstance;

    public constructor(signKeyPair: SignKeyPair, instance?: [Iterable<[string, BoxKeyPair]>, Iterable<[string, BoxKeyPair]>]) {
        this.signKeyPair = signKeyPair;
        this.IK = nacl.box.keyPair.fromSecretKey(hash(signKeyPair.secretKey));
        this.bundleStore = {
            SPK: new Map(instance ? instance[0] : []),
            OPK: new Map(instance ? instance[1] : [])
        };
    }

    public digest(publicX3DH: X3DHBundle): Uint8Array {
        if (X3DHBundle.getType(publicX3DH) !== X3DHBundleType.USER) throw new Error();
        const SPK = this.bundleStore.SPK.get(encodeUTF8(new Uint8Array(publicX3DH.buffer, publicX3DH.length - X3DHBundleStore.signatureLength - 64, 32)));
        const OPK = this.bundleStore.OPK.get(encodeUTF8(new Uint8Array(publicX3DH.buffer, publicX3DH.length - X3DHBundleStore.signatureLength - 64, 64)));
        const publicKey = new Uint8Array(publicX3DH.buffer, X3DHBundle.offset, X3DHBundleStore.publicIdentityKeyLength)
        if (!nacl.sign.detached.verify(new Uint8Array(publicX3DH.buffer, 0, publicX3DH.length - X3DHBundleStore.signatureLength), new Uint8Array(publicX3DH.buffer, publicX3DH.length - X3DHBundleStore.signatureLength), publicKey))
            throw new Error();
        const IK = new Uint8Array(publicX3DH.buffer, X3DHBundle.offset + X3DHBundleStore.publicIdentityKeyLength, X3DHBundleStore.publicKeyLength)
        const EK = new Uint8Array(publicX3DH.buffer, X3DHBundle.offset + X3DHBundleStore.publicIdentityKeyLength + X3DHBundleStore.publicKeyLength, X3DHBundleStore.publicKeyLength)
        if (!SPK || !OPK) throw new Error();
        return hkdf(new Uint8Array([
            ...nacl.scalarMult(SPK.secretKey, IK),
            ...nacl.scalarMult(this.IK.secretKey, EK),
            ...nacl.scalarMult(SPK.secretKey, EK)
        ]), nacl.scalarMult(OPK.secretKey, EK), new Uint8Array([...X3DHBundleStore.hkdfInfo, X3DHBundleStore.version]), X3DHBundleStore.keyLength);
    }

    public generate(): X3DHBundle {
        const SPK = nacl.box.keyPair();
        const OPK = new Array(X3DHBundleStore.maxOPK).fill(0).map(() => nacl.box.keyPair());
        const spkHash = hash(SPK.publicKey);
        this.bundleStore.SPK.set(encodeUTF8(spkHash), SPK);
        OPK.forEach(value => {
            this.bundleStore.OPK.set(encodeUTF8(new Uint8Array([...spkHash, ...hash(value.publicKey)])), value)
        });
        return X3DHBundle.create(this.signKeyPair.secretKey, 'HOST',
            [
                ...hash(this.signKeyPair.publicKey),
                ...this.IK.publicKey,
                ...SPK.publicKey,
                ...OPK.flatMap(value => [...value.publicKey])
            ]
        );
    }

    public export(): X3DHExportedBundleStore {
        return [
            this.IK,
            [
                Array.from(this.bundleStore.SPK.entries()),
                Array.from(this.bundleStore.OPK.entries())
            ]
        ]
    }

    public static import(input: X3DHExportedBundleStore): X3DHBundleStore {
        return new X3DHBundleStore(...input);
    }
}

/*type X3DHBundleUnpacked = {

}*/

export interface X3DHBundle extends Uint8Array { }
export namespace X3DHBundle {
    export const offset = X3DHBundleStore.hkdfInfo.length + 1;

    export function create(secretKey: Uint8Array, type: 'HOST' | 'USER', array: Iterable<number>): X3DHBundle {
        const unsigned = X3DHBundle.createUnsigned(type, array);
        return new Uint8Array([...unsigned, ...nacl.sign.detached(unsigned, secretKey)]);
    }

    /*export function unpack(bundle: Uint8Array): X3DHBundleUnpacked | undefined {
        if (!X3DHBundle.isX3DHMessage(bundle)) return undefined;
        return {

        }
    }*/

    export function createUnsigned(type: 'HOST' | 'USER', array: Iterable<number>): X3DHBundle {
        return new Uint8Array([...X3DHBundleStore.hkdfInfo, (X3DHBundleStore.version & 127) | (Number(X3DHBundleType[type]) << 7), ...array]);
    }

    export function isX3DHBundle(bundle: Uint8Array): boolean {
        return verifyUint8Array(X3DHBundleStore.hkdfInfo, new Uint8Array(bundle.buffer, 0, X3DHBundleStore.hkdfInfo.length));
    }

    export function getVersion(bundle: Uint8Array): number | undefined {
        if (!X3DHBundle.isX3DHBundle(bundle)) return undefined;
        return bundle[X3DHBundleStore.hkdfInfo.length] & 127;
    }

    export function getType(bundle: Uint8Array): X3DHBundleType | undefined {
        if (!X3DHBundle.isX3DHBundle(bundle)) return undefined;
        return (bundle[X3DHBundleStore.hkdfInfo.length] & 128) >>> 7;
    }
}

export function initX3DHBundleStore(secretKey: Uint8Array): X3DHBundleStore | undefined {
    try {
        return new X3DHBundleStore(nacl.sign.keyPair.fromSecretKey(secretKey));
    } catch (error) {
        return undefined;
    }

}

export function digestX3DHBundle(identityKey: Uint8Array, remotePublicKey: Uint8Array, publicX3DH: X3DHBundle): [Uint8Array | undefined, X3DHBundle | undefined] {
    if (X3DHBundle.getType(publicX3DH) !== X3DHBundleType.HOST) return [undefined, undefined];
    try {
        const signKeyPair = nacl.sign.keyPair.fromSecretKey(identityKey);
        const IK = nacl.box.keyPair.fromSecretKey(hash(signKeyPair.secretKey));
        const signature = publicX3DH.subarray(publicX3DH.length - X3DHBundleStore.signatureLength);
        publicX3DH = publicX3DH.subarray(0, publicX3DH.length - X3DHBundleStore.signatureLength);
        let offset = X3DHBundle.offset;
        const publicKey = publicX3DH.subarray(offset, offset += X3DHBundleStore.publicIdentityKeyLength);
        const remoteIK = publicX3DH.subarray(offset, offset += X3DHBundleStore.publicKeyLength);
        if (!verifyUint8Array(hash(remotePublicKey), publicKey) || !nacl.sign.detached.verify(publicX3DH, signature, remotePublicKey)) throw new Error();
        const EK = nacl.box.keyPair();
        const SPK = publicX3DH.subarray(offset, offset += X3DHBundleStore.publicKeyLength);
        offset += Math.floor(Math.random() * ((publicX3DH.length - offset) / X3DHBundleStore.publicKeyLength)) * X3DHBundleStore.publicKeyLength;
        const OPK = publicX3DH.subarray(offset, offset += X3DHBundleStore.publicKeyLength);
        const sharedKey = hkdf(new Uint8Array([
            ...nacl.scalarMult(IK.secretKey, SPK),
            ...nacl.scalarMult(EK.secretKey, remoteIK),
            ...nacl.scalarMult(EK.secretKey, SPK)
        ]), nacl.scalarMult(EK.secretKey, OPK), new Uint8Array([...X3DHBundleStore.hkdfInfo, X3DHBundleStore.version]), X3DHBundleStore.keyLength);
        return [
            sharedKey,
            X3DHBundle.create(signKeyPair.secretKey, 'USER',
                [
                    //...hash(signKeyPair.publicKey),
                    ...signKeyPair.publicKey,
                    ...IK.publicKey,
                    ...EK.publicKey,
                    ...hash(SPK), ...hash(OPK)
                ]
            )
        ];
    } catch (error) {
        return [undefined, undefined];
    }

}