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
/**
 * Decodes a Uint8Array into a UTF-8 string.
 *
 * @param array - The input byte array.
 * @returns The UTF-8 encoded string.
 */
export declare function encodeUTF8(array?: Uint8Array): string;
/**
 * Encodes a UTF-8 string into a Uint8Array.
 *
 * @param string - The input string.
 * @returns The resulting Uint8Array.
 */
export declare function decodeUTF8(string?: string): Uint8Array;
/**
 * Encodes a Uint8Array into a Base64 string.
 *
 * @param array - The input byte array.
 * @returns The Base64 encoded string.
 */
export declare function encodeBase64(array?: Uint8Array): string;
/**
 * Decodes a Base64 string into a Uint8Array.
 *
 * @param string - The Base64 string.
 * @returns The decoded Uint8Array.
 */
export declare function decodeBase64(string?: string): Uint8Array;
/**
 * Converts a Uint8Array into a number (little-endian).
 *
 * @param array - The input byte array.
 * @returns The resulting number.
 */
export declare function numberFromUint8Array(array?: Uint8Array): number;
/**
 * Converts a number into a Uint8Array of specified length (little-endian).
 *
 * @param number - The number to convert.
 * @param length - The desired output length.
 * @returns A Uint8Array representing the number.
 */
export declare function numberToUint8Array(number?: number, length?: number): Uint8Array;
/**
 * Creates a new DoubleRatchetSession instance.
 *
 * @param remoteKey - The public key of the remote peer (optional).
 * @returns A new DoubleRatchetSession.
 */
export declare function createDoubleRatchetSession(remoteKey?: Uint8Array): DoubleRatchetSession;
/**
 * Represents a secure Double Ratchet session.
 * Used for forward-secure encryption and decryption of messages.
 */
export interface DoubleRatchetSession {
    /**
     * Whether both the sending and receiving chains are initialized.
     */
    readonly handshaked: boolean;
    /**
     * The public key of this session.
     */
    readonly publicKey: Uint8Array;
    /**
     * The last known remote public key.
     */
    readonly remoteKey: Uint8Array | undefined;
    /**
     * Encrypts a message payload using the current sending chain.
     *
     * @param payload - The message as a Uint8Array.
     * @returns An EncryptedPayload or undefined if encryption fails.
     */
    encrypt(payload: Uint8Array): EncryptedPayload | undefined;
    /**
     * Decrypts an encrypted message.
     *
     * @param payload - The received encrypted message.
     * @returns The decrypted message as a Uint8Array, or undefined if decryption fails.
     */
    decrypt(payload: Uint8Array | EncryptedPayload): Uint8Array | undefined;
}
export declare class DoubleRatchetSession {
    constructor(remoteKey?: Uint8Array);
    /**
     * The fixed key length (in bytes) used throughout the Double Ratchet session.
     * Typically 32 bytes (256 bits) for symmetric keys.
     */
    static readonly keyLength = 32;
}
/**
 * Interface representing an encrypted payload.
 * Provides metadata and de/serialization methods.
 */
export interface EncryptedPayload extends Uint8Array {
    /**
     * The current message count of the sending chain.
     */
    readonly count: number;
    /**
     * The count of the previous sending chain.
     */
    readonly previous: number;
    /**
     * The sender's public key used for this message.
     */
    readonly publicKey: Uint8Array;
    /**
     * The nonce used during encryption.
     */
    readonly nonce: Uint8Array;
    /**
     * The encrypted message content.
     */
    readonly ciphertext: Uint8Array;
    /**
     * Serializes the payload into a Uint8Array for transport.
     */
    encode(): Uint8Array;
    /**
     * Decodes the payload into a readable object format.
     */
    decode(): {
        count: number;
        previus: number;
        publicKey: string;
        nonce: string;
        ciphertext: string;
        signature?: string;
    };
    /**
     * Returns the payload as a UTF-8 string.
     */
    toString(): string;
    /**
     * Returns the decoded object as a JSON string.
     */
    toJSON(): string;
}
export declare class EncryptedPayload implements EncryptedPayload {
    /**
     * Static factory method that constructs an `EncryptedPayload` from a raw Uint8Array.
     *
     * @param array - A previously serialized encrypted payload.
     * @returns An instance of `EncryptedPayload`.
     */
    static from(array: Uint8Array): EncryptedPayload;
}
