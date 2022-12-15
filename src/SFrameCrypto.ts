// Copyright (c) 2023 GoTo Group, Inc
// SPDX-License-Identifier: BSD 3-Clause "New" or "Revised" License

import { SerializedCryptoKey } from './Types.js';
import { generateIV } from './IV.js';
import { SFrameHeader } from './SFrameHeader.js';
import { CipherSuite, CipherSuiteVariant, createCipherSuite } from './CipherSuite.js';
import { SFrameError, SFrameErrorType } from './Types.js';

export class SFrameCrypto {
    constructor(private readonly cipherSuite: CipherSuite) {}

    public async encrypt(header: SFrameHeader, payload: BufferSource, skip = 0) {
        const iv = generateIV(header.rawCounter, this.cipherSuite.saltKey);

        // step 1: encrypt
        const encrypted = await crypto.subtle.encrypt(
            {
                name: this.cipherSuite.config.algorithm,
                iv: iv,
                length: this.cipherSuite.config.nK * 8, // bits
                additionalData: header.data,
            },
            this.cipherSuite.encryptionKey,
            payload
        );

        const authTagLength = this.cipherSuite.config.nT;
        const frameSize = header.data.byteLength + encrypted.byteLength + authTagLength + skip;
        const encryptedFrame = new Uint8Array(frameSize);

        try {
            encryptedFrame.set(header.data, skip);
            encryptedFrame.set(new Uint8Array(encrypted), skip + header.data.byteLength);
        } catch (error: unknown) {
            const message = error instanceof Error ? error.message : '';
            throw new SFrameError(
                SFrameErrorType.EncryptionFailure,
                'encrypt: encryptedFrame.set: ' + message
            );
        }

        // step 2: calculate AuthTag and append to encrypted payload
        const authCode = new Uint8Array(
            await crypto.subtle.sign(
                'HMAC',
                this.cipherSuite.authKey,
                encryptedFrame.subarray(skip, skip + header.data.byteLength + encrypted.byteLength)
            )
        );

        try {
            const authTag = authCode.subarray(0, authTagLength);
            encryptedFrame.set(authTag, skip + encrypted.byteLength + header.data.byteLength);
            return [encryptedFrame, authTag];
        } catch (error: unknown) {
            const message = error instanceof Error ? error.message : '';
            throw new SFrameError(
                SFrameErrorType.AuthenticationError,
                'encrypt: authTag: ' + message
            );
        }
    }

    public async decrypt(header: SFrameHeader, encryptedFrame: Uint8Array, skip = 0) {
        // step 1: verify authentication by calculating authTag from encrypted payload
        const iv = generateIV(header.rawCounter, this.cipherSuite.saltKey);
        const authTagLength = this.cipherSuite.config.nT;
        const frameLength = encryptedFrame.byteLength - skip;

        const authTag = encryptedFrame.subarray(
            skip + frameLength - authTagLength,
            skip + frameLength
        );

        const encryptedPayload = encryptedFrame.subarray(
            skip + header.data.byteLength,
            skip + frameLength - authTagLength
        );
        const authCode = new Uint8Array(
            await crypto.subtle.sign(
                'HMAC',
                this.cipherSuite.authKey,
                encryptedFrame.subarray(
                    skip,
                    skip + header.data.byteLength + encryptedPayload.byteLength
                )
            )
        );

        let authenticated = true;
        // Avoid timimg attacks by iterating over all bytes
        for (let i = 0; i < authTagLength; ++i) {
            authenticated = authenticated && authTag[i] === authCode[i];
        }

        if (!authenticated) {
            throw new Error('Authentication error');
        }

        // step 2: decrypt payload
        const payload = new Uint8Array(
            await crypto.subtle.decrypt(
                {
                    name: this.cipherSuite.config.algorithm,
                    iv: iv,
                    length: this.cipherSuite.config.nK * 8, // bits
                    additionalData: header.data,
                },
                this.cipherSuite.encryptionKey,
                encryptedPayload
            )
        );

        return [payload, authTag];
    }
}

/**
 * @param variant Use AES_GCM_256_SHA512 for max security in this setup
 */
export async function createSFrameCrypto(
    rawKey: SerializedCryptoKey,
    variant: CipherSuiteVariant = CipherSuiteVariant.AES_GCM_256_SHA512
): Promise<SFrameCrypto> {
    const cipherSuite = await createCipherSuite(variant, rawKey);
    const key = new SFrameCrypto(cipherSuite);
    return key;
}
