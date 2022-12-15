// Copyright (c) 2023 GoTo Group, Inc
// SPDX-License-Identifier: BSD 3-Clause "New" or "Revised" License

import { SFrameCrypto } from './SFrameCrypto.js';
import { checkSFrameHeaderKeyId, generateSFrameHeader } from './SFrameHeader.js';
import { SFrameError, SFrameErrorType } from './Types.js';

export class Sender {
    private counter = 0;
    private key?: SFrameCrypto;

    constructor(private senderId: number) {
        checkSFrameHeaderKeyId(senderId);
    }

    public async encrypt(payloadToBeEncrypted: Uint8Array, skip = 0) {
        if (!this.key) {
            throw new SFrameError(SFrameErrorType.InvalidKey, 'Encryption key not set');
        }

        const counter = this.counter++;
        const header = generateSFrameHeader(this.senderId, counter);
        const [encryptedFrame] = await this.key.encrypt(header, payloadToBeEncrypted, skip);

        // copy part of payload that is not encrypted
        if (skip) {
            encryptedFrame.set(payloadToBeEncrypted.subarray(0, skip), 0);
        }
        return encryptedFrame;
    }

    public setSenderId(senderId: number) {
        checkSFrameHeaderKeyId(senderId);
        this.senderId = senderId;
    }

    public async setEncryptionKey(key: SFrameCrypto) {
        this.key = key;
    }
}
