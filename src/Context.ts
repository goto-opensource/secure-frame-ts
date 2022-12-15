// Copyright (c) 2023 GoTo Group, Inc
// SPDX-License-Identifier: BSD 3-Clause "New" or "Revised" License

import { Receiver } from './Receiver.js';
import { Sender } from './Sender.js';
import { parseSFrameHeader } from './SFrameHeader.js';
import { createSFrameCrypto } from './SFrameCrypto.js';
import { MediaFrame, SerializedCryptoKey, SFrameError, SFrameErrorType } from './Types.js';

export class Context {
    private sender?: Sender;
    private receivers: Map<number, Receiver> = new Map();

    public async setSenderEncryptionKey(senderId: number, key: SerializedCryptoKey) {
        if (!this.sender) {
            this.sender = new Sender(senderId);
        } else {
            this.sender.setSenderId(senderId);
        }
        const encryptionKey = await createSFrameCrypto(key);
        return this.sender.setEncryptionKey(encryptionKey);
    }

    public async setReceiverEncryptionKey(receiverKeyId: number, key: SerializedCryptoKey) {
        let receiver = this.receivers.get(receiverKeyId);
        if (!receiver) {
            receiver = new Receiver(receiverKeyId);
            this.receivers.set(receiverKeyId, receiver);
        }

        const receiverKey = await createSFrameCrypto(key);
        return receiver.setEncryptionKey(receiverKey);
    }

    public deleteReceiver(receiverKeyId: number) {
        return this.receivers.delete(receiverKeyId);
    }

    public canEncrypt() {
        return !!this.sender;
    }

    public async encryptFrame(frame: MediaFrame) {
        return this.encrypt(frame.data, frame.headerLength);
    }

    public async encrypt(frame: Uint8Array, skip: number) {
        if (!this.sender) {
            throw new SFrameError(SFrameErrorType.EncryptionFailure, 'No sender set');
        }
        return this.sender.encrypt(frame, skip);
    }

    public readKeyId(frame: MediaFrame) {
        const header = parseSFrameHeader(frame.data.subarray(frame.headerLength));
        return header.keyId;
    }

    public canDecrypt(receiverKeyId: number) {
        return this.receivers.has(receiverKeyId);
    }

    public async decryptFrame(frame: MediaFrame) {
        return this.decrypt(frame.data, frame.headerLength);
    }

    public async decrypt(encryptedFrame: Uint8Array, skip: number) {
        const header = parseSFrameHeader(encryptedFrame.subarray(skip));
        const receiver = this.receivers.get(header.keyId);

        if (!receiver) {
            throw new SFrameError(
                SFrameErrorType.InvalidKey,
                'No receiver found for keyId ' + header.keyId
            );
        }

        return receiver.decrypt(header, encryptedFrame, skip);
    }
}
