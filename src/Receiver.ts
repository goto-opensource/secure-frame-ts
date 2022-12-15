// Copyright (c) 2023 GoTo Group, Inc
// SPDX-License-Identifier: BSD 3-Clause "New" or "Revised" License

import { SFrameCrypto } from './SFrameCrypto.js';
import { checkSFrameHeaderKeyId, SFrameHeader } from './SFrameHeader.js';
import { SFrameError, SFrameErrorType } from './Types.js';

const ReplayWindow = 128;
const KeyTimeout = 1000;

export class Receiver {
    private maxReceivedCounter = -1;
    private keyring: Array<SFrameCrypto> = [];
    private scheduledKeys: WeakSet<SFrameCrypto> = new WeakSet();

    constructor(senderId: number) {
        checkSFrameHeaderKeyId(senderId);
    }

    public async decrypt(
        header: SFrameHeader,
        encryptedFrame: Uint8Array | ArrayBuffer,
        skip: number
    ) {
        let authTag: Uint8Array | ArrayBuffer | undefined = undefined;

        //conversion to UInt8Array
        const frameToBeDecrypted =
            encryptedFrame instanceof Uint8Array ? encryptedFrame : new Uint8Array(encryptedFrame);

        this.checkForReplayAttack(header);

        // if we have a key that is probably going away (key.length > 1) then we copy the keyring
        // to prevent issues when removing the key after the keyTimeout
        const keyRingSnapshot = this.keyring.length > 1 ? this.keyring.slice() : this.keyring;

        let decryptedFrame;
        for (let i = 0; i < keyRingSnapshot.length; ++i) {
            const key = keyRingSnapshot[i];
            try {
                [decryptedFrame, authTag] = await key.decrypt(header, frameToBeDecrypted, skip);
                break;
            } catch (e) {
                // nothing to do as decryption failure here is not a severe error per se
            }
        }

        if (!decryptedFrame || !authTag) {
            throw new SFrameError(SFrameErrorType.DecryptionFailure, 'Decryption failed');
        }

        // the skip denotes parts that we send in clear, thus they need to be copied into the decrypted frame
        if (skip) {
            decryptedFrame.set(frameToBeDecrypted.subarray(0, skip), 0);
        }

        //Store last received counter
        this.maxReceivedCounter = Math.max(header.counter, this.maxReceivedCounter);

        //Return decrypted payload
        return decryptedFrame;
    }

    public async setEncryptionKey(key: SFrameCrypto) {
        //Append to the keyring
        this.keyring.push(key);
        //Activate
        this.schedulePreviousKeysTimeout(key);
    }

    private checkForReplayAttack(header: SFrameHeader) {
        if (
            header.counter < this.maxReceivedCounter &&
            this.maxReceivedCounter - header.counter > ReplayWindow
        ) {
            //Error
            throw new SFrameError(
                SFrameErrorType.ReplayAttackError,
                'Replay check failed, frame counter too old'
            );
        }
    }

    private schedulePreviousKeysTimeout(key: SFrameCrypto) {
        //If this is the only key
        if (this.keyring.length == 1 && this.keyring[0] === key)
            //Do nothing
            return;
        //If has been already scheduled
        if (this.scheduledKeys.has(key))
            //Not do it twice
            return;
        //Add it
        this.scheduledKeys.add(key);
        //Schedule key timeout of previous keys
        setTimeout(() => {
            //Find key index
            const i = this.keyring.findIndex((k) => k === key);
            //Remove previous keys
            this.keyring = this.keyring.splice(i);
        }, KeyTimeout);
    }
}
