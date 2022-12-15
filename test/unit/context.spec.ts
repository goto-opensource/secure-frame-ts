// Copyright (c) 2023 GoTo Group, Inc
// SPDX-License-Identifier: BSD 3-Clause "New" or "Revised" License

import { assert } from 'chai';

import { Context } from '../../src/Context.js';
import { SerializedCryptoKey } from '../../src/Types.js';
import * as Utils from '../../src/Utils.js';
import { attachWebCryptoToGlobal } from './webcryptoHelper.js';

function sleep(ms: number) {
    return new Promise((resolve) => setTimeout(resolve, ms));
}

async function deriveKey(rawSource: string) {
    return Utils.fromHex(rawSource);
}

describe('context', () => {
    before(() => {
        attachWebCryptoToGlobal();
    });

    let shared: SerializedCryptoKey;
    let keyPair: CryptoKeyPair;
    let sender: Context;
    let receiver: Context;

    beforeEach(async () => {
        shared = await deriveKey(
            '1234567890123456789012345678901212345678901234567890123456789012'
        );
        keyPair = await window.crypto.subtle.generateKey(
            {
                name: 'ECDSA',
                namedCurve: 'P-521',
            }, //
            true,
            ['sign', 'verify']
        );

        if (!keyPair.privateKey || !keyPair.publicKey) {
            throw 'invalid keys';
        }

        sender = new Context();
        receiver = new Context();
    });

    it('cannot encrypt if no sender key is being set', async () => {
        assert.isFalse(sender.canEncrypt());
        await sender.setSenderEncryptionKey(0, shared);
        assert.isTrue(sender.canEncrypt());
    });

    it('cannot decrypt if no receiver key is being set', async () => {
        assert.isFalse(sender.canDecrypt(0));
        await sender.setReceiverEncryptionKey(0, shared);
        assert.isTrue(sender.canDecrypt(0));
    });

    it('encrypts and decrypts audio frames', async () => {
        await sender.setSenderEncryptionKey(0, shared);

        await receiver.setReceiverEncryptionKey(0, shared);

        // Should encrypt and sign
        for (let i = 0; i < 100; ++i) {
            const frame = Utils.fromHex('cacadebaca' + i);
            const encrypted = await sender.encrypt(frame, 0);
            const decrypted = await receiver.decrypt(encrypted, 0);
            assert.equal(Utils.toHex(frame), Utils.toHex(decrypted));
        }
    });

    it('encrypts and decrypts video frames', async () => {
        await sender.setSenderEncryptionKey(0, shared);

        await receiver.setReceiverEncryptionKey(0, shared);

        ///Should encrypt and sign
        for (let i = 0; i < 100; ++i) {
            const frame = Utils.fromHex('cacadebaca' + i);
            const encrypted = await sender.encrypt(frame, 0);
            const decrypted = await receiver.decrypt(encrypted, 0);
            assert.equal(Utils.toHex(frame), Utils.toHex(decrypted));
        }
    });

    it('encrypts and decrypts video frames with skip', async () => {
        await sender.setSenderEncryptionKey(0, shared);

        await receiver.setReceiverEncryptionKey(0, shared);

        ///Should encrypt and sign
        for (let i = 0; i < 100; ++i) {
            const frame = Utils.fromHex('deadbeafcacadebaca' + i);
            const encrypted = await sender.encrypt(frame, 4);
            const decrypted = await receiver.decrypt(encrypted, 4);
            assert.equal(Utils.toHex(frame), Utils.toHex(decrypted));
        }
    });

    it('encrypts and decrypts with two senders and one receiver', async () => {
        const shared1 = await deriveKey(
            '1234567890123456789012345678901212345678901234567890123456789012'
        );
        const shared2 = await deriveKey(
            '2222222222222222222222222222222212345678901234567890123456789012'
        );

        const receiver = new Context();
        const sender1 = new Context();
        const sender2 = new Context();

        await sender1.setSenderEncryptionKey(1, shared1);
        await sender2.setSenderEncryptionKey(2, shared2);

        await receiver.setReceiverEncryptionKey(1, shared1);
        await receiver.setReceiverEncryptionKey(2, shared2);

        const frame1 = Utils.fromHex('cacadebaca1');
        const encrypted1 = await sender1.encrypt(frame1, 0);
        const decrypted1 = await receiver.decrypt(encrypted1, 0);
        assert.equal(Utils.toHex(frame1), Utils.toHex(decrypted1));

        const frame2 = Utils.fromHex('cacadebaca2');
        const encrypted2 = await sender2.encrypt(frame2, 0);
        const decrypted2 = await receiver.decrypt(encrypted2, 0);
        assert.equal(Utils.toHex(frame2), Utils.toHex(decrypted2));
    });

    it('two senders 1 receiver - wrong key', async () => {
        const shared1 = await deriveKey(
            '1234567890123456789012345678901212345678901234567890123456789012'
        );
        const shared2 = await deriveKey(
            '2222222222222222222222222222222212345678901234567890123456789012'
        );

        const receiver = new Context();
        const sender1 = new Context();
        const sender2 = new Context();

        await sender1.setSenderEncryptionKey(1, shared1);
        await sender2.setSenderEncryptionKey(2, shared2);

        //We exchange the keys to force fail
        await receiver.setReceiverEncryptionKey(1, shared2);
        await receiver.setReceiverEncryptionKey(2, shared1);

        const frame1 = Utils.fromHex('cacadebaca1');
        const encrypted1 = await sender1.encrypt(frame1, 0);
        try {
            await receiver.decrypt(encrypted1, 0);
            assert(false);
        } catch (e) {
            assert(true);
        }

        const frame2 = Utils.fromHex('cacadebaca2');
        const encrypted2 = await sender2.encrypt(frame2, 0);
        try {
            await receiver.decrypt(encrypted2, 0);
            assert(false);
        } catch (e) {
            assert(true);
        }
    });

    it('Replay attack', async () => {
        await sender.setSenderEncryptionKey(0, shared);

        await receiver.setReceiverEncryptionKey(0, shared);

        const ordered = [];
        ///Should encrypt and sign
        for (let i = 0; i < 200; ++i) {
            const frame = Utils.fromHex('deadbeafcacadebaca' + i);
            const encrypted = await sender.encrypt(frame, 4);
            ordered.push(encrypted);
        }

        for (let i = 200; i > 0; --i) {
            try {
                //Decrypt
                await receiver.decrypt(ordered[i - 1], 4);
                //Should work for the first 128
                assert(i >= 200 - 128);
            } catch (e) {
                //Should fail for the rest
                assert(i < 200 - 128);
            }
        }
    });

    it('Allow duplicate frames', async () => {
        await sender.setSenderEncryptionKey(0, shared);

        await receiver.setReceiverEncryptionKey(0, shared);

        const frame = Utils.fromHex('cacadebaca');
        const encrypted = await sender.encrypt(frame, 0);
        const decrypted1 = await receiver.decrypt(encrypted, 0);
        const decrypted2 = await receiver.decrypt(encrypted, 0);
        assert.equal(Utils.toHex(frame), Utils.toHex(decrypted1));
        assert.equal(Utils.toHex(frame), Utils.toHex(decrypted2));
    });

    it('Update key', async () => {
        await sender.setSenderEncryptionKey(0, shared);
        await receiver.setReceiverEncryptionKey(0, shared);

        for (let i = 1; i < 10; i++) {
            const frame = Utils.fromHex('cacadebaca' + i);
            const encrypted = await sender.encrypt(frame, 0);
            const decrypted = await receiver.decrypt(encrypted, 0);
            assert.equal(Utils.toHex(frame), Utils.toHex(decrypted));

            //Update key
            const updated = await deriveKey(
                '123456789012345678901234567890121234567890123456789012345678901' + i
            );
            await sender.setSenderEncryptionKey(0, updated);
            await receiver.setReceiverEncryptionKey(0, updated);
        }
    });

    it('key timeout on new key setup', async () => {
        const shared = await deriveKey(
            '1234567890123456789012345678901212345678901234567890123456789010'
        );
        const updated = await deriveKey(
            '1234567890123456789012345678901212345678901234567890123456789011'
        );

        await sender.setSenderEncryptionKey(0, shared);
        //Set both keys on receiver
        await receiver.setReceiverEncryptionKey(0, shared);
        await receiver.setReceiverEncryptionKey(0, updated);
        const frame1 = Utils.fromHex('cacadebaca1');
        const frame2 = Utils.fromHex('cacadebaca2');

        //Encrypt first one with shared
        const encrypted1 = await sender.encrypt(frame1, 0);

        //Encrypte second one with updated
        await sender.setSenderEncryptionKey(0, updated);
        const encrypted2 = await sender.encrypt(frame2, 0);

        //Both should work now
        const decrypted1 = await receiver.decrypt(encrypted1, 0);
        const decrypted2 = await receiver.decrypt(encrypted2, 0);
        assert.equal(Utils.toHex(frame1), Utils.toHex(decrypted1));
        assert.equal(Utils.toHex(frame2), Utils.toHex(decrypted2));

        //Wait for timeout
        await sleep(1000);

        try {
            //Decrypt frame with expeired key
            await receiver.decrypt(encrypted1, 0);
            //Should have failed
            assert(false);
        } catch (e) {
            //Should fail
            assert(true);
        }
    });
});
