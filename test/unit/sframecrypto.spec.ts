// Copyright (c) 2023 GoTo Group, Inc
// SPDX-License-Identifier: BSD 3-Clause "New" or "Revised" License

import { assert } from 'chai';
import { CipherSuiteVariant, createCipherSuite } from '../../src/CipherSuite.js';
import { createSFrameCrypto, SFrameCrypto } from '../../src/SFrameCrypto.js';
import { parseSFrameHeader } from '../../src/SFrameHeader.js';

import * as Utils from '../../src/Utils.js';

import { attachWebCryptoToGlobal } from './webcryptoHelper.js';

// Source for the test vectors: https://github.com/eomara/sframe/blob/master/test-vectors.json
describe('SFrameCrypto', async () => {
    before(() => {
        attachWebCryptoToGlobal();
    });

    describe('draft 0.3: basic key derivation', async () => {
        const testKeyDerivation = async (
            variant: CipherSuiteVariant,
            keyMaterial: string,
            expectedSaltKey: string,
            expectedEncryptionKey: string
        ) => {
            const cipherSuite = await createCipherSuite(variant, Utils.fromHex(keyMaterial));

            const encryptionKey = await cipherSuite.deriveEncryptionKeyBits();
            const saltKey = await cipherSuite.deriveSaltBits();
            assert.equal(Utils.toHex(encryptionKey), expectedEncryptionKey);
            assert.equal(Utils.toHex(saltKey), expectedSaltKey);
        };

        it('AES_CM_128_HMAC_SHA256_4', async () => {
            testKeyDerivation(
                CipherSuiteVariant.AES_CM_128_HMAC_SHA256_4,
                '101112131415161718191a1b1c1d1e1f',
                '343d3290f5c0b936415bea9a43c6f5a2',
                '42d662fbad5cd81eb3aad79a'
            );
        });

        it('AES_CM_128_HMAC_SHA256_8', async () => {
            testKeyDerivation(
                CipherSuiteVariant.AES_CM_128_HMAC_SHA256_8,
                '202122232425262728292a2b2c2d2e2f',
                '3fce747d505e46ec9b92d9f58ee7a5d4',
                '77fbf5f1d82c73f6d2b353c9'
            );
        });

        it('AES_GCM_128_SHA256', async () => {
            testKeyDerivation(
                CipherSuiteVariant.AES_GCM_128_SHA256,
                '303132333435363738393a3b3c3d3e3f',
                '2ea2e8163ff56c0613e6fa9f20a213da',
                'a80478b3f6fba19983d540d5'
            );
        });

        it('AES_GCM_256_SHA512', async () => {
            testKeyDerivation(
                CipherSuiteVariant.AES_GCM_128_SHA256,
                '404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f',
                '436774b0b5ae45633d96547f8f3cb06c8e6628eff2e4255b5c4d77e721aa3355',
                '31ed26f90a072e6aee646298'
            );
        });
    });

    describe('test vectors of draft 0.3: encrypt/decrypt', async () => {
        const initializeTestHarness = (sframeCrypto: SFrameCrypto, plainText: Uint8Array) => {
            return async (header: string, expectedCipherTextAsString: string) => {
                const sframeHeader = parseSFrameHeader(Utils.fromHex(header));
                const cipherText = await sframeCrypto.encrypt(sframeHeader, plainText, 0);
                const expectedCipherText = Utils.fromHex(expectedCipherTextAsString);

                const decrypted = await sframeCrypto.decrypt(sframeHeader, cipherText[0], 0);

                assert.equal(
                    Utils.toHex(cipherText[0].slice(0, expectedCipherText.length)),
                    Utils.toHex(expectedCipherText)
                );
                assert.equal(Utils.toHex(decrypted[0]), Utils.toHex(plainText));
            };
        };
        const initVectorTest = async (
            baseKey: Uint8Array,
            plainText: Uint8Array,
            cipherSuiteVariant: CipherSuiteVariant
        ) => {
            const sframeCrypto = await createSFrameCrypto(baseKey, cipherSuiteVariant);
            const test = initializeTestHarness(sframeCrypto, plainText);
            return test;
        };

        // TODO: not supported by webcrypto
        it.skip('AES_CM_128_HMAC_SHA256_4', async () => {
            const baseKey = Utils.fromHex('101112131415161718191a1b1c1d1e1f');
            const plainText = Utils.fromHex(
                '46726f6d2068656176656e6c79206861726d6f6e79202f2f205468697320756e6976657273616c206672616d6520626567616e'
            );

            const sframeCrypto = await createSFrameCrypto(
                baseKey,
                CipherSuiteVariant.AES_CM_128_HMAC_SHA256_4
            );
            const test = initializeTestHarness(sframeCrypto, plainText);

            await test(
                '1700',
                '170065c67c6fb784631a7db1b589ffb62d75b78e28b0899e632fbbee3b944747a6382d75b6bd3788dc7b71b9295c7fb90b5098f7add14ef329'
            );
            await test(
                '1701',
                '170103bbafa34ada8a6b9f2066bc34a1959d87384c9f4b1ce34fed58e938bde143393910b1aeb55b48d91d5b0db3ea67e3d0e02b843afd41630c940b1948e72dd45396a43a'
            );
            await test(
                '1702',
                '170258d58adebd8bf6f3cc0c1fcacf34ba4d7a763b2683fe302a57f1be7f2a274bf81b2236995fec1203cadb146cd402e1c52d5e6a10989dfe0f4116da1ee4c2fad0d21f8f'
            );
            await test(
                '190faa',
                '190faad0b1743bf5248f90869c9456366d55724d16bbe08060875815565e90b114f9ccbdba192422b33848a1ae1e3bd266a001b2f5bb727112772e0072ea8679ca1850cf11d8'
            );
            await test(
                '1a01ffaa',
                '1a01ffaad0b1743bf5248f90869c9456366d55724d16bbe08060875815565e90b114f9ccbdba192422b33848a1ae1e3bd266a001b2f5bbc9c63bd3973c19bd57127f565380ed4a'
            );
            await test(
                '2a01ffaaaa',
                '2a01ffaaaa9de65e21e4f1ca2247b87943c03c5cb7b182090e93d508dcfb76e08174c6397356e682d2eaddabc0b3c1018d2c13c3570f61c1beaab805f27b565e1329a823a7a649b6'
            );
            await test(
                '7fffffffffffffffffffffffffffff',
                '7fffffffffffffffffffffffffffff09981bdcdad80e380b6f74cf6afdbce946839bedadd57578bfcd809dbcea535546cc24660613d2761adea852155785011e633534f4ecc3b8257c8d34321c27854a1422'
            );
        });

        // TODO: not supported by webcrypto
        it.skip('AES_CM_128_HMAC_SHA256_8', async () => {
            const baseKey = Utils.fromHex('202122232425262728292a2b2c2d2e2f');
            const plainText = Utils.fromHex(
                '46726f6d2068656176656e6c79206861726d6f6e79202f2f205468697320756e6976657273616c206672616d6520626567616e'
            );

            const sframeCrypto = await createSFrameCrypto(
                baseKey,
                CipherSuiteVariant.AES_CM_128_HMAC_SHA256_4
            );
            const test = initializeTestHarness(sframeCrypto, plainText);

            await test(
                '1700',
                '1700647513fce71aab7fed1e904fd9240343d77092c831f0d58fde0985a0f3e5ba4020e87a7b9c870b5f8f7f628d27690cc1e571e4d391da5fbf428433'
            );
            await test(
                '1701',
                '17019e1bdf713b0d4c02f3dbf50a72ea773286e7da38f3872cc734f3e1b1448aab5009b424e05495214f96d02e4e8f8da975cc808f40f67cafead7cffd'
            );
            await test(
                '1702',
                '170220ad36fd9191453ace2d36a175ad8a69c1f16b8613d14b4f7ef30c68bc5609e349df38155cc1544d7dbfa079e3faae3c7883b448e75047caafe05b'
            );
            await test(
                '190faa',
                '190faadab9b284a4b9e3aea36b9cdcae4a58e141d3f0f52f240ef80a93dbb8d809ede01b05b2cace18a22fb39c032724481c5baa181d6b793458355b0f30'
            );
            await test(
                '1a01ffaa',
                '1a01ffaadab9b284a4b9e3aea36b9cdcae4a58e141d3f0f52f240ef80a93dbb8d809ede01b05b2cace18a22fb39c032724481c5baa181dad5ad0f89a1cfb58'
            );
            await test(
                '2a01ffaaaa',
                '2a01ffaaaae0f2384e4dc472cb92238b5b722159205c4481665484de66985f155071655ca4e9d1c998781f8c7d439f8d1eb6f6071cd80fd22f7e8846ba91036a'
            );
            await test(
                '7fffffffffffffffffffffffffffff',
                '7fffffffffffffffffffffffffffff4b8c7429d7ee83eec5e53808b80555b1f80b1df9d97877575fa1c7fa35b6119c68ed6543020075959dcc4ca6900a7f9cf1d936b640bba41ca62f6c'
            );
        });

        describe('AES_GCM_128_SHA256', () => {
            const baseKey = Utils.fromHex('303132333435363738393a3b3c3d3e3f');
            const plainText = Utils.fromHex(
                '46726f6d2068656176656e6c79206861726d6f6e79202f2f205468697320756e6976657273616c206672616d6520626567616e'
            );
            const cipherSuiteVariant = CipherSuiteVariant.AES_GCM_128_SHA256;

            it('basic key', async () => {
                const test = await initVectorTest(baseKey, plainText, cipherSuiteVariant);

                await test(
                    '1700',
                    '17000e426255e47ed70dd7d15d69d759bf459032ca15f5e8b2a91e7d348aa7c186d403f620801c495b1717a35097411aa97cbb140671eb3b49ac3775926db74d57b91e8e6c'
                );
                await test(
                    '1701',
                    '170103bbafa34ada8a6b9f2066bc34a1959d87384c9f4b1ce34fed58e938bde143393910b1aeb55b48d91d5b0db3ea67e3d0e02b843afd41630c940b1948e72dd45396a43a'
                );
                await test(
                    '1702',
                    '170258d58adebd8bf6f3cc0c1fcacf34ba4d7a763b2683fe302a57f1be7f2a274bf81b2236995fec1203cadb146cd402e1c52d5e6a10989dfe0f4116da1ee4c2fad0d21f8f'
                );
            });
            // These test vectors are for an older draft.
            // Changing const lengthAdjustment = 0 in the SFrame header (according to older draft) makes this work.
            it.skip('extended key', async () => {
                const test = await initVectorTest(baseKey, plainText, cipherSuiteVariant);

                await test(
                    '190faa',
                    '190faad0b1743bf5248f90869c9456366d55724d16bbe08060875815565e90b114f9ccbdba192422b33848a1ae1e3bd266a001b2f5bb727112772e0072ea8679ca1850cf11d8'
                );
                await test(
                    '1a01ffaa',
                    '1a01ffaad0b1743bf5248f90869c9456366d55724d16bbe08060875815565e90b114f9ccbdba192422b33848a1ae1e3bd266a001b2f5bbc9c63bd3973c19bd57127f565380ed4a'
                );
                await test(
                    '2a01ffaaaa',
                    '2a01ffaaaa9de65e21e4f1ca2247b87943c03c5cb7b182090e93d508dcfb76e08174c6397356e682d2eaddabc0b3c1018d2c13c3570f61c1beaab805f27b565e1329a823a7a649b6'
                );
                await test(
                    '7fffffffffffffffffffffffffffff',
                    '7fffffffffffffffffffffffffffff09981bdcdad80e380b6f74cf6afdbce946839bedadd57578bfcd809dbcea535546cc24660613d2761adea852155785011e633534f4ecc3b8257c8d34321c27854a1422'
                );
            });
        });

        describe('AES_GCM_256_SHA512', () => {
            const baseKey = Utils.fromHex(
                '404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f'
            );
            const plainText = Utils.fromHex(
                '46726f6d2068656176656e6c79206861726d6f6e79202f2f205468697320756e6976657273616c206672616d6520626567616e'
            );
            const cipherSuiteVariant = CipherSuiteVariant.AES_GCM_256_SHA512;

            it('basic key', async () => {
                const test = await initVectorTest(baseKey, plainText, cipherSuiteVariant);

                await test(
                    '1700',
                    '1700f3e297c1e95207710bd31ccc4ba396fbef7b257440bde638ff0f3c8911540136df61b26220249d6c432c245ae8d55ef45bfccf32530a15aeaaf313a03838e51bd45652'
                );
                await test(
                    '1701',
                    '170193268b0bf030071bff443bb6b4471bdfb1cc81bc9625f4697b0336ff4665d15f152f02169448d8a967fb06359a87d2145398de0ce3fbe257b0992a3da1537590459f3c'
                );
                await test(
                    '1702',
                    '1702649691ba27c4c01a41280fba4657c03fa7fe21c8f5c862e9094227c3ca3ec0d9468b1a2cb060ff0978f25a24e6b106f5a6e1053c1b8f5fce794d88a0e4818c081e18ea'
                );
            });
            // These test vectors are for an older draft.
            // Changing const lengthAdjustment = 0 in the SFrame header (according to older draft) makes this work.
            it.skip('extended key', async () => {
                const test = await initVectorTest(baseKey, plainText, cipherSuiteVariant);

                await test(
                    '190faa',
                    '190faa2858c10b5ddd231c1f26819490521678603a050448d563c503b1fd890d02ead01d754f074ecb6f32da9b2f3859f380b4f47d4edd1e15f42f9a2d7ecfac99067e238321'
                );
                await test(
                    '1a01ffaa',
                    '1a01ffaa2858c10b5ddd231c1f26819490521678603a050448d563c503b1fd890d02ead01d754f074ecb6f32da9b2f3859f380b4f47d4e3bf7040eb10ec25b8126b2ce7b1d9d31'
                );
                await test(
                    '2a01ffaaaa',
                    '2a01ffaaaad9bc6a258a07d210a814d545eca70321c0e87498ada6e5c708b7ead162ffcf4fbaba1eb82650590a87122b4d95fe36bd88b278812166d26e046ed0a530b7ee232ee0f2'
                );
                await test(
                    '7fffffffffffffffffffffffffffff',
                    '7fffffffffffffffffffffffffffffaf480d4779ce0c02b5137ee6a61e026c04ac999cb0c97319feceeb258d58df23bce14979e5c67a431777b34498062e72f939ca42ec84ffbc7b50eff923f515a2df760c'
                );
            });
        });
    });
});
