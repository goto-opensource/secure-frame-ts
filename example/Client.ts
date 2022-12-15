// Copyright (c) 2023 GoTo Group, Inc
// SPDX-License-Identifier: BSD 3-Clause "New" or "Revised" License

import * as Comlink from 'comlink';

import Base64Worker from './Base64Worker.js';
import { LogLevel, LogMessage } from './SFrameLogger.js';
import { SFrameWorker } from './Worker.js';
import { Logger, MediaType, SerializedCryptoKey, SFrameError } from '../src/index.js';

// Caches the worker blob url once.
//
// Note that you want to set this lazily since Node.js would complain about Blob and createObjectURL.
let workerBlobUrl: URL | string = '';

function getWorkerBlobUrl() {
    if (!workerBlobUrl) {
        const blob = new Blob([atob(Base64Worker)], {
            type: 'application/javascript',
        });
        workerBlobUrl = URL.createObjectURL(blob);
    }
    return workerBlobUrl;
}

async function transferKey(key: SerializedCryptoKey | CryptoKey): Promise<SerializedCryptoKey> {
    if (key instanceof CryptoKey) {
        const keyType = key.type === 'private' ? 'pkcs8' : 'raw';
        return crypto.subtle.exportKey(keyType, key as CryptoKey);
    } else {
        return (key as ArrayBuffer).slice(0);
    }
}

export type SFrameClientConfig = {
    mediaType: MediaType;
    signalError: (error: Error) => void;
    logger?: Logger;
};

export interface SFrameClient {
    decrypt(receiver: RTCRtpReceiver, mediaType: MediaType): Promise<void>;
    encrypt(sender: RTCRtpSender, mediaType: MediaType): Promise<void>;
    setSenderEncryptionKey(
        senderKeyId: number,
        key: SerializedCryptoKey | CryptoKey
    ): Promise<void>;
    setReceiverEncryptionKey(
        receiverKeyId: number,
        key: SerializedCryptoKey | CryptoKey
    ): Promise<void>;
    deleteReceiver(receiverKeyId: number): Promise<boolean>;
    close(): void;
}

class SFrameClientImpl implements SFrameClient {
    private encryptedSenders: Array<RTCRtpSender> = [];
    private decryptedReceivers: Array<RTCRtpReceiver> = [];
    private logger: Logger;

    constructor(
        private clientConfig: SFrameClientConfig,
        private worker: Comlink.Remote<SFrameWorker>
    ) {
        if (clientConfig.logger) {
            this.logger = clientConfig.logger;
        } else {
            this.logger = console;
        }

        const loggerCallback = (log: LogMessage) => {
            switch (log.level) {
                case LogLevel.DEBUG:
                    this.logger.debug(log.message);
                    break;
                case LogLevel.INFO:
                    this.logger.info(log.message);
                    break;
                case LogLevel.LOG:
                    this.logger.log(log.message);
                    break;
                case LogLevel.WARN:
                    this.logger.log(log.message);
                    break;
                case LogLevel.ERROR:
                case LogLevel.FATAL:
                    this.logger.error(log.message);
                    this.clientConfig.signalError(new SFrameError(log.type, log.message));
                    break;
            }
        };

        this.worker.setLoggerCallback(Comlink.proxy(loggerCallback));
    }

    public async setSenderEncryptionKey(
        senderKeyId: number,
        key: SerializedCryptoKey | CryptoKey
    ): Promise<void> {
        return this.worker.setSenderEncryptionKey(senderKeyId, await transferKey(key));
    }

    public async setReceiverEncryptionKey(
        receiverKeyId: number,
        key: SerializedCryptoKey | CryptoKey
    ): Promise<void> {
        return this.worker.setReceiverEncryptionKey(receiverKeyId, await transferKey(key));
    }

    public async deleteReceiver(receiverKeyId: number): Promise<boolean> {
        return this.worker.deleteReceiver(receiverKeyId);
    }

    public async encrypt(sender: RTCRtpSender, mediaType: MediaType): Promise<void> {
        if (this.encryptedSenders.includes(sender)) {
            this.logger.warn('E2EE: [Client] Encrypt already called for this sender. ignoring');
        } else {
            this.encryptedSenders.push(sender);

            if (!sender['createEncodedStreams']) {
                this.logger.error(
                    'no RTCRtpSender.createEncodedStreams, use Chrome 87 or Electron 11 or upwards'
                );
                return;
            }

            const insertableStreams = sender['createEncodedStreams']();
            if (!insertableStreams.readable || !insertableStreams.writable) {
                this.logger.error(
                    'could not retrieve insertable streams, use Chrome 87 or Electron 11 or upwards'
                );
                return;
            }

            const { readable: readableStream, writable: writableStream } = insertableStreams;

            return this.worker.encrypt(
                mediaType,
                Comlink.transfer(readableStream, readableStream),
                Comlink.transfer(writableStream, writableStream)
            );
        }
    }

    public async decrypt(receiver: RTCRtpReceiver, mediaType: MediaType): Promise<void> {
        if (this.decryptedReceivers.includes(receiver)) {
            this.logger.warn('E2EE: [Client] Decrypt already called for this receiver. ignoring');
        } else {
            this.decryptedReceivers.push(receiver);

            if (!receiver['createEncodedStreams']) {
                this.logger.error(
                    'no RTCRtpSender.createEncodedStreams, use Chrome 87 or Electron 11 or upwards'
                );
                return;
            }

            const insertableStreams = receiver['createEncodedStreams']();
            if (!insertableStreams.readable || !insertableStreams.writable) {
                this.logger.error(
                    'could not retrieve insertable streams, use Chrome 87 or Electron 11 or upwards'
                );
                return;
            }

            const { readable: readableStream, writable: writableStream } = insertableStreams;

            return this.worker.decrypt(
                mediaType,
                Comlink.transfer(readableStream, readableStream),
                Comlink.transfer(writableStream, writableStream)
            );
        }
    }

    public close() {
        this.worker
            .shutdown()
            .catch((error) => {
                this.logger.error('E2EE: [Client] Failure during close', error.message);
            })
            .finally(() => {
                this.worker.terminate();
            });
    }
}

export async function createSFrameClient(clientConfig: SFrameClientConfig): Promise<SFrameClient> {
    const worker = Comlink.wrap<SFrameWorker>(
        new Worker(getWorkerBlobUrl(), {
            name: `SFrame ${clientConfig.mediaType} worker`,
        })
    );

    const client = new SFrameClientImpl(clientConfig, worker);
    return client;
}
