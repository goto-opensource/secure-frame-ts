// Copyright (c) 2023 GoTo Group, Inc
// SPDX-License-Identifier: BSD 3-Clause "New" or "Revised" License

import * as Comlink from 'comlink';
import {
    Context,
    MediaFrame,
    MediaType,
    SerializedCryptoKey,
    SFrameErrorType,
} from '../src/index.js';
import { LogMessage, SFrameLogger } from './SFrameLogger.js';
import { parseVP8Header } from './VP8PayloadHeader.js';

// We need to skip the headers of the media frames so that encryption works
const kOpusHeaderLength = 1;
function determineHeaderLength(kind: MediaType, data: Uint8Array): number {
    if (kind === 'video' || kind === 'screen') {
        const vp8Header = parseVP8Header(data);
        return vp8Header ? vp8Header.byteLength : 0;
    }
    if (kind === 'audio') {
        return kOpusHeaderLength;
    }
    return 0;
}

function toUint8Array(data: Uint8Array | ArrayBuffer): Uint8Array {
    return data instanceof Uint8Array ? data : new Uint8Array(data);
}

const context = new Context();
const logger = new SFrameLogger();

const sframeWorker = {
    shutdown(): void {
        // noop
    },
    setSenderEncryptionKey(senderKeyId: number, key: SerializedCryptoKey): Promise<void> {
        logger.info('E2EE: [Worker] setSenderEncryptionKey');
        return context.setSenderEncryptionKey(senderKeyId, key);
    },
    setReceiverEncryptionKey(receiverKeyId: number, key: SerializedCryptoKey): Promise<void> {
        logger.info('E2EE: [Worker] setReceiverEncryptionKey');
        return context.setReceiverEncryptionKey(receiverKeyId, key);
    },
    deleteReceiver(receiverKeyId: number): boolean {
        logger.info('E2EE: [Worker] deleteReceiver');
        return context.deleteReceiver(receiverKeyId);
    },
    encrypt(kind: MediaType, readableStream: ReadableStream, writableStream: WritableStream): void {
        logger.info('E2EE: [Worker] encrypt');

        const transformStream = new TransformStream({
            transform: async (chunk, controller) => {
                if (!context.canEncrypt()) {
                    return;
                }

                const frame: MediaFrame = {
                    data: toUint8Array(chunk.data),
                    headerLength: determineHeaderLength(kind, chunk.data),
                };

                try {
                    const encrypted = await context.encryptFrame(frame);
                    chunk.data = encrypted.buffer;
                    controller.enqueue(chunk);
                } catch (error: any) {
                    logger.fatal(error.message, SFrameErrorType.EncryptionFailure);
                    controller.terminate();
                }
            },
        });
        readableStream.pipeThrough(transformStream).pipeTo(writableStream);
    },
    decrypt(kind: MediaType, readableStream: ReadableStream, writableStream: WritableStream): void {
        logger.info('E2EE: [Worker] decrypt');

        const transformStream = new TransformStream({
            transform: async (chunk, controller) => {
                const frame: MediaFrame = {
                    data: toUint8Array(chunk.data),
                    headerLength: determineHeaderLength(kind, chunk.data),
                };

                try {
                    const decrypted = await context.decryptFrame(frame);
                    chunk.data = decrypted.buffer;
                    controller.enqueue(chunk);
                } catch (error: any) {
                    logger.error(error.message, SFrameErrorType.DecryptionFailure);
                }
            },
        });

        readableStream.pipeThrough(transformStream).pipeTo(writableStream);
    },
    setLoggerCallback(loggerCallback: (log: LogMessage) => void): void {
        return logger.setCallback(loggerCallback);
    },
};

export type SFrameWorker = typeof sframeWorker & Worker;

Comlink.expose(sframeWorker);
