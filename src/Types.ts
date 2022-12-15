// Copyright (c) 2023 GoTo Group, Inc
// SPDX-License-Identifier: BSD 3-Clause "New" or "Revised" License

export type MediaType = 'audio' | 'video' | 'screen';

export type MediaFrame = {
    data: Uint8Array;
    headerLength: number;
};

export type SerializedCryptoKey = ArrayBuffer;

export enum SFrameErrorType {
    DecryptionFailure = 'DecryptionFailure',
    EncryptionFailure = 'EncryptionFailure',
    InvalidKey = 'InvalidKey',
    InvalidHeaderKey = 'InvalidHeaderKey',
    InitializationVectorError = 'InitializationVectorError',
    ReplayAttackError = 'ReplayAttackError',
    AuthenticationError = 'AuthenticationError',
    Unknown = 'Unknown',
}

export class SFrameError extends Error {
    public type: SFrameErrorType;
    constructor(type: SFrameErrorType, public override message: string) {
        super(message);
        this.name = 'E2EE SFrameError';
        this.type = type;
    }
}

export interface Logger {
    debug(message?: string, ...optionalParams: any[]): void;
    error(message?: string, ...optionalParams: any[]): void;
    info(message?: string, ...optionalParams: any[]): void;
    log(message?: string, ...optionalParams: any[]): void;
    warn(message?: string, ...optionalParams: any[]): void;
}
