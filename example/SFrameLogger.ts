// Copyright (c) 2023 GoTo Group, Inc
// SPDX-License-Identifier: BSD 3-Clause "New" or "Revised" License

import { SFrameErrorType } from '../src/index.js';

export enum LogLevel {
    DEBUG,
    INFO,
    LOG,
    WARN,
    ERROR,
    FATAL,
}

export type LogMessage = {
    level: LogLevel;
    type: SFrameErrorType;
    message: string;
};

export class SFrameLogger {
    private callback: (log: LogMessage) => void = () => 0;

    setCallback(loggerCallback: (log: LogMessage) => void): void {
        this.callback = loggerCallback;
    }

    public debug(message: string): void {
        this.push(LogLevel.DEBUG, message);
    }
    public info(message: string): void {
        this.push(LogLevel.INFO, message);
    }
    public log(message: string): void {
        this.push(LogLevel.LOG, message);
    }
    public warn(message: string): void {
        this.push(LogLevel.WARN, message);
    }

    public error(message: string, type: SFrameErrorType): void {
        this.push(LogLevel.ERROR, message, type);
    }

    public fatal(message: string, type: SFrameErrorType): void {
        this.push(LogLevel.FATAL, message, type);
    }

    private push(level: LogLevel, message: string, type = SFrameErrorType.Unknown) {
        if (this.callback) {
            this.callback({ message, level, type });
        }
    }
}
