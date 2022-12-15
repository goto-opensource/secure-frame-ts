#!/usr/bin/env node

// Copyright (c) 2023 GoTo Group, Inc
// SPDX-License-Identifier: BSD 3-Clause "New" or "Revised" License

/* eslint-disable no-undef */

import fs from 'fs';

const inputFile = process.argv[2];
const outputFile = process.argv[3];

const inputFileContent = fs.readFileSync(inputFile).toString();
const inlineContent = Buffer.from(inputFileContent).toString('base64');

const newContent = `export default '${inlineContent}';\n`;

fs.writeFileSync(outputFile, newContent);
