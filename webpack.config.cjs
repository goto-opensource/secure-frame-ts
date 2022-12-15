/* eslint-disable @typescript-eslint/no-var-requires */
const path = require('path');

module.exports = {
    mode: 'production',
    entry: {
        SFrameWorker: {
            import: './lib/example/Worker.js',
            filename: '../lib/example/webpack.Worker.js',
        },
    },
    output: {
        path: path.resolve(__dirname, 'lib'),
        library: 'SFrameWorker',
    },
};
