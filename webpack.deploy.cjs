const path = require('path');
const outputFolder = path.resolve(__dirname, 'build/example/testpage');
const CopyWebpackPlugin = require('copy-webpack-plugin');

module.exports = [
    {
        mode: 'development',

        plugins: [
            new CopyWebpackPlugin({
                patterns: [
                    { from: './example/testpage/index.html', to: `${outputFolder}/index.html` },
                ],
            }),
        ],

        entry: {
            testpage: './example/testpage/testpage.js',
        },

        output: {
            filename: '[name].js',
            path: outputFolder,
        },

        optimization: {
            minimize: false,
        },

        devServer: {
            https: true,
            compress: true,
            host: '0.0.0.0',
            port: 8443,
            static: [
                {
                    directory: outputFolder,
                },
            ],
        },
    },
];
