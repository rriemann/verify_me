// Karma configuration
// Generated on Wed Oct 21 2015 02:32:08 GMT+0200 (CEST)

module.exports = function(config) {
  config.set({

    // base path that will be used to resolve all patterns (eg. files, exclude)
    basePath: './',


    // frameworks to use
    // available frameworks: https://npmjs.org/browse/keyword/karma-adapter
    frameworks: [ 'commonjs', 'karma-typescript', 'mocha', 'chai' ],


    // list of files / patterns to load in the browser
    files: [
      'src/**/*.ts',
      'test/**/*.ts',
      'test/fixture/*.html',
      'node_modules/verifyme_utility/dist/src/verifyme_utility.js'
    ],


    // list of files to exclude
    exclude: [
      'test/helper/*.ts',
      'test/sample_keys/*'
    ],


    // preprocess matching files before serving them to the browser
    // available preprocessors: https://npmjs.org/browse/keyword/karma-preprocessor
    preprocessors: {
      'src/**/*.ts': [ 'karma-typescript', 'commonjs' ],
      'test/**/*.ts': [ 'karma-typescript', 'commonjs' ],
      'test/fixture/*.html': [ 'html2js' ],
      'node_modules/verifyme_utility/dist/src/verifyme_utility.js': [ 'commonjs' ]
    },


    // test results reporter to use
    // possible values: 'dots', 'progress'
    // available reporters: https://npmjs.org/browse/keyword/karma-reporter
    reporters: [ 'progress', 'karma-typescript' ],

    // web server port
    port: 9876,


    // enable / disable colors in the output (reporters and logs)
    colors: true,


    // level of logging
    // possible values: config.LOG_DISABLE || config.LOG_ERROR || config.LOG_WARN || config.LOG_INFO || config.LOG_DEBUG
    logLevel: config.LOG_INFO,


    // enable / disable watching file and executing tests whenever any file changes
    autoWatch: true,


    // start these browsers
    // available browser launchers: https://npmjs.org/browse/keyword/karma-launcher
    browsers: ['Chrome'],

    // The number of disconnections tolerated.
    browserDisconnectTolerance: 0,


    // How long will Karma wait for a message from a browser (in ms).
    browserNoActivityTimeout: 300000,


    // Continuous Integration mode
    // if true, Karma captures browsers, runs the tests and exits
    singleRun: false,


    // add additional watchify configuration properties here
    // such as poll to use watchify as continous integration tool
    watchify: {
      poll: true
    },


    coverageReporter: {
      disableCodeCoverageInstrumentation: true,
      instrumenterOptions: {
        istanbul: { noCompact: true }
      },
      reporters : [
        {'type': 'text-summary'},
        {'type': 'lcov'}
      ]
    },

    client: {
      captureConsole: true
    },

    karmaTypescriptConfig: {
      tsconfig: "./tsconfig.test.json"
    },

    plugins: [
      'karma-chai',
      'karma-chrome-launcher',
      'karma-commonjs',
      'karma-html2js-preprocessor',
      'karma-mocha',
      'karma-typescript'
    ]
  })
}
