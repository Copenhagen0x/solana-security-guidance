#!/usr/bin/env node
'use strict';
process.exitCode = require('./src/cli').main(process.argv.slice(2));
