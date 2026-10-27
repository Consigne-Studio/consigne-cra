#!/usr/bin/env node
import { executer } from '../src/cli.js';

process.exitCode = await executer(process.argv.slice(2));
