#!/usr/bin/env node
import 'source-map-support/register';
import * as cdk from 'aws-cdk-lib';
import { S3ECPythonGithub } from '../lib/cdk-stack';

const app = new cdk.App();
new S3ECPythonGithub(app, 'S3ECPythonGithub');
