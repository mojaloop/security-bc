# Security BC - Key Management Service

[![Git Commit](https://img.shields.io/github/last-commit/mojaloop/security-bc.svg?style=flat)](https://github.com/mojaloop/security-bc/commits/master)
[![Git Releases](https://img.shields.io/github/release/mojaloop/security-bc.svg?style=flat)](https://github.com/mojaloop/security-bc/releases)
[![Npm Version](https://img.shields.io/npm/v/@mojaloop-poc/security-bc.svg?style=flat)](https://www.npmjs.com/package/@mojaloop-poc/security-bc)
[![NPM Vulnerabilities](https://img.shields.io/snyk/vulnerabilities/npm/@mojaloop/security-bc.svg?style=flat)](https://www.npmjs.com/package/@mojaloop-poc/security-bc)
[![CircleCI](https://circleci.com/gh/mojaloop/security-bc.svg?style=svg)](https://circleci.com/gh/mojaloop/security-bc)

Mojaloop vNext Key Management Service

#Notes

## How to create RSA private and public keys without password

*These keys should be injected to the key-management-svc, or at this early stage put in the test_keys directory*

Create an RSA certificate

`openssl genrsa -out private.pem 2048`

Extract public certificate from private certificate

`openssl rsa -pubout -in private.pem -out public.pem`

Put the keys in the `dist` directory.

---
docker run --cap-add=IPC_LOCK -e 'VAULT_LOCAL_CONFIG={"storage": {"file": {"path": "/vault/file"}}, "listener": [{"tcp": { "address": "0.0.0.0:8200", "tls_disable": true}}], "default_lease_ttl": "168h", "max_lease_ttl": "720h", "ui": true}' -p 8200:8200 vault:1.13.3 server

### Install
See nodes in root dir of this repository

More information on how to install NVM: https://github.com/nvm-sh/nvm

## Build

```bash
npm run build
```

## Auto build (watch)

```bash
npm run watch
```

## Unit Tests

```bash
npm run test:unit
```

## Run

```bash
npm run start
```

## Docker build
(Must be executed at the root of the monorepo)
```bash
docker build -f packages/key-management-svc/Dockerfile -t mojaloop/security-bc-key-management-svc:0.1.0 .
```
