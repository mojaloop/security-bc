# Security BC - Authentication Service

[![Git Commit](https://img.shields.io/github/last-commit/mojaloop/security-bc.svg?style=flat)](https://github.com/mojaloop/security-bc/commits/master)
[![Git Releases](https://img.shields.io/github/release/mojaloop/security-bc.svg?style=flat)](https://github.com/mojaloop/security-bc/releases)
[![Npm Version](https://img.shields.io/npm/v/@mojaloop-poc/security-bc.svg?style=flat)](https://www.npmjs.com/package/@mojaloop-poc/security-bc)
[![NPM Vulnerabilities](https://img.shields.io/snyk/vulnerabilities/npm/@mojaloop/security-bc.svg?style=flat)](https://www.npmjs.com/package/@mojaloop-poc/security-bc)
[![CircleCI](https://circleci.com/gh/mojaloop/security-bc.svg?style=svg)](https://circleci.com/gh/mojaloop/security-bc)

Mojaloop vNext Authentication Service

#Notes

## How to create RSA private and public keys without password

*These keys should be injected to the authentication-svc, or at this early stage put in the test_keys directory*

Create an RSA certificate 

`openssl genrsa -out private.pem 2048`

Extract public certificate from private certificate

`openssl rsa -pubout -in private.pem -out public.pem`

---

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
```bash
npm run docker:build
```

## Docker run (dev env)
```bash
# example using a local authN_TempStorageFile a custom KAFKA_URL
docker run -ti --rm -p 3201:3201 \
  --name mojaloop_security-bc-authentication-svc \
  -v $(pwd)/modules/authentication-svc/dist/authN_TempStorageFile:/app/data/authN_TempStorageFile \
  -e KAFKA_URL=192.168.1.103:9092 mojaloop/security-bc-authentication-svc
  
#to run as daemon replace "-ti --rm" with "-d"
```
