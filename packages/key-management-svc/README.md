# Security BC - Key Management Service

[![Git Commit](https://img.shields.io/github/last-commit/mojaloop/security-bc.svg?style=flat)](https://github.com/mojaloop/security-bc/commits/master)
[![Git Releases](https://img.shields.io/github/release/mojaloop/security-bc.svg?style=flat)](https://github.com/mojaloop/security-bc/releases)
[![Npm Version](https://img.shields.io/npm/v/@mojaloop-poc/security-bc.svg?style=flat)](https://www.npmjs.com/package/@mojaloop-poc/security-bc)
[![NPM Vulnerabilities](https://img.shields.io/snyk/vulnerabilities/npm/@mojaloop/security-bc.svg?style=flat)](https://www.npmjs.com/package/@mojaloop-poc/security-bc)
[![CircleCI](https://circleci.com/gh/mojaloop/security-bc.svg?style=svg)](https://circleci.com/gh/mojaloop/security-bc)

Mojaloop vNext Key Management Service

## Configuration for Secure Certificate Storage

The Key Management Service supports multiple secure storage options for certificates. You can configure the storage type through environment variables.

### Supported Storage Types

- `LOCAL`: Local file system storage.
- `MONGODB`: MongoDB storage.
- `REDIS`: Redis storage.
- `VAULT`: Vault storage.

### Environment Variables

- `SECURE_STORAGE_TYPE`: Specifies the type of secure storage (`local`, `mongodb`, `redis`, `vault`). Default is `local`.
- `CA_ENCRYPTION_SECRET_KEY`: Secret key used for encrypting certificates. Default is `test_secret_key`.
- `PRIVATE_CERT_PEM_FILE_PATH`: Path to private certificate file for local storage. Only needed For `local` storage type.
- `PUBLIC_CERT_PEM_FILE_PATH`: Path to public certificate file for local storage. Only needed For `local` storage type.
- `PUBLIC_CERT_STORAGE_PATH`: Path to directory for storing public certificates in local storage. Only needed For `local` storage type.
- `MONGO_URL`: MongoDB connection URL. Default is `mongodb://root:mongoDbPas42@localhost:27017/`.
- `REDIS_URL`: Redis connection URL. Default is `redis://localhost:6379`.
- `VAULT_URL`: Vault server URL. Default is `http://localhost:8200`.
- `VAULT_TOKEN`: Token for accessing Vault. Default is `myroot`.

### Deployment Instructions for Vault (Development Mode)

For local development, you can run Vault in development mode using Docker:

```bash
docker run --cap-add=IPC_LOCK -e 'VAULT_DEV_ROOT_TOKEN_ID=myroot' -e 'VAULT_DEV_LISTEN_ADDRESS=0.0.0.0:8200' -p 8200:8200 --name=vault vault server
```

This command sets up a Vault server accessible at localhost:8200 with the root token set to `myroot`. Note that this configuration is not secure and should only be used for development purposes.
## Notes

## How to create RSA private and public keys without password

*These keys should be injected to the key-management-svc, or at this early stage put in the test_keys directory*

Create an RSA certificate

`openssl genrsa -out private.pem 2048`

Extract public certificate from private certificate

`openssl rsa -pubout -in private.pem -out public.pem`

Put the keys in the `dist` directory.

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
(Must be executed at the root of the monorepo)
```bash
docker build -f packages/key-management-svc/Dockerfile -t mojaloop/security-bc-key-management-svc:0.1.0 .
```
