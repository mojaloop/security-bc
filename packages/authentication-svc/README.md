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
(Must be executed at the root of the monorepo)
```bash
docker build -f packages/authentication-svc/Dockerfile -t mojaloop/security-bc-authentication-svc:0.1.0 .
```

## Docker run (dev env)
```bash
# example using a local authN_TempStorageFile a custom KAFKA_URL
docker run -ti --rm -p 3201:3201 \
  --name mojaloop_security-bc-authentication-svc \
  -v $(pwd)/packages/authentication-svc/dist/authN_TempStorageFile:/app/data/authN_TempStorageFile \
  -e KAFKA_URL=192.168.1.103:9092 mojaloop/security-bc-authentication-svc
  
#to run as daemon replace "-ti --rm" with "-d"
```

## Configuration 

### Environment variables

| Environment Variable | Description    | Example Values         |
|---------------------|-----------------|-----------------------------------------|
| PRODUCTION_MODE      | Flag indicating production mode   | FALSE                  |
| LOG_LEVEL            | Logging level for the application                  | LogLevel.DEBUG        |
| AUTH_N_SVC_BASEURL | Authentication service base URL  |http://localhost:3201|
| AUTH_N_TOKEN_ISSUER_NAME    | Authentication service token issuer name           |   mojaloop.vnext.dev.default_issuer    |
| AUTH_N_TOKEN_AUDIENCE        | Authentication service token audience    |    mojaloop.vnext.dev.default_audience   |
| AUTH_N_SVC_JWKS_URL  | Authentication service base URL    | `${AUTH_N_SVC_BASEURL}/.well-known/jwks.json`        |
| AUTH_Z_SVC_BASEURL   | Authorization service base URL    | http://authorization-svc:3202           |
| KAFKA_URL       | Kafka broker URL     | localhost:9092          |
| MONGO_URL            | MongoDB connection URL             | mongodb://root:mongoDbPas42@localhost:27017/ |
| KAFKA_LOGS_TOPIC      | Kafka topic for logs          | logs    |
| KAFKA_AUDITS_TOPIC        | Kafka topic for audits              | audits                 |
| PRIVATE_CERT_PEM_FILE_PATH  | File path for audit key           | /app/data/audit_private_key.pem         |
| ROLES_STORAGE_FILE_PATH | File path for roles storage | /app/data/authN_TempRolesStorageFile.json | 
| AUTH_N_TOKEN_LIFE_SECS | Authentication token life in seconds | 3600 |
| BUILTIN_IAM_BASE_URL | Builtin IAM Base URL  | http://localhost:3203 | 
| REDIS_HOST | Redis Host Name | localhost |
| REDIS_PORT | Redis Service Port | 6379 |
