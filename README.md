# security-bc

**EXPERIMENTAL** vNext Security Bounded Context Mono Repository

See the Reference Architecture documentation [security section](https://mojaloop.github.io/reference-architecture-doc/boundedContexts/security/) for context on this vNext implementation guidelines


## Modules

### Authentication service [link](packages/authentication-svc/README.md)

### Authentication client lib [link](packages/authentication-svc/README.md)


## Usage

### Install Node version

More information on how to install NVM: https://github.com/nvm-sh/nvm

```bash
nvm install
nvm use
```

### Install Dependencies

```bash
npm install
```

## Build

```bash
npm run build
```

## Unit Tests

```bash
npm run test:unit
```





## Troubleshoot

To run those services locally, you need to pass 2 env vars like this (executed in packages/authentication-svc):

```bash
export PRIVATE_CERT_PEM_FILE_PATH=test_keys/private.pem
export IAM_STORAGE_FILE_PATH=dist/authN_TempStorageFile
```



### Unable to load dlfcn_load
```bash
error:25066067:DSO support routines:dlfcn_load:could not load the shared library
```
Fix: https://github.com/mojaloop/security-bc.git  `export OPENSSL_CONF=/dev/null`
