# Onboarding

>*Note:* Before completing this guide, make sure you have completed the _general_ onboarding guide in the [base mojaloop repository](https://github.com/mojaloop/mojaloop/blob/main/onboarding.md#mojaloop-onboarding).

## Contents

1. [Prerequisites](#1-prerequisites)
2. [Service Overview](#2-service-overview)
3. [Installing and Building](#3-installing-and-building)
4. [Running Locally](#4-running-locally-dependencies-inside-of-docker)
5. [Testing](#6-testing)
6. [Common Errors/FAQs](#7-common-errorsfaqs)

##  1. Prerequisites

If you have followed the [general onboarding guide](https://github.com/mojaloop/mojaloop/blob/main/onboarding.md#mojaloop-onboarding), you should already have the following cli tools installed:

* `brew` (macOS), [todo: windows package manager]
* `curl`, `wget`
* `docker` + `docker-compose`
* `node`, `npm` and (optionally) `nvm`

## 2. Service Overview 
The Security BC consists of the following packages;

`authentication-svc`
Authentication Service.
[README](packages/authentication-svc/README.md)

`authorization-svc`
Authorization Service.
[README](packages/authorization-svc/README.md)

`builtin-identity-svc`
Builtin Identity Service.
[README](packages/builtin-identity-svc/README.md)

`client-lib`
Client library types.
[README](./packages/client-lib/README.md)

`public-types-lib`
Security BC Public Types.
[README](./packages/public-types-lib/README.md)

## 3. <a name='InstallingandBuilding'></a>Installing and Building

Firstly, clone your fork of the `security-bc` onto your local machine:
```bash
git clone https://github.com/<your_username>/security-bc.git
```

Then `cd` into the directory and install the node modules:
```bash
cd security-bc
```

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

#### Build

```bash
npm run build
``` 

## 4. Running Locally (dependencies inside of docker)

In this method, we will run all of the core dependencies inside of docker containers, while running the `security-bc` server on your local machine.

> Alternatively, you can run the `security-bc` inside of `docker-compose` with the rest of the dependencies to make the setup a little easier: [Running Inside Docker](#5-running-inside-docker).

### 4.1 Run all back-end dependencies as part of the Docker Compose

Use [platform-shared-tools docker-compose files](https://github.com/mojaloop/platform-shared-tools/tree/main/packages/deployment/): 
Follow instructions in the `README.md` files to run the supporting services. Make sure you have the following services up and running:

- infra services : [docker-compose-infra](https://github.com/mojaloop/platform-shared-tools/tree/main/packages/deployment/docker-compose-infra)
	- mongo
	- kafka
	- zoo

This will do the following:
* `docker pull` down any dependencies defined in each `docker-compose.yml` file, and the services.
* run all of the containers together
* ensure that all dependencies have started for each services.


### 4.2 Set Up Environment Variables

```bash
# set the MONGO_URL* environment variable (required):
export MONGO_URL=mongodb://root:mongoDbPas42@localhost:27017/";
```

```bash
# set the AUDIT_KEY_FILE_PATH 
export AUDIT_KEY_FILE_PATH=./dist/auditing_cert
```
See the README.md file on each services for more Environment Variable Configuration options.



## 5. Testing
We use `npm` scripts as a common entrypoint for running the tests. Tests include unit, functional, and integration.

```bash
# unit tests:
npm run test:unit

# check test coverage
npm run test:coverage

# integration tests
npm run test:integration
```

### 5.1 Testing the `security-bc` API with Postman

[Here](https://github.com/mojaloop/platform-shared-tools/tree/main/packages/postman) you can find a complete Postman collection, in a json file, ready to be imported to Postman.


## 6. Common Errors/FAQs

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