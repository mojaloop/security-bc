# security-bc

**EXPERIMENTAL** vNext Security Bounded Context Mono Repository

See the Reference Architecture documentation [security section](https://mojaloop.github.io/reference-architecture-doc/boundedContexts/security/) for context on this vNext implementation guidelines


## Modules

### Authentication service [link](modules/authentication-svc/README.md)

### Authentication client lib [link](modules/authentication-svc/README.md)


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

## Run the services 

### Startup supporting services

Use https://github.com/mojaloop/platform-shared-tools/tree/main/packages/deployment/docker-compose-infra


To startup Kafka, MongoDB, Elasticsearch and Kibana, follow the steps below(executed in docker-compose-infra/):   

1. Create a sub-directory called `exec` inside the `docker-compose-infra` (this) directory, and navigate to that directory.


```shell
mkdir exec 
cd exec
```

2. Create the following directories as sub-directories of the `docker-compose/exec` directory:
* `certs`
* `esdata01`
* `kibanadata`
* `logs`

```shell
mkdir {certs,esdata01,kibanadata,logs}
```

3. Copy the `.env.sample` to the exec dir:
```shell
cp ../.env.sample ./.env
```

4. Review the contents of the `.env` file

5. Ensure `vm.max_map_count` is set to at least `262144`: Example to apply property on live system:
```shell
sysctl -w vm.max_map_count=262144 # might require sudo
```

### Start Infrastructure Containers

Start the docker containers using docker-compose up (in the exec dir)
```shell
docker-compose -f ../docker-compose-infra.yml --env-file ./.env up -d
```


To view the logs of the infrastructure containers, run:
```shell
docker-compose -f ../docker-compose-infra.yml --env-file ./.env logs -f
```

To stop the infrastructure containers, run:
```shell
docker-compose -f ../docker-compose-infra.yml --env-file ./.env stop
```

After running the docker-compose-infra we can start authentication and authorization services:

```bash
# start the authentication service
npm run start:authentication-svc 

# start the authorization service
npm run start:authorization-svc 
```

To run those services locally, you need to pass 2 env vars like this (executed in modules/authentication-svc):

```bash
export PRIVATE_CERT_PEM_FILE_PATH=test_keys/private.pem
export IAM_STORAGE_FILE_PATH=dist/authN_TempStorageFile
```

## Integration Tests

```bash
npm run test:integration
```

## Troubleshoot 

### Unable to load dlfcn_load
```bash
error:25066067:DSO support routines:dlfcn_load:could not load the shared library
```
Fix: https://github.com/mojaloop/security-bc.git  `export OPENSSL_CONF=/dev/null`
