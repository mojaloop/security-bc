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

## Integration Tests

```bash
npm run test:integration
```


## Run the services 

```bash
# start the authentication service
npm run start:authentication-svc 

# start the authorization service
npm run start:authorization-svc 
```
