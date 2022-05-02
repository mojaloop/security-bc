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
### Install Yarn

```bash
npm -g yarn
```

Set yarn to v3
```bash
yarn set version berry
```

Confirm with
```bash
yarn --version
```

### Install Yarn Plugins

```bash
yarn plugin import workspace-tools
```

### Install Dependencies

```bash
yarn
```

## Build

```bash
yarn build
```

## Run

```bash
yarn start
```

## Unit Tests

```bash
yarn test:unit
```

