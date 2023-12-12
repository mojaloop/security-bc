# Security BC - Authentication Service

[![Git Commit](https://img.shields.io/github/last-commit/mojaloop/security-bc.svg?style=flat)](https://github.com/mojaloop/security-bc/commits/master)
[![Git Releases](https://img.shields.io/github/release/mojaloop/security-bc.svg?style=flat)](https://github.com/mojaloop/security-bc/releases)
[![Npm Version](https://img.shields.io/npm/v/@mojaloop/security-bc-client-lib.svg?style=flat)](https://www.npmjs.com/package/@mojaloop/security-bc-client-lib)
[![NPM Vulnerabilities](https://img.shields.io/snyk/vulnerabilities/npm/@mojaloop/security-bc-client-lib.svg?style=flat)](https://www.npmjs.com/package/@mojaloop/security-bc-client-lib)
[![CircleCI](https://circleci.com/gh/mojaloop/security-bc.svg?style=shield)](https://circleci.com/github/mojaloop/security-bc)

Mojaloop vNext Security Client Service

# TokenHelper

The Token helper class can be used to validade and decode Mojaloop vNext access tokens.

Functions include:
- `decodeToken(accessToken: string): any | null` - Decode an access token string to return the payload
- `verifyToken(accessToken: string): Promise<boolean>` - Perform a full verification of an access token
- `getCallSecurityContextFromAccessToken(accessToken:string):Promise<CallSecurityContext|null>` - Get a CallSecurityContext from a valid access token

This client will update fetch the public keys from the authentication service every 5 minutes.

If instantiated with an IMessageConsumer, it will listen to AuthTokenInvalidatedEvt security events and update a local list of invalidated access token ids (Jwt Id), after this, any verification of invalidated tokens will fail.

### Example usage:
```Typescript
const AUTH_N_SVC_BASEURL = process.env["AUTH_N_SVC_BASEURL"] || "http://localhost:3201";
const AUTH_N_TOKEN_ISSUER_NAME = process.env["AUTH_N_TOKEN_ISSUER_NAME"] || "mojaloop.vnext.dev.default_issuer";
const AUTH_N_TOKEN_AUDIENCE = process.env["AUTH_N_TOKEN_AUDIENCE"] || "mojaloop.vnext.dev.default_audience";
const AUTH_N_SVC_JWKS_URL = process.env["AUTH_N_SVC_JWKS_URL"] || `${AUTH_N_SVC_BASEURL}/.well-known/jwks.json`;
const KAFKA_URL = process.env["KAFKA_URL"] || "localhost:9092";

const BC_NAME = "example-bc";
const APP_NAME = "example-svc";
const INSTANCE_NAME = `${BC_NAME}_${APP_NAME}`;
const INSTANCE_ID = `${BC_NAME}_${APP_NAME}__${crypto.randomUUID()}`;

const logger = new ConsoleLogger(); // create a logger - see logging-bc client

const tokenHelper = new TokenHelper(
    AUTH_N_SVC_JWKS_URL,                    // usually http://authentication-svc:3201/.well-known/jwks.json
    logger,
    AUTH_N_TOKEN_ISSUER_NAME,               // must be same as authentication-svc
    AUTH_N_TOKEN_AUDIENCE,                  // must be same as authentication-svc
    new MLKafkaJsonConsumer(
        {
            kafkaBrokerList: KAFKA_URL,
            autoOffsetReset: "earliest",    // Use earliest so we recreate the list on apps restarts
            kafkaGroupId: INSTANCE_ID       // Should be an instance specific id, not common
        },
        logger
    )
);
await tokenHelper.init();

// Now we can use it

const accessToken = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6Im9HRFNGX2V5aTJqYjd2QV9DN0RDWDFKSGxBTWlfdnlUZmdQNFBuWnhncDgifQ.eyJ0eXAiOiJCZWFyZXIiLCJhenAiOiJzZWN1cml0eS1iYy11aSIsInVzZXJUeXBlIjoiSFVCIiwicGxhdGZvcm1Sb2xlcyI6WyJhZG1pbiJdLCJwYXJ0aWNpcGFudFJvbGVzIjpbXSwiaWF0IjoxNzAyMzIwMTg3LCJleHAiOjE3MDIzMjM3ODcsImF1ZCI6Im1vamFsb29wLnZuZXh0LmRldi5kZWZhdWx0X2F1ZGllbmNlIiwiaXNzIjoibW9qYWxvb3Audm5leHQuZGV2LmRlZmF1bHRfaXNzdWVyIiwic3ViIjoidXNlcjo6YWRtaW4iLCJqdGkiOiI3MDU2ZmYwNS02YTU0LTQwYTEtOWQyNS00ODBhMzQzM2U5ZDIifQ.c88tN_2Ngz4UP7epTtlFhUen-ETeVKxLKSyVjE5sZVnFfppL_XPpuEHNjZnoKeLWJrYgUBw2E2Zj9XdBoecdz9IinPFQKP_wJgEQ0ECyMfK96q2qJeqZQcbv3sEsqIW0xUz-d2rt8syQ5NPHn_ESivxii01UNjB_6SfRBE-2_0RcqmUvx_Nlx-_nfHdgzDJDBugBqxDsNI5j7IVJvU7YljKCLNc6FK0kVZ6yKj-vVfhRengYNH6yJl1oxAgU06dYEtJa2oIrTVmANQ1xfNxgKeDhowXVa2bg-ppcQit5EYjt5oODyVOT7S-wsDWLFFpz3J-G31teCPWg6q6FJNXlsg";

const tokenIsValid = await tokenHelper.verifyToken(accessToken);
```

# LoginHelper

This class facilitates logins by applications or users, i.e., retrieval of access tokens from credentials.
It will cache a valid token for the duration of the token.

Interesting functions:
- getToken(): Promise<AuthToken>;

After instantiating the class, credentials can be inputed by three methods:
- setUserCredentials - passing the user credentials and the client_id of the app being used by the user
- setAppCredentials - passing the app credentials
- setToken - setting a previously obtained access token.

After this we can use the getToken() to fetch a valid token or an exception.

### Example (TODO)

# AuthorizationClient

This client class, serves two main functions, bootstrap service privileges to the central authorization system and verifying that a role has a certain privileges.

This helper requires an IAuthenticatedHttpRequester instance.

Can use an optional IMessageConsumer to automatically refresh the list of roles and respective privilege membership using events sent by the central services.

Interesting functions:
- roleHasPrivilege(roleId: string, privilegeId: string): boolean;
- rolesHavePrivilege(roleIds: string[], privilegeId: string): boolean;
- addPrivilege(privId: string, labelName: string, description: string): void;
- addPrivilegesArray(privsArray: { privId: string, labelName: string, description: string }[]): void;

### Examples

```Typescript
// create the instance of IAuthenticatedHttpRequester
const authRequester = new AuthenticatedHttpRequester(logger, AUTH_N_SVC_TOKEN_URL);
authRequester.setAppCredentials(SVC_CLIENT_ID, SVC_CLIENT_SECRET);

const consumerHandlerLogger = logger.createChild("AuthorizationClientConsumer");
const messageConsumer = new MLKafkaJsonConsumer(
    {
        kafkaBrokerList: KAFKA_URL,
        kafkaGroupId: INSTANCE_ID       // Should be an instance specific id, not common
    },
    consumerHandlerLogger
);

// setup privileges - bootstrap app privs and get priv/role associations
const authorizationClient = new AuthorizationClient(
    BC_NAME, APP_NAME, APP_VERSION,
    AUTH_Z_SVC_BASEURL, logger.createChild("AuthorizationClient"),
    authRequester,
    messageConsumer
);
```

#### At service start - Bootstrap local app privilege list (send to central authorization service)
```Typescript
authorizationClient.addPrivilegesArray(PRIVILEGE_ARRAY);
```

#### In operation - check if a certain required privile is included in the roleIds of a CallSecurityContext
```Typescript
if(authorizationClient.rolesHavePrivilege(secCtx.platformRoleIds, privName)) {
    return;
}
throw new ForbiddenError(
    `Required privilege "${privName}" not held by caller`
);
```

# AuthenticatedHttpRequester (TODO)

A base requester that can intercept http request and inject the fetching of tokens.

### Example (TODO)
