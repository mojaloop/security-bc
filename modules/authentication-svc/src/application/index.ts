/*****
 License
 --------------
 Copyright © 2017 Bill & Melinda Gates Foundation
 The Mojaloop files are made available by the Bill & Melinda Gates Foundation under the Apache License, Version 2.0 (the "License") and you may not use these files except in compliance with the License. You may obtain a copy of the License at

 http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, the Mojaloop files are distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.

 Contributors
 --------------
 This is the official list (alphabetical ordering) of the Mojaloop project contributors for this file.
 Names of the original copyright holders (individuals or organizations)
 should be listed with a '*' in the first column. People who have
 contributed from an organization can be listed under the organization
 that actually holds the copyright for their contributions (see the
 Gates Foundation organization for an example). Those individuals should have
 their names indented and be marked with a '-'. Email address can be added
 optionally within square brackets <email>.

 * Gates Foundation
 - Name Surname <name.surname@gatesfoundation.com>

 * Crosslake
 - Pedro Sousa Barreto <pedrob@crosslaketech.com>

 --------------
 ******/

'use strict'

import express from "express";
import {ConsoleLogger, ILogger} from "@mojaloop/logging-bc-public-types-lib";
import {IAMAuthenticationAdapter, ICryptoAuthenticationAdapter} from "../domain/interfaces";
import {FileIAMAdapter} from "../infrastructure/file_iam_adapter";
import {SimpleCryptoAdapter} from "../infrastructure/simple_crypto_adapter";
import {AuthenticationAggregate} from "../domain/authentication_agg";
import {TokenEndpointResponse} from "@mojaloop/security-bc-public-types-lib";

const ISSUER_NAME = "http://localhost:3000/";

const logger: ILogger = new ConsoleLogger();
const app = express();
let iam:IAMAuthenticationAdapter;
let crypto:ICryptoAuthenticationAdapter;
let authAgg: AuthenticationAggregate;

function setupExpress() {
    app.use(express.json()); // for parsing application/json
    app.use(express.urlencoded({extended: true})); // for parsing application/x-www-form-urlencoded
    app.use( (req: express.Request, res: express.Response, next: express.NextFunction) => {
        logger.debug(`received request to: ${req.protocol}://${req.headers.host}${req.originalUrl}`);

        // CORS allow from any
        res.setHeader("Access-Control-Allow-Origin","*");
        next();
    });
}

function setupRoutes() {
    app.post("/token", async (req: express.Request, res: express.Response, next: express.NextFunction) => {
        const data: any = req.body;
        logger.debug(data);

        const grant_type = req.body.grant_type;
        const client_id = req.body.client_id;
        const client_secret = req.body.client_secret;
        const username = req.body.username;
        const password = req.body.password;
        const audience  = req.body.audience;

        // TODO check existing client_id first

        let loginResp: TokenEndpointResponse | null;
        if(grant_type.toUpperCase() === "password".toUpperCase()) {
            loginResp = await authAgg.loginUser(client_id, client_secret, username, password);
        }else if(grant_type.toUpperCase() === "client_credentials".toUpperCase()) {
            loginResp = await authAgg.loginApp(client_id, client_secret);
        }else {
            return res.status(401).send("Unsupported grant_type");
        }

        if (!loginResp) {
            return res.status(401).send();
        }
        return res.status(200).json(loginResp);

    });

    app.get("/.well-known/openid-configuration", async (req: express.Request, res: express.Response, next: express.NextFunction) => {
        const baseUrl = `${req.protocol}://${req.headers.host}`;

        const ret = {
            "issuer": ISSUER_NAME,
            "jwks_uri":  `${baseUrl}/.well-known/jwks.json`,
            "grant_types_supported": [
                //"authorization_code",
                //"implicit",
                //"refresh_token",
                "password",
                "client_credentials"
            ],
        };

/*
        const ret = {
            "issuer": ISSUER_NAME,
            "authorization_endpoint": `${baseUrl}/auth`,
            "token_endpoint": `${baseUrl}/token`,
            "userinfo_endpoint":  `${baseUrl}/userinfo`,
            "introspection_endpoint":  `${baseUrl}/introspection_endpoint`,
            "token_introspection_endpoint": "http://localhost:3000/auth/realms/test/protocol/openid-connect/token/introspect",
            "jwks_uri":  `${baseUrl}/.well-known/jwks.json`,
            //"jwks_uri": "http://localhost:3000/auth/realms/test/protocol/openid-connect/certs",
            "end_session_endpoint": "http://localhost:3000/auth/realms/test/protocol/openid-connect/logout",
            "check_session_iframe": "http://localhost:3000/auth/realms/test/protocol/openid-connect/login-status-iframe.html",
            "grant_types_supported": [
                "authorization_code",
                "implicit",
                "refresh_token",
                "password",
                "client_credentials"
            ],
            "response_types_supported": [
                "code",
                "none",
                "id_token",
                "token",
                "id_token token",
                "code id_token",
                "code token",
                "code id_token token"
            ],
            "subject_types_supported": [
                "public",
                "pairwise"
            ],
            "id_token_signing_alg_values_supported": [
                "RS256"
            ],
            "userinfo_signing_alg_values_supported": [
                "RS256"
            ],
            "request_object_signing_alg_values_supported": [
                "none",
                "RS256"
            ],
            "response_modes_supported": [
                "query",
                "fragment",
                "form_post"
            ],
            "registration_endpoint": "http://localhost:3000/auth/realms/test/clients-registrations/openid-connect",
            "token_endpoint_auth_methods_supported": [
                "private_key_jwt",
                "client_secret_basic",
                "client_secret_post"
            ],
            "token_endpoint_auth_signing_alg_values_supported": [
                "RS256"
            ],
            "claims_supported": [
                "sub",
                "iss",
                "auth_time",
                "name",
                "given_name",
                "family_name",
                "preferred_username",
                "email"
            ],
            "claim_types_supported": [
                "normal"
            ],
            "claims_parameter_supported": false,
            "scopes_supported": [
                "openid",
                "offline_access"
            ],
            "request_parameter_supported": true,
            "request_uri_parameter_supported": true

        };*/

        res.send(ret);
    })

    app.get("/.well-known/jwks.json", async (req: express.Request, res: express.Response, next: express.NextFunction) => {
        // https://datatracker.ietf.org/doc/html/rfc7517

        const keys = await crypto.getJwsKeys();
        res.send(keys);
    })

    app.use((req, res) => {
        // catch all
        logger.info("got unhandled/404 request to: " + req.path);
        res.send(404);
    })
}

async function start():Promise<void>{
    iam = new FileIAMAdapter("./dist/iamTempStorageFile");
    await iam.init();

    crypto = new SimpleCryptoAdapter("./test_keys/private.pem", "./test_keys/public.pem", ISSUER_NAME, logger);
    await crypto.init();

    if(!(iam as FileIAMAdapter).userCount()) {
        (iam as FileIAMAdapter).createUser("user", "superPass");
    }
    if(!(iam as FileIAMAdapter).appCount()) {
        (iam as FileIAMAdapter).createApp("security-bc-ui", null);
    }

    authAgg = new AuthenticationAggregate(iam, crypto, logger);
    //await authAgg.init();

    setupExpress();
    setupRoutes();

    const server = app.listen(3000, () =>console.log(`🚀 Server ready at: http://localhost:3000`))
}


async function _handle_int_and_term_signals(signal: NodeJS.Signals): Promise<void> {
    logger.info(`Service - ${signal} received - cleaning up...`);
    process.exit();
}

//catches ctrl+c event
process.on("SIGINT", _handle_int_and_term_signals.bind(this));

//catches program termination event
process.on("SIGTERM", _handle_int_and_term_signals.bind(this));

//do something when app is closing
process.on('exit', () => {
    logger.info("Microservice - exiting...");
});

start();
