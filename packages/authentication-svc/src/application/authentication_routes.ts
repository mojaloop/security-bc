/*****
License
--------------
Copyright © 2020-2025 Mojaloop Foundation
The Mojaloop files are made available by the Mojaloop Foundation under the Apache License, Version 2.0 (the "License") and you may not use these files except in compliance with the License. You may obtain a copy of the License at

 http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, the Mojaloop files are distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.

Contributors
--------------
This is the official list of the Mojaloop project contributors for this file.
Names of the original copyright holders (individuals or organizations)
should be listed with a '*' in the first column. People who have
contributed from an organization can be listed under the organization
that actually holds the copyright for their contributions (see the
Mojaloop Foundation for an example). Those individuals should have
their names indented and be marked with a '-'. Email address can be added
optionally within square brackets <email>.

* Mojaloop Foundation
- Name Surname <name.surname@mojaloop.io>

* Crosslake
- Pedro Sousa Barreto <pedrob@crosslaketech.com>
*****/

"use strict";
import express from "express";
import {ILogger} from "@mojaloop/logging-bc-public-types-lib";
import {CallSecurityContext, TokenEndpointResponse, UnauthorizedError} from "@mojaloop/security-bc-public-types-lib";
import {AuthenticationAggregate} from "../domain/authentication_agg";
import {ICryptoAuthenticationAdapter} from "../domain/interfaces";

export class AuthenticationRoutes {
    private _logger: ILogger;
    private _router = express.Router();
    private _authAgg: AuthenticationAggregate;
    private _crypto:ICryptoAuthenticationAdapter;
    private readonly _issuerName:string;

    constructor(authAgg: AuthenticationAggregate, crypto:ICryptoAuthenticationAdapter, issuerName:string, logger: ILogger) {
        this._logger = logger.createChild(this.constructor.name);
        this._authAgg = authAgg;
        this._issuerName = issuerName;
        this._crypto = crypto;

        // bind routes
        this._router.post("/token", this._handlePostToken.bind(this));
        this._router.post("/logout", this._handlePostLogout.bind(this));
        this._router.get("/.well-known/openid-configuration", this._handleGetOpenIdConfiguration.bind(this));
        this._router.get("/.well-known/jwks.json", this._handleGetJwks.bind(this));

        // TODO: handler logout route to send message to other auth clients so the token gets in a blocked list
        // this._router.post("/logout", this._handleLogout.bind(this));

        // user role associations
        // this._router.post("/userRoles/:username", this.bad);
        // this._router.delete("/userRoles/:username", this.bad);
        //
        // // app role associations
        // this._router.post("/appRoles/:client_id", this.bad);
        // this._router.delete("/appRoles/:client_id", this.bad);
    }

    get Router(): express.Router {
        return this._router;
    }

    private async _handlePostToken(req: express.Request, res: express.Response, next: express.NextFunction){
        try{
            const grant_type = req.body.grant_type;
            const client_id = req.body.client_id;
            const client_secret = req.body.client_secret;
            const username = req.body.username;
            const password = req.body.password;
            const audience  = req.body.audience;
            const scope  = req.body.scope;

            // TODO check existing client_id first

            const found = this._authAgg.getSupportedGrants().find(value => value.toUpperCase() === grant_type.toUpperCase());
            if(!found){
                this._logger.info(`Received token request for unsupported grant_type: ${grant_type}"`);
                return res.status(401).send("Unsupported grant_type");
            }

            let loginResp: TokenEndpointResponse | null;
            if(grant_type.toUpperCase() === "password".toUpperCase()) {
                loginResp = await this._authAgg.loginUser(client_id, client_secret, username, password, audience, scope);
            }else if(grant_type.toUpperCase() === "client_credentials".toUpperCase()) {
                loginResp = await this._authAgg.loginApp(client_id, client_secret, audience, scope);
            }else {
                return res.status(401).send("Unsupported grant_type");
            }

            if (!loginResp) {
                this._logger.info(`Login FAILED for grant_type: ${grant_type} client_id: ${client_id} and username: ${username}`);
                return res.status(401).send();
            }

            this._logger.info(`Login successful for grant_type: ${grant_type} client_id: ${client_id} and username: ${username}`);
            return res.status(200).json(loginResp);
        }catch(err){
            this._logger.error(err);
            return res.status(500).send("Unknown Error");
        }
    }

    private async _handlePostLogout(req: express.Request, res: express.Response, next: express.NextFunction){
        try{
            const authorizationHeader = req.headers["authorization"];

            if (!authorizationHeader) return res.sendStatus(401);

            const bearer = authorizationHeader.trim().split(" ");
            if (bearer.length != 2) {
                return res.sendStatus(401);
            }

            const bearerToken = bearer[1];

            if(!bearerToken){
                return res.sendStatus(401);
            }

            await this._authAgg.logoutToken(bearerToken);
            return res.status(200).send();
        }catch(err){
            if (err instanceof UnauthorizedError) {
                this._logger.warn("UnauthorizedError");
                // we don't want to reveal anything, so all requests except errors are 200
                res.status(200).send();
                return;
            }

            this._logger.error(err);
            return res.status(500).send("Unknown Error");
        }
    }

    private async _handleGetOpenIdConfiguration(req: express.Request, res: express.Response, next: express.NextFunction){
        const baseUrl = `${req.protocol}://${req.headers.host}`;

        const supportedGrants = this._authAgg.getSupportedGrants();

        const ret = {
            "issuer": this._issuerName,
            "jwks_uri":  `${baseUrl}/.well-known/jwks.json`,
            "grant_types_supported": [
                ...supportedGrants
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
    }

    private async _handleGetJwks(req: express.Request, res: express.Response, next: express.NextFunction){
        // https://datatracker.ietf.org/doc/html/rfc7517

        const keys = await this._crypto.getJwsKeys();
        res.send(keys);
    }
}
