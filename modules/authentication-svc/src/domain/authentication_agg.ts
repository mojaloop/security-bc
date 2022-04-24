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

"use strict"

import {IAMAuthenticationAdapter, ICryptoAuthenticationAdapter} from "./interfaces";
import {ILogger} from "@mojaloop/logging-bc-logging-client-lib/dist/index";
import {TokenEndpointResponse} from "@mojaloop/security-bc-public-types-lib";

// These should later be put in configurations
const ISSUER_NAME = "vNext Security BC - Authorization Svc";
const DEFAULT_AUDIENCE = "account";
const TOKEN_LIFE_SECS = 3600;
const REFRESH_TOKEN_LENGTH = 128;

export class AuthenticationAggregate{
    private _logger:ILogger
    private _iam:IAMAuthenticationAdapter;
    private _crypto:ICryptoAuthenticationAdapter;

    constructor(iam:IAMAuthenticationAdapter, crypto:ICryptoAuthenticationAdapter, logger:ILogger) {
        this._logger = logger;
        this._iam = iam;
        this._crypto = crypto;
    }

    async loginUser(client_id:string, client_secret:string | null, username:string, password:string, audience?:string, scope?:string):Promise<TokenEndpointResponse | null> {
        if(!username || !password){
            this._logger.info("rejected user login without username or password");
            return null;
        }

        const loginOk = await this._iam.loginUser(client_id, client_secret, username, password);

        if (!loginOk.success) {
            return null;
        }

        // TODO get roles from AuthN svc
        const additionalPayload:any = {
            typ: "Bearer",
            azp: client_id,
            roles: loginOk.roles,
            //testObj: "pedro1",
        };

        if(scope){
            additionalPayload.scope = scope;
        }

        const accessCode = await this._crypto.generateJWT(
                additionalPayload,
                username,
                audience || DEFAULT_AUDIENCE,
                TOKEN_LIFE_SECS
        );

        // TODO verify return
        const ret = {
            token_type: "Bearer",
            scope: null,
            access_token: accessCode,
            expires_in: TOKEN_LIFE_SECS,
            refresh_token: null,
            refresh_token_expires_in: null
        }
        return ret;
    }

    async loginApp(client_id:string, client_secret:string, audience?:string, scope?:string):Promise<TokenEndpointResponse | null> {
        if(!client_id || !client_secret){
            this._logger.info("rejected user login without username or password");
            return null;
        }

        const loginOk = await this._iam.loginApp(client_id, client_secret);

        if (!loginOk.success) {
            return null;
        }

        // TODO get roles from AuthN svc
        const additionalPayload:any = {
            typ: "Bearer",
            azp: client_id,
            roles: loginOk.roles,
        };
        if(scope){
            additionalPayload.scope = scope;
        }

        const accessCode = await this._crypto.generateJWT(
                additionalPayload,
                client_id,
                audience || DEFAULT_AUDIENCE,
                TOKEN_LIFE_SECS
        );

        // TODO verify return
        const ret = {
            token_type: "Bearer",
            scope: null,
            access_token: accessCode,
            expires_in: TOKEN_LIFE_SECS,
            refresh_token: null,
            refresh_token_expires_in: null
        }
        return ret;
    }
}
