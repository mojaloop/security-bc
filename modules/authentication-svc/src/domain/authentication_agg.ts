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
import {ILogger} from "@mojaloop/logging-bc-public-types-lib";
import {TokenEndpointResponse} from "@mojaloop/security-bc-public-types-lib";

// These should later be put in configurations
const ISSUER_NAME = "vNext Security BC - Authorization Svc";


const REFRESH_TOKEN_LENGTH = 128;

const SUPPORTED_GRANTS = ["password","client_credentials"];

export class AuthenticationAggregate{
    private _logger:ILogger
    private _iam:IAMAuthenticationAdapter;
    private _crypto:ICryptoAuthenticationAdapter;
    private readonly _tokenLifeSecs:number;
    private readonly _defaultAudience:string;

    constructor(iam:IAMAuthenticationAdapter, crypto:ICryptoAuthenticationAdapter, tokenLifeSecs:number, defaultAudience:string, logger:ILogger) {
        this._logger = logger.createChild(this.constructor.name);
        this._iam = iam;
        this._crypto = crypto;
        this._tokenLifeSecs = tokenLifeSecs;
        this._defaultAudience = defaultAudience;
    }

    async loginUser(client_id:string, client_secret:string | null, username:string, password:string, audience?:string, scope?:string):Promise<TokenEndpointResponse | null> {
        if(!username || !password){
            this._logger.info("rejected user login without username or password");
            return null;
        }

        const loginOk = await this._iam.loginUser(client_id, client_secret, username, password);

        if (!loginOk.success) {
            this._logger.info(`User Login FAILED for username: ${username} and client_id: ${client_id}`);
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
                `user::${username}`,
                audience || this._defaultAudience,
                this._tokenLifeSecs
        );

        // TODO verify return
        const ret = {
            token_type: "Bearer",
            scope: null,
            access_token: accessCode,
            expires_in: this._tokenLifeSecs,
            refresh_token: null,
            refresh_token_expires_in: null
        }
        this._logger.info(`App Login successful for username: ${username}`);
        return ret;
    }

    async loginApp(client_id:string, client_secret:string, audience?:string, scope?:string):Promise<TokenEndpointResponse | null> {
        if(!client_id || !client_secret){
            this._logger.info("rejected user login without username or password");
            return null;
        }

        const loginOk = await this._iam.loginApp(client_id, client_secret);

        if (!loginOk.success) {
            this._logger.info(`App Login FAILED for client_id: ${client_id}`);
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
                `app::${client_id}`,
                audience || this._defaultAudience,
                this._tokenLifeSecs
        );

        // TODO verify return
        const ret = {
            token_type: "Bearer",
            scope: null,
            access_token: accessCode,
            expires_in: this._tokenLifeSecs,
            refresh_token: null,
            refresh_token_expires_in: null
        }

        this._logger.info(`App Login successful for client_id: ${client_id}`);

        return ret;
    }

    getSupportedGrants():string[]{
        return SUPPORTED_GRANTS;
    }
}
