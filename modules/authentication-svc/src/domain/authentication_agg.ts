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

import {defaultDevApplications} from "../dev_defaults";
import {IAMAuthenticationAdapter, ICryptoAuthenticationAdapter, ILocalRoleAssociationRepo} from "./interfaces";
import {ILogger} from "@mojaloop/logging-bc-public-types-lib";
import {TokenEndpointResponse} from "@mojaloop/security-bc-public-types-lib";

// These should later be put in configurations
const ISSUER_NAME = "vNext Security BC - Authorization Svc";
const REFRESH_TOKEN_LENGTH = 128;

const SUPPORTED_GRANTS = ["password","client_credentials"];

export type AuthenticationAggregateOptions = {
    tokenLifeSecs?: number;
    defaultAudience?: string;
    rolesFromIamProvider?: boolean;
}

const AuthenticationAggregateDefaultOptions: AuthenticationAggregateOptions = {
    tokenLifeSecs: 3600,
    defaultAudience: "",
    rolesFromIamProvider: false
};

export class AuthenticationAggregate{
    private _logger:ILogger
    private _iam:IAMAuthenticationAdapter;
    private _crypto:ICryptoAuthenticationAdapter;
    private readonly _localRolesRepo: ILocalRoleAssociationRepo | null;
    private readonly _options: AuthenticationAggregateOptions;

    constructor(iam:IAMAuthenticationAdapter, crypto:ICryptoAuthenticationAdapter, logger: ILogger, localRolesRepo: ILocalRoleAssociationRepo | null, options?: AuthenticationAggregateOptions) {
        this._logger = logger.createChild(this.constructor.name);
        this._iam = iam;
        this._crypto = crypto;
        this._options = options || AuthenticationAggregateDefaultOptions;

        // apply individual defaults if options were provided
        if(options) {
            if (!this._options.tokenLifeSecs){
                this._options.tokenLifeSecs = AuthenticationAggregateDefaultOptions.tokenLifeSecs;
            }
            if (!this._options.defaultAudience){
                this._options.defaultAudience = AuthenticationAggregateDefaultOptions.defaultAudience;
            }
            if (!this._options.rolesFromIamProvider) {
                this._options.rolesFromIamProvider = AuthenticationAggregateDefaultOptions.rolesFromIamProvider;
            }
        }

        if(this._options.rolesFromIamProvider && !this._localRolesRepo){
            throw new Error("If using rolesFromIamProvider option, a valid ILocalRoleAssociationRepo must be provided");
        }
    }

    async loginUser(client_id:string, client_secret:string | null, username:string, password:string, audience?:string, scope?:string):Promise<TokenEndpointResponse | null> {
        if(!username || !password){
            this._logger.info("rejected user login without username or password");
            return null;
        }

        const loginResponse = await this._iam.loginUser(client_id, client_secret, username, password);

        if (!loginResponse.success) {
            this._logger.debug(`User Login FAILED for username: ${username} and client_id: ${client_id}`);
            return null;
        }

        // TODO get role association from AuthN if rolesFromIamProvider true
        const additionalPayload:any = {
            typ: "Bearer",
            azp: client_id,
            //testObj: "pedro1",
        };

        if(scope){
            additionalPayload.scope = scope;
        }

        if(this._options.rolesFromIamProvider){
            const roles = await this._localRolesRepo!.fetchUserRoles(username);
            additionalPayload.roles = roles;
        }else{
            additionalPayload.roles = loginResponse.roles;
        }

        const accessCode = await this._crypto.generateJWT(
                additionalPayload,
                `user::${username}`,
                audience || this._options.defaultAudience!,
                this._options.tokenLifeSecs!
        );

        // TODO verify return
        const ret = {
            token_type: "Bearer",
            scope: null,
            access_token: accessCode,
            expires_in: this._options.tokenLifeSecs!,
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

        const loginResponse = await this._iam.loginApp(client_id, client_secret);

        if (!loginResponse.success) {
            this._logger.info(`App Login FAILED for client_id: ${client_id}`);
            return null;
        }

        // TODO get roles from AuthN svc
        const additionalPayload:any = {
            typ: "Bearer",
            azp: client_id
        };
        if(scope){
            additionalPayload.scope = scope;
        }

        if (this._options.rolesFromIamProvider) {
            const roles = await this._localRolesRepo!.fetchApplicationRoles(client_id);
            additionalPayload.roles = roles;
        } else {
            additionalPayload.roles = loginResponse.roles;
        }

        const accessCode = await this._crypto.generateJWT(
                additionalPayload,
                `app::${client_id}`,
                audience || this._options.defaultAudience!,
                this._options.tokenLifeSecs!
        );

        // TODO verify return
        const ret = {
            token_type: "Bearer",
            scope: null,
            access_token: accessCode,
            expires_in: this._options.tokenLifeSecs!,
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
