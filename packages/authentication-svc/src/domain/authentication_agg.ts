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


import {
    IAMAuthenticationAdapter,
    ICryptoAuthenticationAdapter,
    IJwtIdsRepository,
    ILocalRoleAssociationRepo
} from "./interfaces";
import {ILogger} from "@mojaloop/logging-bc-public-types-lib";
import {TokenEndpointResponse, UnauthorizedError} from "@mojaloop/security-bc-public-types-lib";
import {IMessageProducer} from "@mojaloop/platform-shared-lib-messaging-types-lib";
import {AuthTokenInvalidatedEvt} from "@mojaloop/platform-shared-lib-public-messages-lib";

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
    private _logger:ILogger;
    private _iam:IAMAuthenticationAdapter;
    private _crypto:ICryptoAuthenticationAdapter;
    private readonly _localRolesRepo: ILocalRoleAssociationRepo | null;
    private readonly _jwtIdsRepo:IJwtIdsRepository;
    private readonly _messageProducer:IMessageProducer;
    private readonly _options: AuthenticationAggregateOptions;

    constructor(
        iam:IAMAuthenticationAdapter,
        crypto:ICryptoAuthenticationAdapter,
        logger: ILogger,
        localRolesRepo: ILocalRoleAssociationRepo | null,
        jwtIdsRepo:IJwtIdsRepository,
        messageProducer:IMessageProducer,
        options?: AuthenticationAggregateOptions
    ) {
        this._logger = logger.createChild(this.constructor.name);
        this._iam = iam;
        this._crypto = crypto;
        this._localRolesRepo = localRolesRepo;
        this._jwtIdsRepo = jwtIdsRepo;
        this._messageProducer = messageProducer;
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

    private async _logout(secPrincipalId:string):Promise<void>{
        this._logger.info(`Logging out secPrincipalId: ${secPrincipalId}`);

        const tokenIds = await this._jwtIdsRepo.get(secPrincipalId);
        if(!tokenIds) return;

        const messages:AuthTokenInvalidatedEvt[] = [];

        for(const item of tokenIds){
            messages.push(new AuthTokenInvalidatedEvt({
                tokenId: item.jti,
                tokenExpirationDateTimestamp: item.tokenExpirationDateTimestamp
            }));
        }

        if(messages.length>0) await this._messageProducer.send(messages);
        await this._jwtIdsRepo.del(secPrincipalId);
    }

    async logoutToken(accessToken:string):Promise<void>{
        const secPrincipal = await this._crypto.verifyAndGetSecPrincipalFromToken(accessToken);

        if(!secPrincipal) throw new UnauthorizedError();

        await this._logout(secPrincipal);
    }


    async loginUser(client_id:string, client_secret:string | null, username:string, password:string, audience?:string, scope?:string):Promise<TokenEndpointResponse | null> {
        if(!username || !password){
            this._logger.info("rejected user login without username or password");
            return null;
        }

        const loginResponse = await this._iam.loginUser(client_id, client_secret, username, password);

        if (!loginResponse) {
            this._logger.debug(`User Login FAILED for username: ${username} and client_id: ${client_id}`);
            return null;
        }

        const additionalPayload:any = {
            typ: "Bearer",
            azp: client_id,
            userType: loginResponse.userType
            //testObj: "pedro1",
        };

        if(scope){
            additionalPayload.scope = scope;
        }

        if(this._options.rolesFromIamProvider){
            additionalPayload.platformRoles = await this._localRolesRepo!.fetchUserPlatformRoles(username) || [];
            additionalPayload.participantRoles = await this._localRolesRepo!.fetchUserPerParticipantRoles(username) || [];
        }else{
            additionalPayload.platformRoles = loginResponse.platformRoles || [];
            additionalPayload.participantRoles = loginResponse.participantRoles || [];
        }

        // apply the minimum duration between the local setting and the IAM response (if one was provided, ie, gt 0)
        const tokenLifeSecs = Math.min(this._options.tokenLifeSecs!, loginResponse.expires_in || this._options.tokenLifeSecs!);

        const genJwtResp = await this._crypto.generateJWT(
            additionalPayload,
            `user::${username}`,
            audience || this._options.defaultAudience!,
            tokenLifeSecs
        );

        await this._jwtIdsRepo.set(username, genJwtResp.tokenId, Date.now() + tokenLifeSecs * 1000);

        // TODO verify return
        const ret = {
            token_type: "Bearer",
            scope: null,
            access_token: genJwtResp.accessToken,
            expires_in: tokenLifeSecs,
            refresh_token: null,
            refresh_token_expires_in: null
        };
        this._logger.info(`App Login successful for username: ${username}`);
        return ret;
    }

    async logoutUser(username:string):Promise<void>{
        await this._logout(username);
    }

    async loginApp(client_id:string, client_secret:string, audience?:string, scope?:string):Promise<TokenEndpointResponse | null> {
        if(!client_id || !client_secret){
            this._logger.info("rejected user login without username or password");
            return null;
        }

        const loginResponse = await this._iam.loginApp(client_id, client_secret);

        if (!loginResponse) {
            this._logger.info(`App Login FAILED for client_id: ${client_id}`);
            return null;
        }

        const additionalPayload:any = {
            typ: "Bearer",
            azp: client_id,
            participantRoles: [] // apps don't have per participant roles
        };
        if(scope){
            additionalPayload.scope = scope;
        }

        if(this._options.rolesFromIamProvider){
            additionalPayload.platformRoles = await this._localRolesRepo!.fetchApplicationPlatformRoles(client_id) || [];
        }else{
            additionalPayload.platformRoles = loginResponse.platformRoles || [];
        }

        // apply the minimum duration between the local setting and the IAM response (if one was provided, ie, gt 0)
        const tokenLifeSecs = Math.min(this._options.tokenLifeSecs!, loginResponse.expires_in || this._options.tokenLifeSecs!);

        const genJwtResp = await this._crypto.generateJWT(
            additionalPayload,
            `app::${client_id}`,
            audience || this._options.defaultAudience!,
            tokenLifeSecs
        );

        await this._jwtIdsRepo.set(client_id, genJwtResp.tokenId, Date.now() + tokenLifeSecs * 1000);

        // TODO verify return
        const ret = {
            token_type: "Bearer",
            scope: null,
            access_token: genJwtResp.accessToken,
            expires_in: tokenLifeSecs,
            refresh_token: null,
            refresh_token_expires_in: null
        };

        this._logger.info(`App Login successful for client_id: ${client_id}`);

        return ret;
    }

    async logoutApp(client_id:string):Promise<void>{
        await this._logout(client_id);
    }

    getSupportedGrants():string[]{
        return SUPPORTED_GRANTS;
    }
}
