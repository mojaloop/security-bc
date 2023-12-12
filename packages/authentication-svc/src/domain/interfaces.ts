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

"use strict";


import {UserLoginResponse, LoginResponse} from "@mojaloop/security-bc-public-types-lib";

export interface IAMAuthenticationAdapter {
    init(): Promise<void>;
    loginUser(client_id:string, client_secret:string|null, username:string, password:string): Promise<UserLoginResponse | null>;
    loginApp(client_id:string, client_secret:string): Promise<LoginResponse | null>;
}

export interface ICryptoAuthenticationAdapter {
    init(): Promise<void>;
    generateJWT(additionalPayload:any, sub:string, aud:string, lifeInSecs:number):Promise<{accessToken:string, tokenId:string }>;
    getJwsKeys():Promise<any[]>; // returns an JWS object array, no need to type it
    verifyAndGetSecPrincipalFromToken(accessToken:string):Promise<string|null>;
    // generateRandomToken(length:number):Promise<string>;
}


export interface ILocalRoleAssociationRepo {
    init(): Promise<void>;

    fetchUserPlatformRoles(username:string): Promise<string[]>;
    fetchApplicationPlatformRoles(clientId: string): Promise<string[]>;

    fetchUserPerParticipantRoles(username:string): Promise<{participantId: string, roleId: string}[]>;

    storeUserRoles(username: string, roles: string[]): Promise<void>;
    storeApplicationRoles(clientId: string, roles: string[]): Promise<void>;
}

export interface IJwtIdsRepository{
    init(): Promise<void>;
    destroy(): Promise<void>;

    // Set jwt id / secPrincipalId association that will expire and be automatically removed after tokenExpirationDateTimestamp
    set(secPrincipalId:string, jti:string, tokenExpirationDateTimestamp:number):Promise<void>;

    // Get a list of jwt ids associated with the secPrincipalId (not expired)
    get(secPrincipalId:string):Promise<{jti:string, tokenExpirationDateTimestamp:number}[]>;

    // remove all token association for secPrincipalId
    del(secPrincipalId:string):Promise<void>;
}
