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


import {IAMLoginResponse} from "@mojaloop/security-bc-public-types-lib";

export interface IAMAuthenticationAdapter {
    init(): Promise<void>;
    loginUser(client_id:string, client_secret:string|null, username:string, password:string): Promise<IAMLoginResponse>;
    loginApp(client_id:string, client_secret:string): Promise<IAMLoginResponse>;

    userExists(username:string):Promise<boolean>;
    appExists(client_id:string):Promise<boolean>;
}


export interface ICryptoAuthenticationAdapter {
    init(): Promise<void>;
    generateJWT(additionalPayload:any, sub:string, aud:string, lifeInSecs:number):Promise<string>;
    getJwsKeys():Promise<any[]>; // returns an JWS object array, no need to type it
    // generateRandomToken(length:number):Promise<string>;
}


export interface ILocalRoleAssociationRepo {
    init(): Promise<void>;

    fetchUserRoles(username:string): Promise<string[]>;
    fetchApplicationRoles(clientId: string): Promise<string[]>;

    storeUserRoles(username: string, roles: string[]): Promise<void>;
    storeApplicationRoles(clientId: string, roles: string[]): Promise<void>;
}