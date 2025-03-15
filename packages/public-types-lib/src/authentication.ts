/// <reference lib="dom" />
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

/*
Authentication specific
*/
import {CallSecurityContext} from "./generic_types";

export type UserType = "HUB" | "DFSP";

export type ParticipantRole = {
    participantId: string;
    roleId: string;
}

export type LoginResponse = {
    scope: string | null;
    platformRoles: string[];
    expires_in: number;
}

export type UserLoginResponse = LoginResponse & {
    userType: UserType
    participantRoles: ParticipantRole[];
}

export type TokenEndpointResponse = {
    token_type: string; // "Bearer"
    scope: string | null;
    access_token: string;
    expires_in: number;
    refresh_token: string | null;
    refresh_token_expires_in: number | null;
}

export type AuthToken = {
    payload: any;
    accessToken: string; // original access token
    accessTokenExpiresIn: number; // timestamp
    refreshToken: string | null | undefined; // original refresh token
    refreshTokenExpiresIn: number | null | undefined; // timestamp
    scope: string | null | undefined;
}


export interface ITokenHelper {
    init(): Promise<void>;
    destroy(): Promise<void>;
    decodeToken(accessToken: string): any | null;
    verifyToken(accessToken: string): Promise<boolean>;
    getCallSecurityContextFromAccessToken(accessToken:string):Promise<CallSecurityContext|null>;
}

export interface ILoginHelper {
    setUserCredentials(client_id: string, username: string, password: string): void;
    setAppCredentials(client_id: string, client_secret: string): void;
    setToken(accessToken: string): void;

    getToken(): Promise<AuthToken>;
}

export interface IAuthenticatedHttpRequester {
    initialised: boolean;
    setUserCredentials(client_id: string, username: string, password: string): void;
    setAppCredentials(client_id: string, client_secret: string): void;
    fetch(requestInfo: RequestInfo, timeoutMs?: number): Promise<Response>;
}
