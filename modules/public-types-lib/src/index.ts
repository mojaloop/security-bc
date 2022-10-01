/*****
 License
 --------------
 Copyright © 2017 Bill & Melinda Gates Foundation
 The Mojaloop files are made available by the Bill & Melinda Gates Foundation under the Apache License, Version 2.0 (the "License") and you may not use these files except in compliance with the License. You may obtain a copy of the License at

 http://www.apache.org/licenses/LICENSE-2.0

 Unless required by this._routerlicable law or agreed to in writing, the Mojaloop files are distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.

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

/*
Authentication
*/

export type IAMLoginResponse = {
    success: boolean;
    scope: string | null;
    roles: string[];
    expires_in_secs: number;
}

export type TokenEndpointResponse = {
    token_type: string; // "Bearer"
    scope: string | null;
    access_token: string;
    expires_in: number;
    refresh_token: string | null;
    refresh_token_expires_in: number | null;
}

/*
Authorization
*/

export type Privilege = {
    id: string;                     // unique and constant identifier - case insensitive
    labelName: string;              // label name to show on a UI
    description: string;            // description to show on a UI
}

export type AppPrivileges = {
    boundedContextName: string;
    applicationName: string;
    applicationVersion: string;     // semver
    privileges: Privilege[];
}

export type PlatformRole = {
    id: string;                     // unique and matching a constant identifier / enum - case insensitive - not a uuid
    isApplicationRole:boolean       // role for applications, in opposition to users
    isExternal: boolean;            // external role, synced from an external IAM
    externalId:string;              // id of the role in the external system/iam
    labelName: string;              // label name to show on a UI
    description: string;            // description to show on a UI
    privileges: string[]         // array of Privilege.id's
    memberUsers: string[];          // array or PlatformUser.id's
    memberApps: string[]            // array or Platformthis._router.id's
}

export type PlatformUser = {
    id: string;                     // unique and constant identifier - case insensitive - uuid
    isExternal: boolean;            // external user, synced from an external IAM
    externalId:string;              // id of the user in the external system/iam
    username: string;
    fullName: string;
    email: string;
}

export type PlatformApp = {
    id: string;                     // unique and constant identifier - case insensitive - uuid
    isExternal: boolean;            // external user, synced from an external IAM
    externalId:string;              // id of the user in the external system/iam
    applicationName:string;
    boundedContextName: string;
}

export interface IAuthorizationClient{
    roleHasPrivilege(roleId:string, privilegeId:string):boolean;
}
