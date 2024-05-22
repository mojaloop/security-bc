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

/*
Authorization specific
*/

export interface IAuthorizationClient {
    roleHasPrivilege(roleId: string, privilegeId: string): boolean;
    rolesHavePrivilege(roleIds: string[], privilegeId: string): boolean;

	addPrivilege(privId: string, labelName: string, description: string): void;

	addPrivilegesArray(privsArray: { privId: string, labelName: string, description: string }[]): void;
}

export type Privilege = {
	id: string;                     // unique and constant identifier - case insensitive
	labelName: string;              // label name to show on a UI
	description: string;            // description to show on a UI
}

export type PrivilegeWithOwnerAppInfo = Privilege & {
    boundedContextName: string;     // bounded context it belongs to
    privilegeSetVersion: string;     // semver
}

export type BoundedContextPrivileges = {
	boundedContextName: string;
	privilegeSetVersion: string;     // semver from the BC privilege set, usually set by the domain code of the BC
	privileges: Privilege[];
}

export type PlatformRole = {
    // unique and matching a constant identifier / enum - case insensitive - not a uuid
    id: string;
    // role for applications, in opposition to users
    isApplicationRole: boolean;
    // external role, synced from an external IAM
    isExternal: boolean;
    // id of the role in the external system/iam
    externalId: string | null | undefined;
    // label name to show on a UI
    labelName: string;
    // description to show on a UI
    description: string;
    // array of Privilege.id's
    privileges: string[];
    // role can only be attributed in conjunction with a participant id (not a system-wide role)
    isPerParticipantRole: boolean;

	//  membership association is from authN,
	// // if using external IAM, users and apps will com e with role association
	// memberUserIds: string[];                  // array of PlatformUser.id's
	// memberAppIds: string[]                    // array of PlatformApp.id's
}



// export type PlatformUser = {
//     id: string;                     // unique and constant identifier - case-insensitive - uuid
//     isExternal: boolean;            // external user, synced from an external IAM
//     externalId:string;              // id of the user in the external system/iam
//     username: string;               // corresponds to a username from the IAM provider
//     fullName: string;
//     email: string;
//     roleIds:string[];               // array or PlatformRole.id the user belongs to
// }
//
// export type PlatformApp = {
//     id: string;                     // unique and constant identifier - case-insensitive
//     isExternal: boolean;            // external user, synced from an external IAM
//     externalId: string;             // id of the user in the external system/iam
//     client_id: string;              // corresponds to a client_id from the IAM provider
//     applicationName: string;
//     boundedContextName: string;
//     roleIds: string[];               // array or PlatformRole.id the application belongs to
// }
