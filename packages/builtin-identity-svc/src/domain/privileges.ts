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

export enum BuiltinIdentityPrivileges {
    CREATE_USER = "SECURITY_BUILTIN_IAM_CREATE_USER",
    VIEW_ALL_USERS = "SECURITY_BUILTIN_IAM_VIEW_ALL_USERS",
    ENABLE_USER = "SECURITY_BUILTIN_IAM_ENABLE_USER",
    DISABLE_USER = "SECURITY_BUILTIN_IAM_DISABLE_USER",
    MANAGE_USER_ROLES = "SECURITY_BUILTIN_IAM_MANAGE_USER_ROLES",
    CREATE_APP = "SECURITY_BUILTIN_IAM_CREATE_APP",
    VIEW_ALL_APPS = "SECURITY_BUILTIN_IAM_VIEW_ALL_APPS",
    ENABLE_APP = "SECURITY_BUILTIN_IAM_ENABLE_APP",
    DISABLE_APP = "SECURITY_BUILTIN_IAM_DISABLE_APP",
    MANAGE_APP_ROLES = "SECURITY_BUILTIN_IAM_MANAGE_APP_ROLES",
    CHANGE_APP_SECRETS = "SECURITY_BUILTIN_IAM_CHANGE_APP_SECRETS",
}

export const BuiltinIdentityPrivilegesDefinition = [
    {
        privId: BuiltinIdentityPrivileges.CREATE_USER,
        labelName: "Create Users",
        description: "Allows creation of users in the Builtin Identity Service"
    },{
        privId: BuiltinIdentityPrivileges.VIEW_ALL_USERS,
        labelName: "View All Users",
        description: "Allows retrieving information of all users in the Builtin Identity Service"
    },{
        privId: BuiltinIdentityPrivileges.ENABLE_USER,
        labelName: "Enable Users",
        description: "Allows enabling of users in the Builtin Identity Service"
    },{
        privId: BuiltinIdentityPrivileges.DISABLE_USER,
        labelName: "Disable Users",
        description: "Allows disabling of users in the Builtin Identity Service"
    },{
        privId: BuiltinIdentityPrivileges.MANAGE_USER_ROLES,
        labelName: "Manage Users' Roles",
        description: "Allows adding and removing roles to users in the Builtin Identity Service"
    },{
        privId: BuiltinIdentityPrivileges.CREATE_APP,
        labelName: "Create Applications",
        description: "Allows creation of applications in the Builtin Identity Service"
    },{
        privId: BuiltinIdentityPrivileges.VIEW_ALL_APPS,
        labelName: "View All Applications",
        description: "Allows retrieving information of all applications in the Builtin Identity Service"
    },{
        privId: BuiltinIdentityPrivileges.ENABLE_APP,
        labelName: "Enable Applications",
        description: "Allows enabling of applications in the Builtin Identity Service"
    },{
        privId: BuiltinIdentityPrivileges.DISABLE_APP,
        labelName: "Disable Applications",
        description: "Allows disabling of applications in the Builtin Identity Service"
    },{
        privId: BuiltinIdentityPrivileges.MANAGE_APP_ROLES,
        labelName: "Manage Applications' Roles",
        description: "Allows adding and removing roles to applications in the Builtin Identity Service"
    }
];
