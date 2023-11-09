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

export enum AuthorizationPrivileges {
    VIEW_PRIVILEGE = "SECURITY_VIEW_PRIVILEGE",
    VIEW_ROLE = "SECURITY_VIEW_ROLE",
    CREATE_ROLE = "SECURITY_CREATE_ROLE",
    DELETE_ROLE = "SECURITY_DELETE_ROLE",
    ADD_PRIVILEGES_TO_ROLE = "SECURITY_ADD_PRIVILEGES_TO_ROLE",
    REMOVE_PRIVILEGES_FROM_ROLE = "SECURITY_REMOVE_PRIVILEGES_FROM_ROLE",
    FETCH_APP_ROLE_PRIVILEGES_ASSOCIATIONS = "SECURITY_FETCH_APP_ROLE_PRIVILEGES_ASSOCIATIONS",
    BOOTSTRAP_PRIVILEGES = "SECURITY_BOOTSTRAP_PRIVILEGES",
}

export const AuthorizationPrivilegesDefinition = [
    {
        privId: AuthorizationPrivileges.VIEW_PRIVILEGE,
        labelName: "View Privileges",
        description: "Allows fetching/consultation of Security Privileges"
    },{
        privId: AuthorizationPrivileges.VIEW_ROLE,
        labelName: "View Roles",
        description: "Allows fetching/consultation of Security Platform Roles"
    },{
        privId: AuthorizationPrivileges.CREATE_ROLE,
        labelName: "Create new Roles",
        description: "Allows creation of Security Platform Roles in the Authorization Service"
    },{
        privId: AuthorizationPrivileges.DELETE_ROLE,
        labelName: "Remove existing Roles",
        description: "Allows removal of Security Platform Roles from the Authorization Service"
    },{
        privId: AuthorizationPrivileges.ADD_PRIVILEGES_TO_ROLE,
        labelName: "Add Privileges to a Role",
        description: "Allows the association of Privileges to an existing Role"
    },{
        privId: AuthorizationPrivileges.REMOVE_PRIVILEGES_FROM_ROLE,
        labelName: "Remove Privileges from Role",
        description: "Allows the disassociation of existing Privileges from an existing Role"
    },{
        privId: AuthorizationPrivileges.FETCH_APP_ROLE_PRIVILEGES_ASSOCIATIONS,
        labelName: "Fetch applications role/priv associations",
        description: "Allows an application to fetch the roles containing its own privileges"
    },{
        privId: AuthorizationPrivileges.BOOTSTRAP_PRIVILEGES,
        labelName: "Bootstrap application privileges",
        description: "Allows bootstrapping of an application specific privileges to the central authorization service"
    }
];
