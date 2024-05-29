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

export const defaultDevUsers = [
	{id:"user", userType: "HUB", fullName: "Dev User", password: "superPass", platformRoles: ["hub_operator"]},
	{id: "admin", userType: "HUB", fullName: "Dev Admin", password: "superMegaPass", platformRoles:["admin"]},
];

// Applications that can't login on their own have a null secret and no roles
// Ex: UIs or APIs that always call other services using the caller/user token
export const defaultDevApplications = [
	{client_id: "admin-ui", client_secret: null},
    {client_id: "security-bc-ui", client_secret: null},

    // TODO bad name, rename it to bcname-appname
    {client_id: "platform-configuration-bc-api-svc", client_secret: "superServiceSecret", platformRoles: ["basic-application","platform-configuration-bc-api-svc"]},

    {client_id: "participants-bc-participants-svc", client_secret: "superServiceSecret", platformRoles:["basic-application","participants-bc-participants-svc"]},

    {client_id: "accounts-and-balances-bc-coa-grpc-svc", client_secret: "superServiceSecret", platformRoles:["basic-application","accounts-and-balances-bc-coa-grpc-svc"]},
    {client_id: "accounts-and-balances-bc-builtinledger-grpc-svc", client_secret: "superServiceSecret", platformRoles:["basic-application"]},

    {client_id: "transfers-bc-api-svc", client_secret: "superServiceSecret", platformRoles:["basic-application"]},
    {client_id: "transfers-bc-event-handler-svc", client_secret: "superServiceSecret", platformRoles:["basic-application"]},
    {client_id: "transfers-bc-command-handler-svc", client_secret: "superServiceSecret", platformRoles:["basic-application","transfers-bc-command-handler-svc"]},

    {client_id: "account-lookup-bc-account-lookup-svc", client_secret: "superServiceSecret", platformRoles:["basic-application","account-lookup-bc-account-lookup-svc"]},

    {client_id: "interop-api-bc-fspiop-api-svc", client_secret: "superServiceSecret", platformRoles:["basic-application","interop-api-bc-fspiop-api-svc"]},

    {client_id: "quoting-bc-api-svc", client_secret: "superServiceSecret", platformRoles: ["basic-application"]},
    {client_id: "quoting-bc-command-handler-svc", client_secret: "superServiceSecret", platformRoles: ["basic-application","quoting-bc-command-handler-svc"]},

    {client_id: "settlements-bc-command-handler-svc", client_secret: "superServiceSecret", platformRoles: ["basic-application","settlements-bc-command-handler-svc"]},
    {client_id: "settlements-bc-event-handler-svc", client_secret: "superServiceSecret", platformRoles: ["basic-application","settlements-bc-event-handler-svc"]},
    {client_id: "settlements-bc-api-svc", client_secret: "superServiceSecret", platformRoles: ["basic-application","settlements-bc-api-svc"]},

    {client_id: "security-bc-identity-svc", client_secret: "superServiceSecret", platformRoles: ["basic-application"]},

    {client_id: "reporting-bc-reporting-api-svc", client_secret: "superServiceSecret", platformRoles: ["basic-application","reporting-bc-reporting-api-svc"]},
    {client_id: "reporting-bc-participants-reporting-svc", client_secret: "superServiceSecret", platformRoles: ["basic-application","reporting-bc-participants-reporting-svc"]},
    {client_id: "reporting-bc-transfers-reporting-svc", client_secret: "superServiceSecret", platformRoles: ["basic-application"]},
    {client_id: "reporting-bc-quotes-reporting-svc", client_secret: "superServiceSecret", platformRoles: ["basic-application","reporting-bc-quotes-reporting-svc"]},
    {client_id: "reporting-bc-settlements-reporting-svc", client_secret: "superServiceSecret", platformRoles: ["basic-application","reporting-bc-settlements-reporting-svc"]},

    {client_id: "certs-management-bc-mcm-internal-svc", client_secret: "superServiceSecret", platformRoles:["basic-application"]},
];
