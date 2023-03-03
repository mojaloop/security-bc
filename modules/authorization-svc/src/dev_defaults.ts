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

import {PlatformRole} from "@mojaloop/security-bc-public-types-lib";

export const defaultDevRoles:PlatformRole[] = [
	{
		id: "tests",
		description: "test role for automated unit/integration tests",
		labelName: "tests",
		isExternal: false,
		externalId: undefined,
		isApplicationRole: false,
		privileges: [
			"TEST_EXAMPLE_PRIV"
		]
	},{
		id: "hub_operator",
		description: "Default dev Hub Operator Role",
		labelName: "Hub Operator",
		isExternal: false,
		externalId: undefined,
		isApplicationRole: false,
		privileges: [
			"VIEW_PARTICIPANT",
			"CREATE_PARTICIPANT",
			"APPROVE_PARTICIPANT",
			"ENABLE_PARTICIPANT",
			"DISABLE_PARTICIPANT",
			"MANAGE_ENDPOINTS",
			"MANAGE_ACCOUNTS",
			"CREATE_FUNDS_DEPOSIT",
			"CREATE_FUNDS_WITHDRAWAL",
			"APPROVE_FUNDS_DEPOSIT",
			"APPROVE_FUNDS_WITHDRAWAL",
			"COA_VIEW_ACCOUNT",
			"COA_CREATE_ACCOUNT",
			"BUILTIN_LEDGER_VIEW_ACCOUNT",
			"BUILTIN_LEDGER_CREATE_ACCOUNT",
			"SETTLEMENTS_CREATE_BATCH_ACCOUNT",
			"SETTLEMENTS_CREATE_BATCH",
			"SETTLEMENTS_CREATE_TRANSFER",
			"SETTLEMENTS_REQUEST_MATRIX",
			"SETTLEMENTS_EXECUTE_MATRIX",
			"SETTLEMENTS_GET_MATRIX_REQUEST",
			"SETTLEMENTS_RETRIEVE_BATCH",
			"SETTLEMENTS_RETRIEVE_BATCH_ACCOUNTS",
			"SETTLEMENTS_RETRIEVE_TRANSFERS"
		]
	},
	{
		id: "admin",
		description: "Default dev Admin Role",
		labelName: "Admin",
		isExternal: false,
		externalId: undefined,
		isApplicationRole: false,
		privileges: [
			"VIEW_PARTICIPANT",
			"CREATE_PARTICIPANT",
			"APPROVE_PARTICIPANT",
			"ENABLE_PARTICIPANT",
			"DISABLE_PARTICIPANT",
			"MANAGE_ENDPOINTS",
			"MANAGE_ACCOUNTS",
			"CREATE_FUNDS_DEPOSIT",
			"CREATE_FUNDS_WITHDRAWAL",
			"APPROVE_FUNDS_DEPOSIT",
			"APPROVE_FUNDS_WITHDRAWAL",
			"COA_CREATE_ACCOUNT",
			"COA_CREATE_JOURNAL_ENTRY",
			"COA_VIEW_ACCOUNT",
			"COA_VIEW_JOURNAL_ENTRY",
			"BUILTIN_LEDGER_CREATE_ACCOUNT",
			"BUILTIN_LEDGER_CREATE_JOURNAL_ENTRY",
			"BUILTIN_LEDGER_VIEW_ACCOUNT",
			"BUILTIN_LEDGER_VIEW_JOURNAL_ENTRY",
			"BUILTIN_LEDGER_DEACTIVATE_ACCOUNT",
			"BUILTIN_LEDGER_REACTIVATE_ACCOUNT",
			"BUILTIN_LEDGER_DELETE_ACCOUNT",
			"SETTLEMENTS_CREATE_BATCH_ACCOUNT",
			"SETTLEMENTS_CREATE_BATCH",
			"SETTLEMENTS_CREATE_TRANSFER",
			"SETTLEMENTS_REQUEST_MATRIX",
			"SETTLEMENTS_EXECUTE_MATRIX",
			"SETTLEMENTS_GET_MATRIX_REQUEST",
			"SETTLEMENTS_RETRIEVE_BATCH",
			"SETTLEMENTS_RETRIEVE_BATCH_ACCOUNTS",
			"SETTLEMENTS_RETRIEVE_TRANSFERS"
		]
	},{
		id: "participants-bc-participants-svc",
		description: "participants-bc-participants-svc roles",
		labelName: "participants-bc-participants-svc roles",
		isExternal: false,
		externalId: undefined,
		isApplicationRole: true,
		privileges: [
			"COA_CREATE_ACCOUNT",
			"COA_CREATE_JOURNAL_ENTRY",
			"COA_VIEW_ACCOUNT",
			"COA_VIEW_JOURNAL_ENTRY",
			"BUILTIN_LEDGER_VIEW_ACCOUNT",
			"BUILTIN_LEDGER_CREATE_ACCOUNT",

		]
	}, {
		id: "accounts-and-balances-bc-coa-grpc-svc",
		description: "accounts-and-balances-bc-coa-grpc-svc roles",
		labelName: "accounts-and-balances-bc-coa-grpc-svc roles",
		isExternal: false,
		externalId: undefined,
		isApplicationRole: true,
		privileges: [
			"BUILTIN_LEDGER_CREATE_ACCOUNT",
			"BUILTIN_LEDGER_CREATE_JOURNAL_ENTRY",
			"BUILTIN_LEDGER_VIEW_ACCOUNT",
			"BUILTIN_LEDGER_VIEW_JOURNAL_ENTRY",
			"BUILTIN_LEDGER_DEACTIVATE_ACCOUNT",
			"BUILTIN_LEDGER_REACTIVATE_ACCOUNT",
			"BUILTIN_LEDGER_DELETE_ACCOUNT"
		]
	}, {
		id: "transfers-bc-command-handler-svc",
		description: "transfers-bc-command-handler-svc roles",
		labelName: "transfers-bc-command-handler-svc roles",
		isExternal: false,
		externalId: undefined,
		isApplicationRole: true,
		privileges: [
			"VIEW_PARTICIPANT",
			"COA_VIEW_ACCOUNT",
			"COA_VIEW_JOURNAL_ENTRY",
			"COA_CREATE_ACCOUNT",
			"COA_CREATE_JOURNAL_ENTRY",
			"BUILTIN_LEDGER_VIEW_ACCOUNT",
			"BUILTIN_LEDGER_VIEW_JOURNAL_ENTRY",
			"BUILTIN_LEDGER_CREATE_ACCOUNT",
			"BUILTIN_LEDGER_CREATE_JOURNAL_ENTRY",
		]
	}, {
		id: "account-lookup-bc-account-lookup-svc",
		description: "account-lookup-bc-account-lookup-svc roles",
		labelName: "account-lookup-bc-account-lookup-svc roles",
		isExternal: false,
		externalId: undefined,
		isApplicationRole: true,
		privileges: [
			"VIEW_PARTICIPANT"
		]
	}, {
		id: "interop-api-bc-fspiop-api-svc",
		description: "interop-api-bc-fspiop-api-svc roles",
		labelName: "interop-api-bc-fspiop-api-svc roles",
		isExternal: false,
		externalId: undefined,
		isApplicationRole: true,
		privileges: [
			"VIEW_PARTICIPANT"
		]
	}, {
		id: "quoting-bc-quoting-svc",
		description: "quoting-bc-quoting-svc roles",
		labelName: "quoting-bc-quoting-svc roles",
		isExternal: false,
		externalId: undefined,
		isApplicationRole: true,
		privileges: [
			"VIEW_PARTICIPANT"
		]
	}, {
		id: "settlements-bc-command-handler-svc",
		description: "settlements-bc-command-handler-svc roles",
		labelName: "settlements-bc-command-handler-svc roles",
		isExternal: false,
		externalId: undefined,
		isApplicationRole: true,
		privileges: [
			"VIEW_PARTICIPANT",
			"COA_VIEW_ACCOUNT",
			"COA_VIEW_JOURNAL_ENTRY",
			"COA_CREATE_ACCOUNT",
			"COA_CREATE_JOURNAL_ENTRY",
			"BUILTIN_LEDGER_VIEW_ACCOUNT",
			"BUILTIN_LEDGER_VIEW_JOURNAL_ENTRY",
			"BUILTIN_LEDGER_CREATE_ACCOUNT",
			"BUILTIN_LEDGER_CREATE_JOURNAL_ENTRY",
			"SETTLEMENTS_CREATE_BATCH_ACCOUNT",
			"SETTLEMENTS_CREATE_BATCH",
			"SETTLEMENTS_CREATE_TRANSFER",
			"SETTLEMENTS_REQUEST_MATRIX",
			"SETTLEMENTS_EXECUTE_MATRIX",
			"SETTLEMENTS_GET_MATRIX_REQUEST",
			"SETTLEMENTS_RETRIEVE_BATCH",
			"SETTLEMENTS_RETRIEVE_BATCH_ACCOUNTS",
			"SETTLEMENTS_RETRIEVE_TRANSFERS"
		]
	}, {
		id: "settlements-bc-api-svc",
		description: "settlements-bc-api-svc roles",
		labelName: "settlements-bc-api-svc roles",
		isExternal: false,
		externalId: undefined,
		isApplicationRole: true,
		privileges: [
			"VIEW_PARTICIPANT",
			"COA_VIEW_ACCOUNT",
			"COA_VIEW_JOURNAL_ENTRY",
			"COA_CREATE_ACCOUNT",
			"COA_CREATE_JOURNAL_ENTRY",
			"BUILTIN_LEDGER_VIEW_ACCOUNT",
			"BUILTIN_LEDGER_VIEW_JOURNAL_ENTRY",
			"BUILTIN_LEDGER_CREATE_ACCOUNT",
			"BUILTIN_LEDGER_CREATE_JOURNAL_ENTRY",
			"SETTLEMENTS_CREATE_BATCH_ACCOUNT",
			"SETTLEMENTS_CREATE_BATCH",
			"SETTLEMENTS_CREATE_TRANSFER",
			"SETTLEMENTS_REQUEST_MATRIX",
			"SETTLEMENTS_EXECUTE_MATRIX",
			"SETTLEMENTS_GET_MATRIX_REQUEST",
			"SETTLEMENTS_RETRIEVE_BATCH",
			"SETTLEMENTS_RETRIEVE_BATCH_ACCOUNTS",
			"SETTLEMENTS_RETRIEVE_TRANSFERS"
		]
	}

];
