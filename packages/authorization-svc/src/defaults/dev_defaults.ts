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
        id: "basic-application",
        description: "Role for applications that can boostrap own privileges, fetch own priv/role associations, bootstrap and read own platform configurations",
        labelName: "basic-application roles",
        isExternal: false,
        externalId: undefined,
        isApplicationRole: true,
        isPerParticipantRole: false,
        privileges: [
            "SECURITY_BOOTSTRAP_PRIVILEGES",
            "SECURITY_FETCH_APP_ROLE_PRIVILEGES_ASSOCIATIONS",
            "PLATFORM_CONFIGURATION_VIEW_GLOBAL",
            "PLATFORM_CONFIGURATION_BOOSTRAP_BOUNDED_CONTEXT",
            "PLATFORM_CONFIGURATION_VIEW_BOUNDED_CONTEXT",
        ]
    }, {
		id: "hub_operator",
		description: "Default dev Hub Operator Role",
		labelName: "Hub Operator",
		isExternal: false,
		externalId: undefined,
		isApplicationRole: false,
        isPerParticipantRole: false,
		privileges: [
			"VIEW_PARTICIPANT",
			"CREATE_PARTICIPANT",
			"APPROVE_PARTICIPANT",
			"ENABLE_PARTICIPANT",
			"DISABLE_PARTICIPANT",
			"MANAGE_ENDPOINTS",
			"CREATE_PARTICIPANT_ACCOUNT",
			"CHANGE_PARTICIPANT_ACCOUNT_BANK_DETAILS",
			"APPROVE_PARTICIPANT_ACCOUNT_CREATION_REQUEST",
			"APPROVE_PARTICIPANT_ACCOUNT_BANK_DETAILS_CHANGE_REQUEST",
            "CREATE_PARTICIPANT_SOURCE_IP_CHANGE_REQUEST",
            "APPROVE_PARTICIPANT_SOURCE_IP_CHANGE_REQUEST",
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
            "SETTLEMENTS_CREATE_STATIC_MATRIX",
            "SETTLEMENTS_CREATE_DYNAMIC_MATRIX",
            "SETTLEMENTS_EXECUTE_MATRIX",
            "SETTLEMENTS_GET_MATRIX",
            "SETTLEMENTS_RETRIEVE_BATCH",
            "SETTLEMENTS_RETRIEVE_BATCH_ACCOUNTS",
            "SETTLEMENTS_RETRIEVE_TRANSFERS",
            "SETTLEMENTS_CLOSE_MATRIX",
            "SETTLEMENTS_SETTLE_MATRIX",
            "SETTLEMENTS_DISPUTE_MATRIX",
            "PLATFORM_CONFIGURATION_VIEW_GLOBAL",
            "PLATFORM_CONFIGURATION_BOOSTRAP_GLOBAL",
            "PLATFORM_CONFIGURATION_VIEW_ALL_BOUNDED_CONTEXT",
            "PLATFORM_CONFIGURATION_VIEW_BOUNDED_CONTEXT",
            "PLATFORM_CONFIGURATION_BOOSTRAP_BOUNDED_CONTEXT",
            "PLATFORM_CONFIGURATION_CHANGE_VALUES_BOUNDED_CONTEXT",
            "TRANSFERS_VIEW_ALL_TRANSFERS",
            "CREATE_NDC_CHANGE_REQUEST",
            "APPROVE_NDC_CHANGE_REQUEST",
			"QUOTING_VIEW_ALL_QUOTES",
			"ACCOUNT_LOOKUP_VIEW_PARTY_PARTICIPANT_ID",
			"ACCOUNT_LOOKUP_VIEW_ALL_ORACLES",
			"ACCOUNT_LOOKUP_CREATE_ORACLE",
			"ACCOUNT_LOOKUP_REMOVE_ORACLE",
			"ACCOUNT_LOOKUP_VIEW_ALL_ORACLE_ASSOCIATIONS",
      "CERTIFICATES_VIEW_CERTIFICATES",
      "CERTIFICATES_CREATE_REQUEST",
      "CERTIFICATES_APPROVE_REQUEST",
      "CERTIFICATES_REJECT_REQUEST",
		]
	}, {
		id: "admin",
		description: "Default dev Admin Role",
		labelName: "Admin",
		isExternal: false,
		externalId: undefined,
		isApplicationRole: false,
        isPerParticipantRole: false,
		privileges: [
			"VIEW_PARTICIPANT",
			"CREATE_PARTICIPANT",
			"APPROVE_PARTICIPANT",
			"ENABLE_PARTICIPANT",
			"DISABLE_PARTICIPANT",
			"MANAGE_ENDPOINTS",
            "CREATE_PARTICIPANT_ACCOUNT",
            "CHANGE_PARTICIPANT_ACCOUNT_BANK_DETAILS",
            "APPROVE_PARTICIPANT_ACCOUNT_CREATION_REQUEST",
            "APPROVE_PARTICIPANT_ACCOUNT_BANK_DETAILS_CHANGE_REQUEST",
            "CREATE_PARTICIPANT_SOURCE_IP_CHANGE_REQUEST",
            "APPROVE_PARTICIPANT_SOURCE_IP_CHANGE_REQUEST",
            "CREATE_PARTICIPANT_STATUS_CHANGE_REQUEST",
            "APPROVE_PARTICIPANT_STATUS_CHANGE_REQUEST",
            "CREATE_PARTICIPANT_CONTACT_INFO_CHANGE_REQUEST",
            "APPROVE_PARTICIPANT_CONTACT_INFO_CHANGE_REQUEST",
            "SECURITY_BUILTIN_IAM_CHANGE_APP_SECRETS",
            "CREATE_LIQUIDITY_ADJUSTMENT_BULK_REQUEST",
            "APPROVE_PENDING_APPROVAL_BULK_REQUEST",
            "VIEW_ALL_PENDING_APPROVALS",
            "APPROVE_PENDING_APPROVAL_BULK_REQUEST",
            "CREATE_NDC_CHANGE_REQUEST",
            "APPROVE_NDC_CHANGE_REQUEST",
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
			"SETTLEMENTS_CREATE_STATIC_MATRIX",
			"SETTLEMENTS_CREATE_DYNAMIC_MATRIX",
			"SETTLEMENTS_EXECUTE_MATRIX",
			"SETTLEMENTS_GET_MATRIX_REQUEST",
			"SETTLEMENTS_RETRIEVE_BATCH",
			"SETTLEMENTS_RETRIEVE_BATCH_ACCOUNTS",
			"SETTLEMENTS_RETRIEVE_TRANSFERS",
			"SETTLEMENTS_CLOSE_MATRIX",
			"SETTLEMENTS_SETTLE_MATRIX",
			"SETTLEMENTS_DISPUTE_MATRIX",
            "PLATFORM_CONFIGURATION_VIEW_GLOBAL",
            "PLATFORM_CONFIGURATION_BOOSTRAP_GLOBAL",
            "PLATFORM_CONFIGURATION_CHANGE_VALUES_GLOBAL",
            "PLATFORM_CONFIGURATION_VIEW_ALL_BOUNDED_CONTEXT",
            "PLATFORM_CONFIGURATION_VIEW_BOUNDED_CONTEXT",
            "PLATFORM_CONFIGURATION_BOOSTRAP_BOUNDED_CONTEXT",
            "PLATFORM_CONFIGURATION_CHANGE_VALUES_BOUNDED_CONTEXT",
            "TRANSFERS_VIEW_ALL_TRANSFERS",
			"QUOTING_VIEW_ALL_QUOTES",
			"ACCOUNT_LOOKUP_VIEW_PARTY_PARTICIPANT_ID",
			"ACCOUNT_LOOKUP_VIEW_ALL_ORACLES",
			"ACCOUNT_LOOKUP_CREATE_ORACLE",
			"ACCOUNT_LOOKUP_REMOVE_ORACLE",
			"ACCOUNT_LOOKUP_VIEW_ALL_ORACLE_ASSOCIATIONS",
            "SECURITY_VIEW_PRIVILEGE",
            "SECURITY_VIEW_ROLE",
            "SECURITY_CREATE_ROLE",
            "SECURITY_DELETE_ROLE",
            "SECURITY_ADD_PRIVILEGES_TO_ROLE",
            "SECURITY_REMOVE_PRIVILEGES_FROM_ROLE",
            "SECURITY_BUILTIN_IAM_CREATE_USER",
            "SECURITY_BUILTIN_IAM_VIEW_ALL_USERS",
            "SECURITY_BUILTIN_IAM_ENABLE_USER",
            "SECURITY_BUILTIN_IAM_DISABLE_USER",
            "SECURITY_BUILTIN_IAM_MANAGE_USER_ROLES",
            "SECURITY_BUILTIN_IAM_CREATE_APP",
            "SECURITY_BUILTIN_IAM_VIEW_ALL_APPS",
            "SECURITY_BUILTIN_IAM_ENABLE_APP",
            "SECURITY_BUILTIN_IAM_DISABLE_APP",
            "SECURITY_BUILTIN_IAM_MANAGE_APP_ROLES",
      "CERTIFICATES_VIEW_CERTIFICATES",
      "CERTIFICATES_CREATE_REQUEST",
      "CERTIFICATES_APPROVE_REQUEST",
      "CERTIFICATES_REJECT_REQUEST"
		]
	}, {
		id: "participants-bc-participants-svc",
		description: "participants-bc-participants-svc roles",
		labelName: "participants-bc-participants-svc roles",
		isExternal: false,
		externalId: undefined,
		isApplicationRole: true,
        isPerParticipantRole: false,
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
        isPerParticipantRole: false,
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
        isPerParticipantRole: false,
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
	},{
		id: "account-lookup-bc-account-lookup-svc",
		description: "account-lookup-bc-account-lookup-svc roles",
		labelName: "account-lookup-bc-account-lookup-svc roles",
		isExternal: false,
		externalId: undefined,
		isApplicationRole: true,
        isPerParticipantRole: false,
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
        isPerParticipantRole: false,
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
        isPerParticipantRole: false,
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
        isPerParticipantRole: false,
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
            "SETTLEMENTS_CREATE_STATIC_MATRIX",
            "SETTLEMENTS_CREATE_DYNAMIC_MATRIX",
            "SETTLEMENTS_EXECUTE_MATRIX",
            "SETTLEMENTS_GET_MATRIX_REQUEST",
            "SETTLEMENTS_RETRIEVE_BATCH",
            "SETTLEMENTS_RETRIEVE_BATCH_ACCOUNTS",
            "SETTLEMENTS_RETRIEVE_TRANSFERS",
            "SETTLEMENTS_CLOSE_MATRIX",
            "SETTLEMENTS_SETTLE_MATRIX",
            "SETTLEMENTS_DISPUTE_MATRIX",
            "SETTLEMENTS_LOCK_MATRIX",
            "SETTLEMENTS_UNLOCK_MATRIX"
		]
	}, {
		id: "settlements-bc-api-svc",
		description: "settlements-bc-api-svc roles",
		labelName: "settlements-bc-api-svc roles",
		isExternal: false,
		externalId: undefined,
		isApplicationRole: true,
        isPerParticipantRole: false,
		privileges: [
]
	},{
        id: "reporting-bc-reporting-api-svc",
        description: "reporting-bc-reporting-api-svc roles",
        labelName: "reporting-bc-reporting-api-svc roles",
        isExternal: false,
        externalId: undefined,
        isApplicationRole: true,
        isPerParticipantRole: false,
        privileges: [
            "VIEW_PARTICIPANT"
        ]
    },{
        id: "reporting-bc-participants-reporting-svc",
        description: "reporting-bc-participants-reporting-svc roles",
        labelName: "reporting-bc-participants-reporting-svc roles",
        isExternal: false,
        externalId: undefined,
        isApplicationRole: true,
        isPerParticipantRole: false,
        privileges: [
            "VIEW_PARTICIPANT",
        ]
    },{
        id: "reporting-bc-quotes-reporting-svc",
        description: "reporting-bc-quotes-reporting-svc roles",
        labelName: "reporting-bc-quotes-reporting-svc roles",
        isExternal: false,
        externalId: undefined,
        isApplicationRole: true,
        isPerParticipantRole: false,
        privileges: [
            "QUOTING_VIEW_ALL_QUOTES",
        ]
    },{
        id: "reporting-bc-settlements-reporting-svc",
        description: "reporting-bc-settlements-reporting-svc roles",
        labelName: "reporting-bc-settlements-reporting-svc roles",
        isExternal: false,
        externalId: undefined,
        isApplicationRole: true,
        isPerParticipantRole: false,
        privileges: [
            "SETTLEMENTS_GET_MATRIX_REQUEST",
            "SETTLEMENTS_RETRIEVE_BATCH",
            "SETTLEMENTS_RETRIEVE_BATCH_ACCOUNTS",
            "SETTLEMENTS_RETRIEVE_TRANSFERS",
        ]
    }

];
