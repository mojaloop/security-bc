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

 * ThitsaWorks
 - Si Thu Myo <sithu.myo@thitsaworks.com>

 --------------
 ******/

"use strict";

export enum CertKeyManagementPrivileges {
    UPLOAD_CSR = "SECURITY_UPLOAD_CSR",
    VIEW_CSR_APPROVALS = "SECURITY_VIEW_CSR_APPROVALS",
    VIEW_PUB_CERTIFICATE = "SECURITY_VIEW_PUB_CERTIFICATE",
    VIEW_HUB_PUB_CERTIFICATE = "SECURITY_VIEW_HUB_PUB_CERTIFICATE",
    VIEW_HUB_PRIVATE_KEY = "SECURITY_VIEW_HUB_PRIVATE_KEY",
    CREATE_CERTIFICATE = "SECURITY_CREATE_CERTIFICATE",
    REMOVE_CERTIFICATE = "SECURITY_REMOVE_CERTIFICATE",
    REVOKE_CERTIFICATE = "SECURITY_REVOKE_CERTIFICATE",
    VIEW_REVOKED_CERTIFICATES = "SECURITY_VIEW_REVOKED_CERTIFICATES",
    VERIFY_CERTIFICATE = "SECURITY_VERIFY_CERTIFICATE",
}

export const CertKeyMangementPriviledgesDefinition = [
    {
        privId: CertKeyManagementPrivileges.UPLOAD_CSR,
        labelName: "Upload CSR",
        description: "Allows uploading of Certificate Signing Requests"
    }, {
        privId: CertKeyManagementPrivileges.VIEW_CSR_APPROVALS,
        labelName: "View CSR Approvals",
        description: "Allows fetching of Certificate Signing Requests for approval"
    }, {
        privId: CertKeyManagementPrivileges.VIEW_PUB_CERTIFICATE,
        labelName: "View Public Certificate",
        description: "Allows fetching of the public certificates of participants"
    }, {
        privId: CertKeyManagementPrivileges.VIEW_HUB_PUB_CERTIFICATE,
        labelName: "View Hub Public Certificate",
        description: "Allows fetching of the public certificate of the Hub"
    }, {
        privId: CertKeyManagementPrivileges.CREATE_CERTIFICATE,
        labelName: "Create Certificate",
        description: "Allows creation of certificates for participants"
    }, {
        privId: CertKeyManagementPrivileges.REMOVE_CERTIFICATE,
        labelName: "Remove Certificate",
        description: "Allows removal of certificates of participants"
    }, {
        privId: CertKeyManagementPrivileges.REVOKE_CERTIFICATE,
        labelName: "Revoke Certificate",
        description: "Allows revocation of certificates of participants"
    }, {
        privId: CertKeyManagementPrivileges.VERIFY_CERTIFICATE,
        labelName: "Verify Certificate",
        description: "Allows verification of certificates of participants"
    }
];
