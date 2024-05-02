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
    VIEW_PUB_CERTIFICATE = "SECURITY_VIEW_PUB_CERTIFICATE",
    VIEW_HUB_PUB_CERTIFICATE = "SECURITY_VIEW_HUB_PUB_CERTIFICATE",
    VIEW_CSR_APPROVALS = "SECURITY_VIEW_CSR_APPROVALS",
    UPLOAD_CSR = "SECURITY_UPLOAD_CSR",
    APPROVE_CSR = "SECURITY_APPROVE_CSR",
    REJECT_CSR = "SECURITY_REJECT_CSR",
    VERIFY_CERTIFICATE = "SECURITY_VERIFY_CERTIFICATE",
}

export const CertKeyMangementPriviledgesDefinition = [
    {
        privId: CertKeyManagementPrivileges.VIEW_PUB_CERTIFICATE,
        labelName: "View Public Certificate",
        description: "Allows fetching of the public certificates of participants"
    }, {
        privId: CertKeyManagementPrivileges.VIEW_HUB_PUB_CERTIFICATE,
        labelName: "View Hub Public Certificate",
        description: "Allows fetching of the public certificate of the Hub"
    }, {
        privId: CertKeyManagementPrivileges.VIEW_CSR_APPROVALS,
        labelName: "View CSR Approvals",
        description: "Allows fetching of Certificate Signing Requests for approval"
    }, {
        privId: CertKeyManagementPrivileges.UPLOAD_CSR,
        labelName: "Upload CSR",
        description: "Allows uploading of Certificate Signing Requests"
    }, {
        privId: CertKeyManagementPrivileges.APPROVE_CSR,
        labelName: "Approve CSR",
        description: "Allows approval of Certificate Signing Requests"
    }, {
        privId: CertKeyManagementPrivileges.REJECT_CSR,
        labelName: "Reject CSR",
        description: "Allows rejection of Certificate Signing Requests"
    }, {
        privId: CertKeyManagementPrivileges.VERIFY_CERTIFICATE,
        labelName: "Verify Certificate",
        description: "Allows verification of certificates of participants"
    }
];
