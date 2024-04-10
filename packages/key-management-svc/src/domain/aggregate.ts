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

 * ThitsaWorks
 - Si Thu Myo <sithu.myo@thitsaworks.com>

 --------------
 ******/

"use strict";

import forge from "node-forge";
import { ILogger } from "@mojaloop/logging-bc-public-types-lib";
import { CallSecurityContext, ForbiddenError, IAuthorizationClient, ICSRRequest, IDecodedCSRInfo, IPublicCertificate } from "@mojaloop/security-bc-public-types-lib";
import { CertificateManager } from "./certificate_manager";
import { ISecureCertificateStorage } from "./isecure_storage";
import { CertKeyManagementPrivileges } from "./privileges";

export class KeyManagementAggregate {
    private _logger: ILogger;
    private _certificateManager: CertificateManager;
    private _secureStorage: ISecureCertificateStorage;
    private _authorizationClient: IAuthorizationClient;

    constructor(
        logger: ILogger,
        certManager: CertificateManager,
        secureStorage: ISecureCertificateStorage,
        authorizationClient: IAuthorizationClient
    ) {
        this._logger = logger.createChild(this.constructor.name);
        this._certificateManager = certManager;
        this._secureStorage = secureStorage;
        this._authorizationClient = authorizationClient;
    }

    async getAllCSRRequests(securityContext: CallSecurityContext): Promise<ICSRRequest[]> {
        this._enforcePrivilege(securityContext, CertKeyManagementPrivileges.VIEW_CSR_APPROVALS);
        return this._secureStorage.fetchAllCSRs();
    }

    async getCSRFromId(securityContext: CallSecurityContext, csrId: string): Promise<ICSRRequest | null> {
        this._enforcePrivilege(securityContext, CertKeyManagementPrivileges.VIEW_CSR_APPROVALS);
        return this._secureStorage.fetchCSRWhereCSRId(csrId);
    }

    async getCSRRequestsFromIds(securityContext: CallSecurityContext, csrIds: string[]): Promise<ICSRRequest[]> {
        this._enforcePrivilege(securityContext, CertKeyManagementPrivileges.VIEW_CSR_APPROVALS);
        return this._secureStorage.fetchCSRsWhereCSRIds(csrIds);
    }

    async uploadCSR(securityContext: CallSecurityContext, participantId: string, csr: string): Promise<ICSRRequest> {
        this._enforcePrivilege(securityContext, CertKeyManagementPrivileges.UPLOAD_CSR);
        this._validateCSR(csr);
        const decodedCsrInfo = this._decodeInfoFromCSR(csr);
        const csrRequest: ICSRRequest = {
            csrPEM: csr,
            decodedCsrInfo,
            participantId: participantId,
            createdDate: Date.now(),
        };
        const csrId = await this._secureStorage.storeCSR(csrRequest);
        csrRequest.id = csrId;
        return csrRequest;
    }

    async createCertificateFromCSR(securityContext: CallSecurityContext, csrId: string): Promise<IPublicCertificate> {
        this._enforcePrivilege(securityContext, CertKeyManagementPrivileges.CREATE_CERTIFICATE);

        const csrRequest = await this._secureStorage.fetchCSRWhereCSRId(csrId);
        if (!csrRequest) {
            throw new Error("CSR not found");
        }

        await this._secureStorage.updateCSR(csrId, csrRequest);
        const pubCert = await this._certificateManager.signAndStorePublicCertFromCSR(csrId, csrRequest);
        return pubCert;
    }

    async removeCSR(securityContext: CallSecurityContext, csrId: string): Promise<void> {
        this._enforcePrivilege(securityContext, CertKeyManagementPrivileges.REMOVE_CERTIFICATE);

        const csrRequest = await this._secureStorage.fetchCSRWhereCSRId(csrId);
        if (!csrRequest) {
            throw new Error("CSR not found");
        }
        await this._secureStorage.removeCSR(csrId);
    }

    async getHubCAPubCert(securityContext: CallSecurityContext): Promise<IPublicCertificate | null> {
        this._enforcePrivilege(securityContext!, CertKeyManagementPrivileges.VIEW_HUB_PUB_CERTIFICATE);

        return this._secureStorage.fetchCAHubPublicCert();
    }

    async getPubCert(securityContext: CallSecurityContext, certId: string): Promise<IPublicCertificate | null> {
        this._enforcePrivilege(securityContext, CertKeyManagementPrivileges.VIEW_PUB_CERTIFICATE);

        return this._secureStorage.fetchPublicCertWhereCertId(certId);
    }

    async getPubCerts(securityContext: CallSecurityContext, certId: string[]): Promise<IPublicCertificate[]> {
        this._enforcePrivilege(securityContext, CertKeyManagementPrivileges.VIEW_PUB_CERTIFICATE);

        return this._secureStorage.fetchPublicCertsWhereCertIds(certId);
    }

    async verifyCert(securityContext: CallSecurityContext, certPem: string): Promise<boolean> {
        this._enforcePrivilege(securityContext, CertKeyManagementPrivileges.VERIFY_CERTIFICATE);

        return this._certificateManager.verifyCert(certPem);
    }

    async revokePubCert(securityContext: CallSecurityContext, certId: string, reason: string): Promise<void> {
        this._enforcePrivilege(securityContext, CertKeyManagementPrivileges.REVOKE_CERTIFICATE);

        return this._secureStorage.revokePublicCert(certId, reason);
    }

    private _decodeInfoFromCSR(csrPEM: string): IDecodedCSRInfo {
        const csr = forge.pki.certificationRequestFromPem(csrPEM);

        // Extract the subject information
        const subject = csr.subject.attributes.map(attr => `${attr.name}=${attr.value}`).join(", ");

        // Extract the signature information
        const signatureAlgorithm = csr.signatureOid!;  // OID representing the algorithm
        const signatureLength = csr.signature.byteLength;  // Byte length of the signature

        // Extract extensions, if available
        const extensions: Record<string, any> = {};
        if (csr.attributes) {
            for (const attr of csr.attributes) {
                if (attr.name === "extensionRequest" && Array.isArray(attr.value)) {
                    for (const ext of attr.value) {
                        extensions[ext.name] = ext.value;
                    }
                }
            }
        }

        return {
            subject,
            signatureAlgorithm,
            signatureLength,
            extensions,
        };
    }

    private _enforcePrivilege(secCtx: CallSecurityContext, privilegeId: string): void {
        for (const roleId of secCtx.platformRoleIds) {
            if (this._authorizationClient.roleHasPrivilege(roleId, privilegeId)) {
                return;
            }
        }
        const error = new ForbiddenError(`Required privilege "${privilegeId}" not held by caller`);
        this._logger.isWarnEnabled() && this._logger.warn(error.message);
        throw error;
    }

    private _validateCSR(csrPEM: string): void {
        try {
            // Convert the PEM-formatted CSR to an ASN.1 object
            const csr = forge.pki.certificationRequestFromPem(csrPEM);

            // Check if the CSR is valid and has been signed correctly
            const valid = csr.verify();
            if (!valid) {
                throw new Error("CSR verification failed: CSR is not valid");
            }
        } catch (error) {
            console.error("CSR validation error:", error);
            throw new Error("CSR verification failed: CSR is not valid");
        }
    }
}
