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

import { ICSRRequest, IPublicCertificate } from "@mojaloop/security-bc-public-types-lib";

export enum SECURE_CERTIFICATE_STORAGE_TYPE {
    // add more storage types here
    MONGO = "mongo",
    MONGODB = "mongodb",
}

export interface ISecureCertificateStorage {
    init(secret_key: string, is_ca_encrypted: boolean,): Promise<void>;

    getCAHubID(): string;

    _encrypt(data: string): string;
    _decrypt(data: string): string;

    fetchAllCSRs(): Promise<ICSRRequest[]>;
    fetchCSRWhereCSRId(csrId: string): Promise<ICSRRequest | null>;
    fetchCSRsWhereCSRIds(csrIds: string[]): Promise<ICSRRequest[]>;
    fetchCSRsWhereParticipantId(participantId: string): Promise<ICSRRequest[]>;

    storeCSR(csr: ICSRRequest): Promise<string>;
    updateCSR(csrId: string, csr: ICSRRequest): Promise<void>;
    removeCSR(csrId: string): Promise<void>;

    fetchPublicCertWhereCertId(certId: string): Promise<IPublicCertificate | null>;
    fetchPublicCertsWhereCertIds(certIds: string[]): Promise<IPublicCertificate[]>;

    storePublicCert(participantId: string, cert: IPublicCertificate): Promise<string>;

    storeCAHubPrivateKey(key: string): Promise<void>;
    fetchCAHubPrivateKey(): Promise<string>;

    storeCAHubRootCert(cert: IPublicCertificate): Promise<void>;

    fetchCAHubPublicCert(): Promise<IPublicCertificate | null>;

    revokePublicCert(certId: string, reason: string): Promise<void>;
    fetchRevokedPublicCerts(): Promise<IPublicCertificate[]>;

    destroy(): Promise<void>;
}
