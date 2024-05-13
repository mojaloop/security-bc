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

import { ApprovalRequestState, ICSRRequest, IPublicCertificate } from "@mojaloop/security-bc-public-types-lib";

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
    fetchCSRsWhereParticipantId(participantId: string): Promise<ICSRRequest[]>;
    fetchCSRsWhereRequestState(request_state: ApprovalRequestState): Promise<ICSRRequest[]>;

    storeCSR(csr: ICSRRequest): Promise<string>;
    updateCSR(csrId: string, csr: ICSRRequest): Promise<void>;

    getPublicCert(participantId: string): Promise<string>;
    storePublicCert(participantId: string, cert: IPublicCertificate): Promise<void>;

    storeCAHubPrivateKey(key: string): Promise<void>;
    getCAHubPrivateKey(): Promise<string>;

    storeCAHubRootCert(cert: IPublicCertificate): Promise<void>;

    getCAHubPublicCert(): Promise<IPublicCertificate>;

    destroy(): Promise<void>;
}
