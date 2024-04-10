/*****
 License
 --------------
 Copyright © 2017 Bill & Melinda Gates Foundation
 The Mojaloop files are made available by the Bill & Melinda Gates Foundation under the Apache License, Version 2.0 (the "License") and you may not use these files except in compliance with the License. You may obtain a copy of the License at

 http://www.apache.org/licenses/LICENSE-2.0

 Unless required by this._routerlicable law or agreed to in writing, the Mojaloop files are distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.

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

export class UploadCSRFailedError extends Error {}
export class GetCSRFailedError extends Error {}
export class GetPublicCertificateFailedError extends Error {}
export class VerifyPublicCertificateFailedError extends Error {}
export class CreateCertificateFromCSRFailedError extends Error {}
export class RevokeCertificateFailedError extends Error {}
export class RemoveCSRFailedError extends Error {}

export interface IDecodedCSRInfo {
    subject: string;
    signatureAlgorithm?: string | null;
    signatureLength: number;
    extensions: Record<string, any>;
}

export declare interface ICSRRequest {
    id?: string;
    csrPEM: string;
    decodedCsrInfo?: IDecodedCSRInfo;
    participantId: string;
    createdDate: number;
}

export declare interface IPublicCertificate {
    id?: string;
    csrRequestId?: string | null;
    participantId: string;
    keyFingerprint: string;
    pubCertificatePem: string;
    certType: "HUB_CA" | "HUB_INTERMEDIATE" | "DFSP";
    decodedCertInfo?: IDecodedCertificateInfo;

    isRevoked?: boolean;
    revocationReason?: string;
    revocationDate?: Date;

    createdDate: number;
}

export interface IDecodedCertificateInfo {
    subject: string;
    issuer: string;
    validFrom: string;
    validTo: string;
    serialNumber: string;
    signatureAlgorithm: string;
    extensions: Record<string, any>;
}

