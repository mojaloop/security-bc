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

 * ThitsaWorks
 - Si Thu Myo <sithu.myo@thitsaworks.com>

 --------------
 ******/

"use strict";

// import { ILogger } from "@mojaloop/logging-bc-public-types-lib";
import { RemoveCSRFailedError, CreateCertificateFromCSRFailedError, GetCSRFailedError, GetPublicCertificateFailedError, IAuthenticatedHttpRequester, ICSRRequest, IPublicCertificate, UploadCSRFailedError} from "@mojaloop/security-bc-public-types-lib";

export class KeyMgmtHttpClient {
    // private readonly _logger: ILogger;
    private readonly _baseUrlHttpService: string;
    private readonly _authRequester: IAuthenticatedHttpRequester;

    constructor(
        // logger: ILogger,
        baseUrlHttpService: string,
        authRequester: IAuthenticatedHttpRequester,
    ) {
        // this._logger = logger.createChild(this.constructor.name);
        this._baseUrlHttpService = baseUrlHttpService;
        this._authRequester = authRequester;
    }

    public async uploadCSR(participantId: string, csr: string): Promise<ICSRRequest> {
        const requestInfo = new Request(`${this._baseUrlHttpService}/certs/csrs`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify({
                participantId,
                csr,
            }),

        });
        const response = await this._authRequester.fetch(requestInfo);
        if (!response.ok) {
            throw new UploadCSRFailedError(await response.text());
        }
        return await response.json();
    }

    public async createCertificateFromCSR(csrId: string): Promise<IPublicCertificate> {
        const requestInfo = new Request(`${this._baseUrlHttpService}/certs/csrs/${csrId}/createCertificate`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
        });
        const response = await this._authRequester.fetch(requestInfo);
        if (!response.ok) {
            throw new CreateCertificateFromCSRFailedError(`Failed to create certificate from CSR: ${await response.text()}`);
        }

        return await response.json();
    }

    public async removeCSR(csrId: string): Promise<void> {
        const requestInfo = new Request(`${this._baseUrlHttpService}/certs/csrs/${csrId}`, {
            method: "DELETE",
            headers: {
                "Content-Type": "application/json",
            },
        });
        const response = await this._authRequester.fetch(requestInfo);
        if (!response.ok) {
            throw new RemoveCSRFailedError(`Failed to remove CSR: ${await response.text()}`);
        }
    }

    public async getAllCSRs(): Promise<ICSRRequest[]> {
        const requestInfo = new Request(`${this._baseUrlHttpService}/certs/csrs/`, {
            method: "GET",
            headers: {
                "Content-Type": "application/json",
            },
        });
        const response = await this._authRequester.fetch(requestInfo);
        if (!response.ok) {
            throw new GetCSRFailedError(`Failed to get pending CSR approvals: ${await response.text()}`);
        }
        return await response.json();
    }

    public async getCSRFromId(id: string): Promise<ICSRRequest | null> {
        const requestInfo = new Request(`${this._baseUrlHttpService}/certs/csrs/${id}`, {
            method: "GET",
            headers: {
                "Content-Type": "application/json",
            },
        });
        const response = await this._authRequester.fetch(requestInfo);
        return response.ok ? await response.json() : null;
    }

    public async getCSRsFromIds(ids: string[]): Promise<ICSRRequest[]> {
        const requestInfo = new Request(`${this._baseUrlHttpService}/certs/csrs/${ids.join(",")}/multi`, {
            method: "GET",
            headers: {
                "Content-Type": "application/json",
            }
        });
        const response = await this._authRequester.fetch(requestInfo);
        if (!response.ok) {
            throw new GetCSRFailedError(`Failed to get CSRs from IDs: ${await response.text()}`);
        }
        return await response.json();
    }


    public async getHubCAPubCert(): Promise<IPublicCertificate | null> {
        const requestInfo = new Request(`${this._baseUrlHttpService}/certs/pubCerts/hubCA`, {
            method: "GET",
            headers: {
                "Content-Type": "application/json",
            },
        });
        const response = await this._authRequester.fetch(requestInfo);
        if (!response.ok) {
            return null;
        }
        return await response.json();
    }

    public async getPubCertFromCertId(certId: string): Promise<IPublicCertificate | null> {
        const requestInfo = new Request(`${this._baseUrlHttpService}/certs/pubCerts/${certId}`, {
            method: "GET",
            headers: {
                "Content-Type": "application/json",
            },
        });
        const response = await this._authRequester.fetch(requestInfo);
        if (!response.ok) {
            return null;
        }
        return await response.json();
    }

    public async revokePubCert(certId: string, reason: string): Promise<void> {
        const requestInfo = new Request(`${this._baseUrlHttpService}/certs/pubCerts/${certId}/revoke`, {
            method: "PUT",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify({ reason }),
        });
        const response = await this._authRequester.fetch(requestInfo);
        if (!response.ok) {
            throw new Error(`Failed to revoke public certificate: ${await response.text()}`);
        }
    }

    public async verifyCert(cert: string): Promise<{verified: boolean}> {
        const requestInfo = new Request(`${this._baseUrlHttpService}/certs/verify`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify({
                cert,
            }),
        });
        const response = await this._authRequester.fetch(requestInfo);
        return await response.json();
    }

}
