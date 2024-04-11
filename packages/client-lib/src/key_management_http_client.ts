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

import {ILogger} from "@mojaloop/logging-bc-public-types-lib";
import {IAuthenticatedHttpRequester} from "@mojaloop/security-bc-public-types-lib";

export class KeyMgmtHttpClient {
    // Properties received through the constructor.
    // private readonly _logger: ILogger;
    // Other properties.
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

    public async UploadCSR(csr: string): Promise<string> {
        const requestInfo = new Request(`${this._baseUrlHttpService}/certs/upload-csr`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify({
                csr,
            }),

        });
        // const response = await this._authRequester.fetch(requestInfo);
        const response = await fetch(requestInfo); // This is a temporary fix to avoid unable to send csr to the server.
        if (!response.ok) {
            throw new Error(`Failed to upload CSR: ${await response.text()}`);
        }
        return await response.text();
    }

    public async GetHubCAPubCert(): Promise<string> {
        const requestInfo = new Request(`${this._baseUrlHttpService}/certs/hub-pub-cert`, {
            method: "GET",
            headers: {
                "Content-Type": "application/json",
            },
        });
        // const response = await this._authRequester.fetch(requestInfo);
        const response = await fetch(requestInfo); // Temporary fix
        if (!response.ok) {
            throw new Error(`Failed to get Hub CA Public Cert: ${await response.text()}`);
        }
        return await response.text();
    }

}
