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

import { ILogger } from "@mojaloop/logging-bc-public-types-lib";
import { ISecureCertificateStorage } from "../domain/isecure_storage";
import { promises as fs } from "fs";
import path from "path";

export class LocalCertificateStorage implements ISecureCertificateStorage {
    private _logger: ILogger;
    private _certificates: Map<string, string> = new Map<string, string>();

    private _localCertStoragePath: string;
    private _filenamePostfix: string = "-pub.pem";

    private _caHubPrivateFilePath: string;
    private _caHubPublicFilePath: string;

    constructor(localCertStoragePath: string, caPrivateKeyPath: string, caPublicKeyPath: string, logger: ILogger) {
        this._localCertStoragePath = path.join(__dirname, "../../", localCertStoragePath)
        this._caHubPrivateFilePath = path.join(__dirname, "../../", caPrivateKeyPath)
        this._caHubPublicFilePath = path.join(__dirname, "../../", caPublicKeyPath)
        this._logger = logger;

        this._logger.debug(`LocalCertificateStorage: localCertStoragePath: ${this._localCertStoragePath}`);
        this._logger.debug(`LocalCertificateStorage: caPrivateKeyPath: ${this._caHubPrivateFilePath}`);
        this._logger.debug(`LocalCertificateStorage: caPublicKeyPath: ${this._caHubPublicFilePath}`);
    }

    public async init(): Promise<void> {
        try {
            fs.mkdir(this._localCertStoragePath, { recursive: true });
        } catch (error) {
            throw new Error(`Error creating storage path ${this._localCertStoragePath} for certificates: ${(error as Error).message}`);
        }
    }

    public async getPublicCert(client_id: string): Promise<string> {
        const sanitizedClientId = this._sanitizeClientId(client_id);
        const pubCertFilename = path.join(this._localCertStoragePath, sanitizedClientId + this._filenamePostfix);

        if (this._certificates.has(sanitizedClientId)) {
            return this._certificates.get(sanitizedClientId) as string;
        }

        try {
            const cert = await fs.readFile(pubCertFilename, 'utf8');
            this._certificates.set(sanitizedClientId, cert);
            return cert;
        } catch (error) {
            throw new Error(`Error reading public cert file: ${pubCertFilename}`);
        }
    }

    public async storePublicCert(client_id: string, cert: string): Promise<void> {
        const sanitizedClientId = this._sanitizeClientId(client_id);
        const pubCertFilename = path.join(this._localCertStoragePath, sanitizedClientId + this._filenamePostfix);

        // Prevent accidental overwriting CA certificates with public participants' certificates
        if (pubCertFilename === this._caHubPrivateFilePath || pubCertFilename === this._caHubPublicFilePath) {
            this._logger.error(`Attempted to overwrite CA certificate with public cert: ${sanitizedClientId}`);
            throw new Error("Operation not allowed: Cannot overwrite CA certificate with public certificate.");
        }

        try {
            await fs.writeFile(pubCertFilename, cert);
            this._certificates.set(sanitizedClientId, cert);
        } catch (error) {
            this._logger.error(`Error writing public cert file: `, error);
            throw new Error(`Error writing public cert file: ${pubCertFilename}`);
        }
    }

    public async storeCAHubPrivateKey(key: string): Promise<void> {
        try {
            await fs.writeFile(this._caHubPrivateFilePath, key);
        } catch (error) {
            throw new Error(`Error writing private cert file: ${this._caHubPrivateFilePath}`);
        }
    }

    public async getCAHubPrivateKey(): Promise<string> {
        try {
            return await fs.readFile(this._caHubPrivateFilePath, "utf8");
        } catch (error) {
            throw new Error(`Error reading private cert file: ${this._caHubPrivateFilePath}`);
        }
    }

    public async storeCAHubPublicKey(key: string): Promise<void> {
        try {
            await fs.writeFile(this._caHubPublicFilePath, key);
        } catch (error) {
            this._logger.error(`Error writing public cert file: `, error);
            throw new Error(`Error writing public cert file: ${this._caHubPublicFilePath}`);
        }
    }

    public async getCAHubPublicKey(): Promise<string> {
        try {
            return await fs.readFile(this._caHubPublicFilePath, "utf8");
        } catch (error) {
            throw new Error(`Error reading public cert file: ${this._caHubPublicFilePath}`);
        }
    }

    private _sanitizeClientId(client_id: string): string {
        // Only allow alphanumeric characters, hyphen, and underscore
        return client_id.replace(/[^a-zA-Z0-9-_ ]/g, '').trim();
    }

    public async destroy(): Promise<void> {
        this._certificates.clear();
    }
}
