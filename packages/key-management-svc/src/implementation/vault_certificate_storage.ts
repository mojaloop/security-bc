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

import { createCipheriv, randomBytes, createDecipheriv, scryptSync } from "crypto";
import Vault from "node-vault";
import { ILogger } from "@mojaloop/logging-bc-public-types-lib";
import { ISecureCertificateStorage } from "../domain/isecure_storage";

export class VaultCertificateStorage implements ISecureCertificateStorage {
    private _client: Vault.client;
    private _logger: ILogger;

    private _scryptKey: Buffer;
    private _isCAEncrypted: boolean;

    constructor(vaultConfig: Vault.Option, logger: ILogger) {
        this._client = Vault(vaultConfig);
        this._logger = logger.createChild(this.constructor.name);
    }

    public async init(CAEncryptionKey: string, isCAEncrypted: boolean = false): Promise<void> {
        this._scryptKey = scryptSync(CAEncryptionKey, "salt", 32);
        this._isCAEncrypted = isCAEncrypted;
        try {
            // Optional: Check if Vault is sealed and unseal if necessary
            const health = await this._client.health();
            if (health.sealed) {
                this._logger.error("Vault is sealed.");
                throw new Error("Vault is sealed.");
                // Additional handling to unseal Vault if needed ??
            }
            this._logger.debug("Vault connection established and unsealed.");
        } catch (err) {
            this._logger.error("Failed to initialize Vault: ", err);
            throw err;
        }
    }

    public async getPublicCert(client_id: string): Promise<string> {
        try {
            const result = await this._client.read(`secret/data/public_certs/${client_id}`);
            return result.data.data.cert;
        } catch (err) {
            this._logger.error(`Failed to retrieve public certificate for client_id ${client_id}: `, err);
            throw new Error(`Certificate not found for client_id: ${client_id}`);
        }
    }

    public async storePublicCert(client_id: string, cert: string): Promise<void> {
        try {
            //  KV Secrets Engine v2 requires to wrapped with `data`
            await this._client.write(`secret/data/public_certs/${client_id}`, { data: { cert } });

            this._logger.debug(`Public certificate stored for client_id: ${client_id}`);
        } catch (err) {
            this._logger.error(`Failed to store public certificate for client_id ${client_id}: `, err);
            throw err;
        }
    }

    public async storeCAHubPrivateKey(privateKey: string): Promise<void> {
        // Need to encrypt for Vault storage?
        try {
            //  KV Secrets Engine v2 requires to wrapped with `data`
            await this._client.write("secret/data/ca/private_key", { data: { privateKey } });
            this._logger.debug("CA private key stored.");
        } catch (err) {
            this._logger.error("Failed to store CA private key: ", err);
            throw err;
        }
    }

    public async getCAHubPrivateKey(): Promise<string> {
        // Need to encrypt for Vault storage?
        try {
            const result = await this._client.read("secret/data/ca/private_key");

            if (!result || !result.data || !result.data.data) {
                throw new Error("Private key not found for hub");
            }

            return result.data.data.privateKey;

        } catch (err) {
            this._logger.error("Failed to retrieve CA private key: ", err);
            throw new Error("Private key not found for hub");
        }
    }

    public async storeCAHubPublicKey(publicKey: string): Promise<void> {
        try {
            await this._client.write("secret/data/ca/public_key", { data: { publicKey } });
            this._logger.debug("CA public key stored.");
        } catch (err) {
            this._logger.error("Failed to store CA public key: ", err);
            throw err;
        }
    }

    public async getCAHubPublicKey(): Promise<string> {
        try {
            const result = await this._client.read("secret/data/ca/public_key");
            return result.data.data.publicKey;
        } catch (err) {
            this._logger.error("Failed to retrieve CA public key: ", err);
            throw new Error("Public key not found for hub");
        }
    }

    _encrypt(text: string): string {
        if (!this._isCAEncrypted) {
            return text; // don't encrypt.. return as is
        }
        const iv = randomBytes(16); // IV should be random for each encryption
        const cipher = createCipheriv("aes-256-gcm", this._scryptKey, iv);
        let encrypted = cipher.update(text, "utf8", "hex");
        encrypted += cipher.final("hex");
        const tag = cipher.getAuthTag();
        return `${iv.toString("hex")}:${tag.toString("hex")}:${encrypted}`;
    }

    _decrypt(encrypted: string): string {
        if (!this._isCAEncrypted) {
            return encrypted; // don't decrypt.. return as is
        }
        const parts = encrypted.split(":");
        const iv = Buffer.from(parts[0], "hex");
        const tag = Buffer.from(parts[1], "hex");
        const text = parts[2];
        const decipher = createDecipheriv("aes-256-gcm", this._scryptKey, iv);
        decipher.setAuthTag(tag);
        let decrypted = decipher.update(text, "hex", "utf8");
        decrypted += decipher.final("utf8");
        return decrypted;
    }

    public async destroy(): Promise<void> {
        // Optionally clear any session or token if needed
        this._logger.debug("Vault session ended.");
    }
}
