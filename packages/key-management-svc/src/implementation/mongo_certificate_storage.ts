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

import { createCipheriv, randomBytes, createDecipheriv, scryptSync } from "crypto";
import { MongoClient, Collection } from "mongodb";
import { ILogger } from "@mojaloop/logging-bc-public-types-lib";
import { ISecureCertificateStorage } from "../domain/isecure_storage";

export class MongoCertificateStorage implements ISecureCertificateStorage {
    private _mongoClient: MongoClient;
    private _collectionName: string = "certificates";
    private _hubID: string = "hub";
    private _collection: Collection;
    private _logger: ILogger;

    private _scryptKey: Buffer;
    private _isCAEncrypted: boolean;

    constructor(mongoUrl: string, logger: ILogger) {
        this._mongoClient = new MongoClient(mongoUrl);
        this._logger = logger;
    }

    public async init(CAEncryptionKey: string, isCAEncrypted: boolean = false): Promise<void> {
        this._scryptKey = scryptSync(CAEncryptionKey, "salt", 32);
        this._isCAEncrypted = isCAEncrypted;

        await this._mongoClient.connect();
        this._collection = this._mongoClient.db().collection(this._collectionName);
        this._logger.debug("MongoDB connection established.");
    }

    public async getPublicCert(client_id: string): Promise<string> {
        const cert = await this._collection
            .findOne({ client_id: client_id }, { projection: { _id: 0, client_id: 0 } });

        if (!cert) {
            throw new Error(`Certificate not found for client_id: ${client_id}`);
        }
        return cert.cert;
    }

    public async storePublicCert(client_id: string, cert: string): Promise<void> {
        if (client_id === this._hubID) {
            this._logger.error(`Attempted to overwrite CA certificate with public cert: ${client_id}`);
            throw new Error("Operation not allowed: Cannot overwrite CA certificate with public certificate.");
        }

        try {
            const result = await this._collection.updateOne(
                { client_id: client_id },
                { $set: { cert } },
                { upsert: true }
            );
            if (result.modifiedCount === 0 && result.upsertedCount === 0) {
                throw new Error(`Failed to store certificate for client_id: ${client_id}`);
            }
        } catch (error) {
            throw new Error(`Failed to store certificate for client_id: ${client_id}`);
        }
    }

    public async storeCAHubPrivateKey(privateKey: string): Promise<void> {
        const encryptedKey = this._encrypt(privateKey);
        try {
            const result = await this._collection.updateOne(
                { client_id: this._hubID },
                {
                    $set: {
                        privateKey: encryptedKey,
                        isEncrypted: this._isCAEncrypted
                    }
                },
                { upsert: true }
            );
            if (result.modifiedCount === 0 && result.upsertedCount === 0) {
                throw new Error("Failed to store private key for hub");
            }
        } catch (error) {
            throw new Error("Failed to store private key for hub");
        }
    }


    public async getCAHubPrivateKey(): Promise<string> {
        const privateKey = await this._collection
            .findOne({ client_id: this._hubID }, { projection: { _id: 0, client_id: 0 } });

        if (!privateKey) {
            throw new Error("Private key not found for hub");
        }
        const decryptedKey = this._decrypt(privateKey.privateKey);
        return decryptedKey;
    }


    public async storeCAHubPublicKey(key: string): Promise<void> {
        try {
            const result = await this._collection.updateOne(
                { client_id: this._hubID },
                {
                    $set: {
                        publicKey: key,
                    }
                },
                { upsert: true });
            if (result.modifiedCount === 0 && result.upsertedCount === 0) {
                throw new Error("Failed to store public key for hub");
            }
        } catch (error) {
            throw new Error("Failed to store public key for hub");
        }
    }

    public async getCAHubPublicKey(): Promise<string> {
        const publicKey = await this._collection
            .findOne({ client_id: this._hubID }, { projection: { _id: 0, client_id: 0 } });

        if (!publicKey) {
            throw new Error("Public key not found for hub");
        }
        return publicKey.publicKey;
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
        await this._mongoClient.close();
        this._logger.debug("MongoDB connection closed.");
    }
}
