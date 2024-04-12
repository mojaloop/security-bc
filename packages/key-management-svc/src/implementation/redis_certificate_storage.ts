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

import Redis from 'ioredis';
import { createCipheriv, randomBytes, createDecipheriv, scryptSync } from 'crypto';
import { ILogger } from "@mojaloop/logging-bc-public-types-lib";
import { ISecureCertificateStorage } from '../domain/isecure_storage';

export class RedisCertificateStorage implements ISecureCertificateStorage {
    private _redisClient: Redis;
    private _logger: ILogger;

    private _scryptKey: Buffer;
    private _isCAEncrypted: boolean;

    constructor(redisUrl: string, logger: ILogger) {
        this._redisClient = new Redis(redisUrl);
        this._logger = logger.createChild(this.constructor.name);
    }

    public async init(CAEncryptionKey: string, isCAEncrypted: boolean = false): Promise<void> {
        this._scryptKey = scryptSync(CAEncryptionKey, 'salt', 32);
        this._isCAEncrypted = isCAEncrypted;

        this._redisClient.on('connect', () => {
            this._logger.debug("Redis connection established.");
        });
        this._redisClient.on('error', (err) => {
            this._logger.error("Redis connection error: ", err);
        });
    }

    public async getPublicCert(client_id: string): Promise<string> {
        const cert = await this._redisClient.get(`cert:public:${client_id}`);
        if (!cert) {
            throw new Error(`Certificate not found for client_id: ${client_id}`);
        }
        return cert;
    }

    public async storePublicCert(client_id: string, cert: string): Promise<void> {
        await this._redisClient.set(`cert:public:${client_id}`, cert);
        this._logger.debug(`Public certificate stored for client_id: ${client_id}`);
    }

    public async storeCAHubPrivateKey(privateKey: string): Promise<void> {
        let encryptedPrivateKey = this._encrypt(privateKey);
        await this._redisClient.set('ca:privateKey', encryptedPrivateKey);
        this._logger.debug("CA private key stored.");
    }

    public async getCAHubPrivateKey(): Promise<string> {
        const privateKey = await this._redisClient.get('ca:privateKey');
        if (!privateKey) {
            throw new Error("Private key not found for hub");
        }
        return this._decrypt(privateKey);
    }

    public async storeCAHubPublicKey(publicKey: string): Promise<void> {
        await this._redisClient.set('ca:publicKey', publicKey);
        this._logger.debug("CA public key stored.");
    }

    public async getCAHubPublicKey(): Promise<string> {
        const publicKey = await this._redisClient.get('ca:publicKey');
        if (!publicKey) {
            throw new Error("Public key not found for hub");
        }
        return publicKey;
    }

    public async destroy(): Promise<void> {
        await this._redisClient.quit();
        this._logger.debug("Redis connection closed.");
    }

    _encrypt(text: string): string {
        if (!this._isCAEncrypted) {
            // don't encrypt.. return as is
            return text;
        }
        const iv = randomBytes(16); // IV should be random for each encryption
        const cipher = createCipheriv('aes-256-gcm', this._scryptKey, iv);
        let encrypted = cipher.update(text, 'utf8', 'hex');
        encrypted += cipher.final('hex');
        const tag = cipher.getAuthTag();
        return `${iv.toString('hex')}:${tag.toString('hex')}:${encrypted}`;
    }

    _decrypt(encrypted: string): string {
        if (!this._isCAEncrypted) {
            // data is not encrypted.. return as is
            return encrypted;
        }
        const parts = encrypted.split(':');
        const iv = Buffer.from(parts[0], 'hex');
        const tag = Buffer.from(parts[1], 'hex');
        const text = parts[2];
        const decipher = createDecipheriv('aes-256-gcm', this._scryptKey, iv);
        decipher.setAuthTag(tag);
        let decrypted = decipher.update(text, 'hex', 'utf8');
        decrypted += decipher.final('utf8');
        return decrypted;
    }

}
