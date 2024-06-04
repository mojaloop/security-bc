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
import { MongoClient, Collection, ObjectId } from "mongodb";
import { ILogger } from "@mojaloop/logging-bc-public-types-lib";
import { ISecureCertificateStorage } from "../domain/isecure_storage";
import { ICSRRequest, IPublicCertificate } from "@mojaloop/security-bc-public-types-lib";

export class MongoCertificateStorage implements ISecureCertificateStorage {
    private _mongoClient: MongoClient;
    private readonly _databaseName: string = "security";

    private _csrCollectionName: string = "certificates_signing_requests";
    private _publicCertCollectionName: string = "certificates_public";
    private _hubPrivateKeyCollectionName: string = "hub_private_key";

    private _hubID: string = "hub";
    private _csrCollection: Collection;
    private _publicCertCollection: Collection;
    private _hubPrivateKeyCollection: Collection;

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
        this._csrCollection = this._mongoClient.db(this._databaseName).collection(this._csrCollectionName);
        this._publicCertCollection = this._mongoClient.db(this._databaseName).collection(this._publicCertCollectionName);
        this._hubPrivateKeyCollection = this._mongoClient.db(this._databaseName).collection(this._hubPrivateKeyCollectionName);
        this._logger.debug("MongoDB connection established.");
    }

    public getCAHubID(): string {
        return this._hubID;
    }

    public async storeCSR(csr: ICSRRequest): Promise<string> {
        try {
            const result = await this._csrCollection.insertOne(csr);
            return result.insertedId.toString();
        } catch (error) {
            throw new Error(`Failed to store CSR for participantId: ${csr.participantId}: ${error}`);
        }
    }

    public async updateCSR(csrId: string, csr: ICSRRequest): Promise<void> {
        const csrObjectId = new ObjectId(csrId);
        await this._csrCollection.updateOne({ _id: csrObjectId }, { $set: csr });
    }

    public async removeCSR(csrId: string): Promise<void> {
        const csrObjectId = new ObjectId(csrId);
        const result = await this._csrCollection.deleteOne({ _id: csrObjectId });
        if (result.deletedCount === 0) {
            throw new Error(`Failed to remove CSR with id: ${csrId}`);
        }
    }

    public async fetchAllCSRs(): Promise<ICSRRequest[]> {
        const csrs = await this._csrCollection.find()
            .toArray();
        return csrs.map(this._mapDocumentToCSRRequest);
    }

    public async fetchCSRWhereCSRId(csrId: string): Promise<ICSRRequest | null> {
        const csrObjectId = new ObjectId(csrId);
        return await this._csrCollection.findOne({ _id: csrObjectId }) as ICSRRequest | null;
    }

    public async fetchCSRsWhereParticipantId(participantId: string): Promise<ICSRRequest[]> {
        const csrs = await this._csrCollection.find({ participantId: participantId })
            .toArray();
        return csrs.map(this._mapDocumentToCSRRequest);
    }

    public async fetchCSRsWhereCSRIds(csrIds: string[]): Promise<ICSRRequest[]> {
        const csrObjectIds = csrIds.map((id) => new ObjectId(id));
        const csrs = await this._csrCollection.find({ _id: { $in: csrObjectIds } })
            .toArray();
        return csrs.map(this._mapDocumentToCSRRequest);
    }

    public async getPublicCert(participantId: string): Promise<string> {
        const cert = await this._publicCertCollection
            .findOne({ participantId: participantId, isRevoked: { $ne: true } }, { projection: { _id: 0, participantId: 0 } });

        if (!cert) {
            throw new Error(`Certificate not found for participantId: ${participantId}`);
        }
        return cert.cert;
    }

    public async getPublicCerts(participantIds: string[]): Promise<IPublicCertificate[]> {
        const certs = await this._publicCertCollection.find({ participantId: { $in: participantIds }, isRevoked: { $ne: true } })
            .project({ _id: 0 })
            .toArray() as IPublicCertificate[];

        return certs;
    }

    public async storePublicCert(participantId: string, cert: IPublicCertificate): Promise<string> {
        if (participantId === this._hubID) {
            this._logger.error(`Attempted to overwrite CA certificate with public cert: ${participantId}`);
            throw new Error("Operation not allowed: Cannot overwrite CA certificate with public certificate.");
        }

        try {
            const result = await this._publicCertCollection.updateOne(
                { participantId: participantId },
                {
                    $set: {
                        cert,
                    }
                },
                { upsert: true }
            );


            if (result.modifiedCount === 0 && result.upsertedCount === 0) {
                throw new Error(`Failed to store certificate for participantId: ${participantId}`);
            }

            return result.upsertedId!.toString();

        } catch (error) {
            throw new Error(`Failed to store certificate for participantId: ${participantId}`);
        }
    }

    public async storeCAHubPrivateKey(privateKey: string): Promise<void> {
        const encryptedKey = this._encrypt(privateKey);
        try {
            const result = await this._hubPrivateKeyCollection.updateOne(
                { participantId: this._hubID },
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
        const privateKey = await this._hubPrivateKeyCollection
            .findOne({ participantId: this._hubID }, { projection: { _id: 0, participantId: 0 } });

        if (!privateKey) {
            throw new Error("Private key not found for hub");
        }
        const decryptedKey = this._decrypt(privateKey.privateKey);
        return decryptedKey;
    }


    public async storeCAHubRootCert(cert: IPublicCertificate): Promise<void> {
        try {
            const result = await this._publicCertCollection.updateOne(
                { participantId: this._hubID },
                {
                    $set: {
                        cert,
                    }
                },
                { upsert: true });
            if (result.modifiedCount === 0 && result.upsertedCount === 0) {
                throw new Error("Failed to store public cert for hub");
            }
        } catch (error) {
            throw new Error("Failed to store public cert for hub");
        }
    }

    public async getCAHubPublicCert(): Promise<IPublicCertificate> {
        const publicCert = await this._publicCertCollection
            .findOne({ participantId: this._hubID, isRevoked: { $ne: true } }, { projection: { _id: 0, participantId: 0 } });

        if (!publicCert) {
            throw new Error("Public key not found for hub");
        }
        return publicCert.cert;
    }

    public async revokePublicCert(participantId: string, reason: string): Promise<void> {
        const updateResult = await this._publicCertCollection.updateOne(
            { participantId: participantId },
            {
                $set: {
                    isRevoked: true,
                    revocationReason: reason,
                    revocationDate: new Date()
                }
            }
        );

        if (updateResult.modifiedCount === 0) {
            throw new Error(`Failed to revoke certificate for participantId: ${participantId}`);
        }
    }

    public async getRevokedPublicCerts(): Promise<IPublicCertificate[]> {
        return await this._publicCertCollection.find({ isRevoked: true })
            .project({ _id: 0 })
            .toArray() as IPublicCertificate[];
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

    _mapDocumentToCSRRequest(csr: any): ICSRRequest {
        return {
            id: csr._id.toString(),
            csrPEM: csr.csrPEM,
            decodedCsrInfo: csr.decodedCsrInfo,
            participantId: csr.participantId,
            createdDate: csr.createdDate
        };
    }

    public async destroy(): Promise<void> {
        await this._mongoClient.close();
        this._logger.debug("MongoDB connection closed.");
    }
}
