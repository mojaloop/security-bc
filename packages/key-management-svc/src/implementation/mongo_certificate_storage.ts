import { MongoClient, Collection } from 'mongodb';
import { ILogger } from "@mojaloop/logging-bc-public-types-lib";
import { ISecureCertificateStorage } from '../domain/isecure_storage';

export class MongoCertificateStorage implements ISecureCertificateStorage {
    private _mongoClient: MongoClient;
    private _collectionName: string = "certificates";
    private _hubID: string = "hub";
    private _collection: Collection;
    private _logger: ILogger;

    constructor(mongoUrl: string, logger: ILogger) {
        this._mongoClient = new MongoClient(mongoUrl);
        this._logger = logger;
    }

    public async init(): Promise<void> {
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
            const result = await this._collection.updateOne({ client_id: client_id }, { $set: { cert } }, { upsert: true });
            if (result.modifiedCount === 0 && result.upsertedCount === 0) {
                throw new Error(`Failed to store certificate for client_id: ${client_id}`);
            }
        } catch (error) {
            throw new Error(`Failed to store certificate for client_id: ${client_id}`);
        }
    }

    public async storeCAHubPrivateKey(privateKey: string): Promise<void> {
        try {
            const result = await this._collection.updateOne({ client_id: this._hubID }, { $set: { privateKey } }, { upsert: true });
            if (result.modifiedCount === 0 && result.upsertedCount === 0) {
                throw new Error(`Failed to store private key for hub`);
            }
        } catch (error) {
            throw new Error(`Failed to store private key for hub`);
        }
    }


    public async getCAHubPrivateKey(): Promise<string> {
        const privateKey = await this._collection
            .findOne({ client_id: this._hubID }, { projection: { _id: 0, client_id: 0 } });

        if (!privateKey) {
            throw new Error(`Private key not found for hub`);
        }
        return privateKey.privateKey;
    }


    public async storeCAHubPublicKey(key: string): Promise<void> {
        try {
            const result = await this._collection.updateOne({ client_id: this._hubID }, { $set: { publicKey: key } }, { upsert: true });
            if (result.modifiedCount === 0 && result.upsertedCount === 0) {
                throw new Error(`Failed to store public key for hub`);
            }
        } catch (error) {
            throw new Error(`Failed to store public key for hub`);
        }
    }

    public async getCAHubPublicKey(): Promise<string> {
        const publicKey = await this._collection
            .findOne({ client_id: this._hubID }, { projection: { _id: 0, client_id: 0 } });

        if (!publicKey) {
            throw new Error(`Public key not found for hub`);
        }
        return publicKey.publicKey;
    }

    public async destroy(): Promise<void> {
        await this._mongoClient.close();
        this._logger.debug("MongoDB connection closed.");
    }
}
