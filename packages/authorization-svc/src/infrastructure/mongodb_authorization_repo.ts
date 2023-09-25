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

 * Crosslake
 - Pedro Sousa Barreto <pedrob@crosslaketech.com>

 --------------
 ******/

"use strict";



import {IAuthorizationRepository} from "../domain/interfaces";
import {ILogger} from "@mojaloop/logging-bc-public-types-lib";
import {Collection, MongoClient, WithId} from "mongodb";
import {AppPrivileges, PlatformRole, Privilege} from "@mojaloop/security-bc-public-types-lib";

export class MongoDbAuthorizationRepo implements IAuthorizationRepository{
    private _mongoUri: string;
    private _logger: ILogger;
    private _mongoClient: MongoClient;
    private _rolesCollection: Collection;
    private _privilegesCollection: Collection;

    private _initialized: boolean = false;
    private readonly _databaseName: string = "security";
    private readonly _collectionNameRoles: string = "authz_roles";
    private readonly _collectionNamePrivileges: string = "authz_privileges";

    constructor(mongoUri: string, logger: ILogger) {
        this._logger = logger.createChild(this.constructor.name);
        this._mongoUri = mongoUri;
    }

    async init(): Promise<void> {
        try {
            this._mongoClient = await MongoClient.connect(this._mongoUri);
        } catch (err: any) {
            this._logger.error(err);
            this._logger.isWarnEnabled() &&
            this._logger.warn(
                `init failed with error: ${err?.message?.toString()}`
            );
            throw err;
        }
        if (this._mongoClient === null)
            throw new Error("Couldn't instantiate mongo client");

        const db = this._mongoClient.db(this._databaseName);

        const collections = await db.listCollections().toArray();

        // Check if the Participants collection already exists or create.
        if (collections.find((col) => col.name === this._collectionNameRoles)) {
            this._rolesCollection = db.collection(this._collectionNameRoles);
        } else {
            this._rolesCollection = await db.createCollection(this._collectionNameRoles);
            await this._rolesCollection.createIndex({id: 1}, {unique: true});
        }

        // Check if the Participants collection already exists or create.
        if (collections.find((col) => col.name === this._collectionNamePrivileges)) {
            this._privilegesCollection = db.collection(this._collectionNamePrivileges);
        } else {
            this._privilegesCollection = await db.createCollection(this._collectionNamePrivileges);
            //await this._privilegesCollection.createIndex({id: 1}, {unique: true});
        }

        this._initialized = true;
        this._logger.info("initialized");
    }

    /* Privileges */

    private _appPrivilegeIdString(boundedContextName: string, applicationName: string): string{
        return boundedContextName.toUpperCase()+"::"+applicationName.toUpperCase();
    }

    async fetchAllAppPrivileges(): Promise<AppPrivileges[]> {
        const found = await this._privilegesCollection
            .find({})
            .project({_id: 0})
            .toArray();
        return found as AppPrivileges[];
    }


    async fetchAppPrivileges(boundedContextName: string, applicationName: string): Promise<AppPrivileges | null> {
        const found = await this._privilegesCollection.findOne(
            {boundedContextName: boundedContextName, applicationName: applicationName},
            {projection: {_id: 0}}
        );

        return found as AppPrivileges | null;
    }

    async storeAppPrivileges(priv: AppPrivileges): Promise<void> {
        try {
            const updateResult = await this._privilegesCollection.replaceOne(
                {boundedContextName: priv.boundedContextName, applicationName: priv.applicationName},
                priv,
                {upsert: true}
            );

            if ((updateResult.upsertedCount + updateResult.modifiedCount) !== 1) {
                const err = new Error("Could not storeAppPrivileges - mismatch between requests length and MongoDb response length");
                this._logger.error(err);
                throw err;
            }
        } catch (error: unknown) {
            this._logger.error(error);
            throw error;
        }
    }

    /* Roles */

    async fetchAllPlatformRoles(): Promise<PlatformRole[]> {
        const found = await this._rolesCollection
            .find({})
            .project({_id: 0})
            .toArray();
        return found as PlatformRole[];
    }

    async fetchPlatformRole(roleId: string): Promise<PlatformRole | null> {
        const found = await this._rolesCollection.findOne(
            {id: roleId},
            {projection: {_id: 0}}
        );
        return found as PlatformRole | null;
    }

    async fetchPrivilege(privilegeId: string): Promise<Privilege | null> {
        const found = await this._privilegesCollection.findOne(
            {id: privilegeId},
            {projection: {_id: 0}}
        );
        return found as PlatformRole | null;
    }



    async storePlatformRole(role: PlatformRole): Promise<void> {
        try {
            const updateResult = await this._rolesCollection.replaceOne(
                {id: role.id},
                role,
                {upsert: true}
            );

            if ((updateResult.upsertedCount + updateResult.modifiedCount) !== 1) {
                const err = new Error("Could not storePlatformRole - mismatch between requests length and MongoDb response length");
                this._logger.error(err);
                throw err;
            }
        } catch (error: unknown) {
            this._logger.error(error);
            throw error;
        }
    }


}
