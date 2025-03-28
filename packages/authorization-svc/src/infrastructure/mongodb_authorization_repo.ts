/*****
License
--------------
Copyright © 2020-2025 Mojaloop Foundation
The Mojaloop files are made available by the Mojaloop Foundation under the Apache License, Version 2.0 (the "License") and you may not use these files except in compliance with the License. You may obtain a copy of the License at

 http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, the Mojaloop files are distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.

Contributors
--------------
This is the official list of the Mojaloop project contributors for this file.
Names of the original copyright holders (individuals or organizations)
should be listed with a '*' in the first column. People who have
contributed from an organization can be listed under the organization
that actually holds the copyright for their contributions (see the
Mojaloop Foundation for an example). Those individuals should have
their names indented and be marked with a '-'. Email address can be added
optionally within square brackets <email>.

* Mojaloop Foundation
- Name Surname <name.surname@mojaloop.io>

* Crosslake
- Pedro Sousa Barreto <pedrob@crosslaketech.com>
*****/

"use strict";



import {IAuthorizationRepository} from "../domain/interfaces";
import {ILogger} from "@mojaloop/logging-bc-public-types-lib";
import {Collection, MongoClient, WithId} from "mongodb";
import {
    BoundedContextPrivileges,
    PlatformRole,
    Privilege,
    PrivilegeWithOwnerBcInfo
} from "@mojaloop/security-bc-public-types-lib";

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

    /* privilege simple types (flat privs with apps/bc/app_ver) */

    async fetchAllPrivileges(): Promise<PrivilegeWithOwnerBcInfo[]> {
        const found = await this._privilegesCollection.find({})
            .project({_id: 0})
            .toArray() as BoundedContextPrivileges[];

        const resp:PrivilegeWithOwnerBcInfo[] = found.flatMap(appPriv => appPriv.privileges.map(priv => {
            return {
                boundedContextName: appPriv.boundedContextName,
                privilegeSetVersion: appPriv.privilegeSetVersion,
                id: priv.id,
                labelName: priv.labelName,
                description: priv.description
            };
        }));

        return resp.length<=0 ? [] : resp;
    }


    async fetchPrivilegeById(privilegeId: string):Promise<PrivilegeWithOwnerBcInfo | null> {
        const filter = {privileges:{
                "$elemMatch":{ "id": privilegeId}
            }};

        const found: BoundedContextPrivileges | null = await this._privilegesCollection.findOne(
            filter,
            {projection: {_id: 0}}
        ) as BoundedContextPrivileges | null;
        if(!found) return null;

        const appPriv:Privilege | undefined = found.privileges.find(
            value => value.id === privilegeId
        );
        if(!appPriv) return null;

        return {
            id: privilegeId,
            labelName: appPriv.labelName,
            description: appPriv.description,
            boundedContextName: found.boundedContextName,
            privilegeSetVersion: found.privilegeSetVersion
        };
    }


    /* BoundedContextPrivileges (privs grouped by app/bc scope) */

    async fetchBcPrivileges(boundedContextName: string): Promise<BoundedContextPrivileges | null> {
        const found = await this._privilegesCollection.findOne(
            {boundedContextName: boundedContextName},
            {projection: {_id: 0}}
        );

        return found as BoundedContextPrivileges | null;
    }

    async storeBcPrivileges(priv: BoundedContextPrivileges, override = true): Promise<void> {
        try {
            const existingPrivileges = await this._privilegesCollection.findOne({boundedContextName: priv.boundedContextName});
            
            let updatedPriv;
            if (existingPrivileges && !override) {
                // Attention: done so that we can add the extra privileges without overriding the local privileges
                // we spread the original object value and override the privileges with the concatenation of both
                updatedPriv = {
                    ...existingPrivileges, 
                    privileges: existingPrivileges.privileges.concat(priv.privileges)
                };
            } else {
                updatedPriv = priv;
            }
    
            const updateResult = await this._privilegesCollection.replaceOne(
                {boundedContextName: priv.boundedContextName},
                updatedPriv,
                {upsert: true}
            );
    
            if ((updateResult.upsertedCount + updateResult.modifiedCount) !== 1) {
                const err = new Error("Could not storeBcPrivileges - mismatch between requests length and MongoDb response length");
                this._logger.error(err);
                throw err;
            }
        } catch (error) {
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

    async fetchPlatformRoleByLabelName(roleLabelName:string):Promise<PlatformRole | null>{
        const found = await this._rolesCollection.findOne(
            {labelName: roleLabelName},
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
