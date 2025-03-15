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

import {IBuiltinIdentityRepository} from "../domain/interfaces";
import {ILogger} from "@mojaloop/logging-bc-public-types-lib";
import {Collection, MongoClient} from "mongodb";
import {IBuiltinIamApplication, IBuiltinIamUser} from "@mojaloop/security-bc-public-types-lib/dist/builtin_identity";

const DB_NAME = "security";
const USERS_COLLECTION_NAME = "builtin_identity_users";
const APPS_COLLECTION_NAME = "builtin_identity_apps";

export class MongoDbBuiltinIdentityRepository implements IBuiltinIdentityRepository{
    private _mongoUri: string;
    private _logger: ILogger;
    private _mongoClient: MongoClient;
    protected _collectionUsers: Collection;
    protected _collectionApps: Collection;

    constructor(_mongoUri: string, logger: ILogger) {
        this._logger = logger.createChild(this.constructor.name);
        this._mongoUri = _mongoUri;
    }

    async init(): Promise<void> {
        try {
            this._mongoClient = await MongoClient.connect(this._mongoUri);
        } catch (err: any) {
            this._logger.error(err);
            this._logger.isWarnEnabled() &&
            this._logger.warn(`MongoDbBuiltinIdentityRepository - init failed with error: ${err?.message?.toString()}`
            );
            throw err;
        }
        if (this._mongoClient === null) throw new Error("Couldn't instantiate mongo client");

        const db = this._mongoClient.db(DB_NAME);

        const collections = await db.listCollections().toArray();

        // Check if the users collection already exists or create.
        if (collections.find((col) => col.name === USERS_COLLECTION_NAME)) {
            this._collectionUsers = db.collection(USERS_COLLECTION_NAME);
        } else {
            this._collectionUsers = await db.createCollection(USERS_COLLECTION_NAME);
            await this._collectionUsers.createIndex( {email: 1}, {unique: true});
        }

        // Check if the apps collection already exists or create.
        if (collections.find((col) => col.name === APPS_COLLECTION_NAME)) {
            this._collectionApps = db.collection(APPS_COLLECTION_NAME);
        } else {
            this._collectionApps = await db.createCollection(APPS_COLLECTION_NAME);
            await this._collectionApps.createIndex( {clientId: 1}, {unique: true});
        }

        this._logger.info("Initialized");
    }

    async destroy(): Promise<void> {
        await this._mongoClient.close();
    }


    async fetchAllUsers():Promise<IBuiltinIamUser[]>{
        const found = await this._collectionUsers.find({})
            .project({_id: 0}).toArray();
        return found as IBuiltinIamUser[];
    }

    async searchUsers(userType?:string, email?:string, name?:string, enabled?:boolean):Promise<IBuiltinIamUser[]>{
        const filter: any = {$and: []};
        if (userType) {
            filter.$and.push({userType: userType});
        }
        if (email) {
            filter.$and.push({email: {$regex: email, $options: "i"}});
        }
        if (name) {
            filter.$and.push({fullName: {$regex: name, $options: "i"}});
        }
        if (enabled!=undefined) {
            filter.$and.push({enabled: enabled});
        }

        const found = await this._collectionUsers.find(filter)
            .project({_id: 0}).toArray();
        return found as IBuiltinIamUser[];
    }

    async fetchUser(username:string):Promise<IBuiltinIamUser | null>{
        const found = await this._collectionUsers.findOne(
            {email: username},
            {projection: {_id: 0}}
        );
        return found as IBuiltinIamUser | null;
    }

    async storeUser(user:IBuiltinIamUser): Promise<void> {
        const updateResult = await this._collectionUsers.replaceOne(
            {email: user.email},
            user,
            {upsert: true}
        );

        if ((updateResult.upsertedCount + updateResult.modifiedCount) !== 1) {
            const err = new Error("Could not storeUser - mismatch between requests length and MongoDb response length");
            this._logger.error(err);
            throw err;
        }
    }



    async fetchAllApps():Promise<IBuiltinIamApplication[]>{
        const found = await this._collectionApps.find({})
            .project({_id: 0}).toArray();
        return found as IBuiltinIamApplication[];
    }

    async searchApps(clientId?:string, canLogin?:boolean, enabled?:boolean):Promise<IBuiltinIamApplication[]>{
        const filter: any = {$and: []};
        if (clientId) {
            filter.$and.push({clientId: {$regex: clientId, $options: "i"}});
        }
        if (canLogin!=undefined) {
            filter.$and.push({canLogin: canLogin});
        }
        if (enabled!=undefined) {
            filter.$and.push({enabled: enabled});
        }

        const found = await this._collectionApps.find(filter)
            .project({_id: 0}).toArray();
        return found as IBuiltinIamApplication[];
    }

    async fetchApp(clientId:string):Promise<IBuiltinIamApplication | null>{
        const found = await this._collectionApps.findOne(
            {clientId: clientId},
            {projection: {_id: 0}}
        );
        return found as IBuiltinIamApplication | null;
    }

    async storeApp(app:IBuiltinIamApplication): Promise<void> {
        const updateResult = await this._collectionApps.replaceOne(
            {clientId: app.clientId},
            app,
            {upsert: true}
        );

        if ((updateResult.upsertedCount + updateResult.modifiedCount) !== 1) {
            const err = new Error("Could not storeApp - mismatch between requests length and MongoDb response length");
            this._logger.error(err);
            throw err;
        }

    }

}
