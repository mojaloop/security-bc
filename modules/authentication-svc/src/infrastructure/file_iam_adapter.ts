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

import { watch } from "node:fs";
import {IAMAuthenticationAdapter} from "../domain/interfaces";
import {readFile, writeFile} from "fs/promises";
import fs from "fs";
import {IAMLoginResponse} from "@mojaloop/security-bc-public-types-lib";
import {ILogger} from "@mojaloop/logging-bc-public-types-lib";

const FIXED_EXPIRES_IN_SECS = 3600;

class UserRecord{
    username: string;
    password: string;
    roles: string[];
}

class AppRecord{
    client_id: string;
    client_secret: string | null;
    roles: string[];
}

export class FileIAMAdapter implements IAMAuthenticationAdapter{
    private readonly _logger:ILogger;
    private readonly _filePath: string;
    private readonly _users:Map<string, UserRecord> = new Map<string, UserRecord>();
    private readonly _apps:Map<string, AppRecord> = new Map<string, AppRecord>();
    private _watching = false;
    private _saving = false;

    constructor(filePath:string, logger:ILogger) {
        this._logger = logger.createChild(this.constructor.name);
        this._filePath = filePath;

        this._logger.info(`Starting FileIAMAdapter with file path: "${this._filePath}"`);
    }

    private async _loadFromFile():Promise<boolean>{
        this._users.clear();
        this._apps.clear();

        let fileData: any;
        try{
            const strContents = await readFile(this._filePath, "utf8");
            if(!strContents || !strContents.length){
                return false;
            }
            fileData = JSON.parse(strContents);
        }catch (e) {
            throw new Error("cannot read FileIAMAdapter storage file");
        }

        if(fileData.users && Array.isArray(fileData.users)){
            for (const rec of fileData.users) {
                const userRec = new UserRecord();
                userRec.username = rec.username;
                userRec.password = rec.password;
                userRec.roles = rec.roles;

                if (userRec.username && userRec.password && !this._users.has(userRec.username)) {
                    this._users.set(userRec.username, userRec);
                }
            }
        }

        if(fileData.apps && Array.isArray(fileData.apps)){
            for (const rec of fileData.apps) {
                const appRecord = new AppRecord();
                appRecord.client_id = rec.client_id;
                appRecord.client_secret = rec.client_secret;
                appRecord.roles = rec.roles;

                if (appRecord.client_id && !this._apps.has(appRecord.client_id)) {
                    this._apps.set(appRecord.client_id, appRecord);
                }
            }
        }

        this._logger.info(`Successfully read file contents - userCount: ${this._users.size} and appCount: ${this._apps.size}`);

        return true;
    }

    private async _saveToFile():Promise<void>{
        try{
            this._saving = true;
            const obj = {
                users: Array.from(this._users.values()),
                apps: Array.from(this._apps.values())
            };
            const strContents = JSON.stringify(obj, null, 4);
            await writeFile(this._filePath, strContents, "utf8");
            this._ensureIsWatching();
        }catch (e) {
            this._logger.error(e, "cannot write FileIAMAdapter storage file");
            throw new Error("cannot write FileIAMAdapter storage file");
        }finally {
            this._saving = false;
        }
    }

    async init(): Promise<void>{
        const exists = fs.existsSync(this._filePath);

        // if not exists we skip, it will be loaded after
        if(!exists){
            this._logger.warn("FileIAMAdapter data file does not exist, will be created at first write - filepath: "+this._filePath);
            return;
        }


        const loadSuccess = await this._loadFromFile();
        if(!loadSuccess){
            throw new Error("Error loading FileIAMAdapter file")
        }


        this._ensureIsWatching();
    }

    private _ensureIsWatching(){
        if (this._watching) return;

        let fsWait: NodeJS.Timeout | undefined; // debounce wait
        watch(this._filePath, async (eventType, filename) => {
            if (this._saving) return;
            if (eventType==="change") {
                if (fsWait) return;
                fsWait = setTimeout(() => {
                    fsWait = undefined;
                }, 100);
                this._logger.info(`FileIAMAdapter file changed,  with file path: "${this._filePath}" - reloading...`);
                await this._loadFromFile();
            }
        });
        this._watching = true;
    }

    async createApp(client_id: string, client_secret: string | null, roles?: string[]):Promise<boolean>{
        if(this._apps.has(client_id)){
            return false;
        }
        const appRec = new AppRecord();
        appRec.client_id = client_id;
        appRec.client_secret = client_secret;
        if (roles) appRec.roles = roles;
        this._apps.set(client_id, appRec);

        await this._saveToFile();
        return true;
    }


    appCount():number{
        return this._apps.size;
    }

    async appExists(client_id:string):Promise<boolean>{
        return this._apps.has(client_id);
    }

    async createUser(username: string, password: string, roles?:string[]):Promise<boolean>{
        if(this._users.has(username)){
            return false;
        }
        const userRec = new UserRecord();
        userRec.username = username;
        userRec.password = password;
        if(roles) userRec.roles = roles;
        this._users.set(userRec.username, userRec);

        await this._saveToFile();
        return true;
    }

    userCount():number{
        return this._users.size;
    }

    async userExists(username:string):Promise<boolean>{
        return this._users.has(username);
    }

    async loginApp(client_id: string, client_secret: string): Promise<IAMLoginResponse> {
        const resp:IAMLoginResponse = {
            success: false,
            scope: null,
            expires_in_secs: 0,
            roles: []
        };

        const appRec = this._apps.get(client_id);
        if(!appRec){
            return resp;
        }

        if(appRec.client_secret == null || !client_secret || appRec.client_secret !== client_secret ){
            return resp;
        }

        // this is a mock implementation, no encryption needed or desired - but pass must not be empty
        resp.success = true;
        resp.expires_in_secs = FIXED_EXPIRES_IN_SECS;
        resp.roles = appRec.roles || [];

        return resp;
    }

    async loginUser(client_id:string, client_secret:string|null, username: string, password: string): Promise<IAMLoginResponse> {
        const resp:IAMLoginResponse = {
            success: false,
            scope: null,
            expires_in_secs: 0,
            roles: []
        };

        const appRec = this._apps.get(client_id);
        if(!appRec){
            return resp;
        }

        if(appRec.client_secret != null && appRec.client_secret !== client_secret ){
            return resp;
        }

        if(!this._users.has(username)){
            return resp;
        }
        const rec = this._users.get(username);

        // this is a mock implementation, no ecryption needed or desired - but pass must not be empty
        if(rec && rec.password && rec.password === password){
            resp.success = true;
            resp.expires_in_secs = FIXED_EXPIRES_IN_SECS;
            resp.roles = rec.roles || [];

            return resp;
        }
        return resp;
    }
}
