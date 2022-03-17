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

'use strict'


import {IAMAdapter} from "../domain/types";
import {readFile, stat, writeFile} from "fs/promises";
import fs from "fs";

class UserRecord{
    username: string;
    password: string;

}

export class FileIAMAdapter implements IAMAdapter{
    private _filePath: string;
    private _store:Map<string, UserRecord> = new Map<string, UserRecord>();

    constructor(filePath:string) {
        this._filePath = filePath;
    }

    private async _loadFromFile():Promise<boolean>{
        let fileData: [any];
        try{
            const strContents = await readFile(this._filePath, "utf8");
            if(!strContents || !strContents.length){
                return false;
            }

            fileData = JSON.parse(strContents);
        }catch (e) {
            throw new Error("cannot read FileIAMAdapter storage file");
        }

        for(const rec of fileData){
            const userRec = new UserRecord();
            userRec.username = rec.username;
            userRec.password = rec.password;

            if(userRec.username && userRec.password && !this._store.has(userRec.username)){
                this._store.set(userRec.username, userRec);
            }
        }
        return true;
    }

    private async _saveToFile():Promise<void>{
        try{
            const strContents = JSON.stringify(Array.from(this._store.values()));
            await writeFile(this._filePath, strContents, "utf8");
        }catch (e) {
            throw new Error("cannot rewrite FileIAMAdapter storage file");
        }
    }

    async init(): Promise<void>{
        const exists = fs.existsSync(this._filePath);

        if(fs.existsSync(this._filePath)){
            const loadSuccess = await this._loadFromFile();
            if(!loadSuccess){
                throw new Error("Error loading FileIAMAdapter file")
            }
        }

    }

    async createUser(username: string, password: string):Promise<boolean>{
        if(this._store.has(username)){
            return false;
        }
        const userRec = new UserRecord();
        userRec.username = username;
        userRec.password = password;
        this._store.set(userRec.username, userRec);

        await this._saveToFile();
        return true;
    }

    userCount():number{
        return this._store.size;
    }


    async loginApp(app_id: string, password: string): Promise<boolean> {
        return Promise.resolve(false);
    }

    async loginUser(username: string, password: string): Promise<boolean> {
        if(!this._store.has(username)){
            return false;
        }
        const rec = this._store.get(username);

        // this is a mock implementation, no ecryption needed or desired - but pass must not be empty
        if(rec && rec.password && rec.password === password){
            return true;
        }
        return false;
    }
}
