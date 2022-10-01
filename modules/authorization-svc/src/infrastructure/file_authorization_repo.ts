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

import fs from "fs";
import {readFile, stat, writeFile} from "fs/promises";
import {ILogger} from "@mojaloop/logging-bc-public-types-lib";
import {Privilege, AppPrivileges, PlatformRole} from "@mojaloop/security-bc-public-types-lib";
import {IAuthorizationRepository} from "../domain/interfaces";
import {watch} from "node:fs";


export class FileAuthorizationRepo implements IAuthorizationRepository{
    private _filePath: string;
    private _logger: ILogger;
    private _appPrivs : Map<string, AppPrivileges> = new Map<string, AppPrivileges>();
    private _roles : Map<string, PlatformRole> = new Map<string, PlatformRole>();

    constructor(filePath:string, logger: ILogger) {
        this._logger = logger.createChild(this.constructor.name);
        this._filePath = filePath;

        this._logger.info(`Starting FileAuthorizationRepo with file path: "${this._filePath}"`);
    }

    private async _loadFromFile():Promise<boolean>{
        this._appPrivs.clear();
        this._roles.clear();

        let fileData: any;
        try{
            const strContents = await readFile(this._filePath, "utf8");
            if(!strContents || !strContents.length){
                return false;
            }

            fileData = JSON.parse(strContents);
        }catch (e) {
            throw new Error("cannot read FileAuthorizationRepo storage file");
        }

        if(fileData.appPrivileges && Array.isArray(fileData.appPrivileges)){
            for (const rec of fileData.appPrivileges) {
                const appPrivs:AppPrivileges = {
                    boundedContextName: rec.boundedContextName,
                    applicationName: rec.applicationName,
                    applicationVersion: rec.applicationVersion,
                    privileges: rec.privileges
                }

                if (appPrivs.boundedContextName && appPrivs.applicationName && appPrivs.applicationVersion && Array.isArray(appPrivs.privileges) ){
                    const id = this._appPrivilegeIdString(appPrivs.boundedContextName, appPrivs.applicationName);
                    if(!this._appPrivs.has(id)) {
                        this._appPrivs.set(id, appPrivs);
                    }
                }
            }
        }

        if(fileData.platformRoles && Array.isArray(fileData.platformRoles)){
            for (const rec of fileData.platformRoles) {
                const role:PlatformRole = {
                    id: rec.id,
                    externalId: rec.externalId,
                    isExternal: rec.isExternal,
                    isApplicationRole: rec.isApplicationRole,
                    labelName: rec.labelName,
                    description: rec.description,
                    privileges: rec.privileges,
                    memberApps: rec.memberApps,
                    memberUsers: rec.memberUsers
                }

                if (role.id && role.labelName ){
                    if(!this._roles.has(role.id)) {
                        this._roles.set(role.id, role);
                    }
                }
            }
        }

        this._logger.info(`Successfully read file contents - app privileges count: ${this._appPrivs.size} and platform roles count: ${this._roles.size}`);
        return true;
    }

    private async _saveToFile():Promise<void>{
        try{
            const obj = {
                appPrivileges: Array.from(this._appPrivs.values()),
                platformRoles: Array.from(this._roles.values())
            };
            const strContents = JSON.stringify(obj, null, 4);
            await writeFile(this._filePath, strContents, "utf8");
        }catch (e) {
            throw new Error("cannot rewrite FileConfigSetRepo storage file");
        }
    }

    private _deepCopyAppPrivilege(appPrivileges:AppPrivileges):AppPrivileges{
        // we need this to de-reference the objects in memory when passing them to callers
        return JSON.parse(JSON.stringify(appPrivileges));
    }

    private _appPrivilegeIdString(boundedContextName: string, applicationName: string): string{
        return boundedContextName.toUpperCase()+"::"+applicationName.toUpperCase();
    }


    async init(): Promise<void>{
        const exists = fs.existsSync(this._filePath);

        // if not exists we skip, it will be loaded after
        if(!exists){
            this._logger.warn("FileAuthorizationRepo data file does not exist, will be created at first write - filepath: "+this._filePath);
            return;
        }

        const loadSuccess = await this._loadFromFile();
        if(!loadSuccess){
            throw new Error("Error loading FileAuthorizationRepo file")
        }else{
            this._logger.info(`FileAuthorizationRepo - loaded ${this._appPrivs.size} appPrivileges and ${this._roles.size} roles at init`);
        }

        let fsWait:NodeJS.Timeout | undefined; // debounce wait
        watch(this._filePath, async (eventType, filename) => {
            if (eventType === "change") {
                if (fsWait) return;
                fsWait = setTimeout(() => {
                    fsWait = undefined;
                }, 100);
                this._logger.info(`FileAuthorizationRepo file changed,  with file path: "${this._filePath}" - reloading...`);
                await this._loadFromFile();
            }
        });
    }


    // PlatformRole
    async storePlatformRole(role:PlatformRole):Promise<boolean>{
        this._roles.set(role.id, role);
        await this._saveToFile();
        return true;
    }

    async fetchPlatformRole(roleId:string):Promise<PlatformRole | null>{
        const resp = this._roles.get(roleId) || null;
        return resp;
    }

    async fetchAllPlatformRoles():Promise<PlatformRole[]>{
        const resp = Array.from(this._roles.values()) || [];
        return resp;
    }


    // AppPrivileges
    async storeAppPrivileges(priv:AppPrivileges):Promise<boolean>{
        const id = this._appPrivilegeIdString(priv.boundedContextName, priv.applicationName);
        this._appPrivs.set(id, priv);
        await this._saveToFile();
        return true;
    }

    async fetchPrivilege(privilegeId: string):Promise<Privilege | null>{
        for(const appPrivs of this._appPrivs.values()){
            const foundPriv = appPrivs.privileges.find(value => value.id === privilegeId) || null;
            if(foundPriv)
                return foundPriv;
        }

        return null;
    }

    async fetchAppPrivileges(boundedContextName: string, applicationName: string):Promise<AppPrivileges | null>{
        const id = this._appPrivilegeIdString(boundedContextName, applicationName);
        const resp = this._appPrivs.get(id) || null;
        return resp;
    }

    async fetchAllAppPrivileges():Promise<AppPrivileges[]>{
        const resp = Array.from(this._appPrivs.values()) || [];
        return resp;
    }


}
