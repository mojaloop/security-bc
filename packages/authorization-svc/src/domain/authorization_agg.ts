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

import semver from "semver";
import * as Crypto from "crypto";
import {ILogger} from "@mojaloop/logging-bc-public-types-lib";
import {
    Privilege,
    AppPrivileges,
    PlatformRole,
    PrivilegeWithOwnerAppInfo
} from "@mojaloop/security-bc-public-types-lib";
import {IAuthorizationRepository} from "./interfaces";
import {
    ApplicationsPrivilegesNotFoundError,
    CannotCreateDuplicateAppPrivilegesError,
    CannotCreateDuplicateRoleError,
    CannotOverrideAppPrivilegesError, CannotStorePlatformRoleError,
    CouldNotStoreAppPrivilegesError,
    InvalidAppPrivilegesError,
    InvalidPlatformRoleError,
    NewRoleWithPrivsUsersOrAppsError, PlatformRoleNotFoundError, PrivilegeNotFoundError
} from "./errors";
import {PrivilegesByRole} from "../domain/types";
import {IMessageProducer} from "@mojaloop/platform-shared-lib-messaging-types-lib";
import {PlatformRoleChangedEvt} from "@mojaloop/platform-shared-lib-public-messages-lib";

export class AuthorizationAggregate{
    private _logger:ILogger;
    //private _iamAuthNAdapter:IAMAuthorizationAdapter;
    private _authzRepo:IAuthorizationRepository;
    private _producer:IMessageProducer;


    // constructor(authzRepo:IAuthorizationRepository, iamAuthN:IAMAuthorizationAdapter, logger:ILogger) {
    constructor(authzRepo:IAuthorizationRepository, producer:IMessageProducer, logger:ILogger) {
        this._logger = logger.createChild(this.constructor.name);
        this._authzRepo = authzRepo;
        this._producer = producer;
        //this._iamAuthNAdapter = iamAuthN;
    }

    private _validateAppPrivileges(appPrivs: AppPrivileges): boolean{
        if(!appPrivs.applicationName  || !appPrivs.boundedContextName || !appPrivs.applicationVersion) {
            return false;
        }

        if(!appPrivs.privileges || !Array.isArray(appPrivs.privileges)){
            return false;
        }


        if(!appPrivs.applicationVersion || typeof(appPrivs.applicationVersion) !== "string"){
            return false;
        }
        const parsed = semver.coerce(appPrivs.applicationVersion);
        if(!parsed || parsed.raw != appPrivs.applicationVersion) {
            // the 2nd check assures that formats like "v1.0.1" which are considered valid by semver are rejected, we want strict semver
            return false;
        }

        return true;
    }

    private async _sendRoleChangedEvt(roleId: string){
        const evt = new PlatformRoleChangedEvt({roleId: roleId});
        await this._producer.send(evt);
    }
    async processAppBootstrap(appPrivs: AppPrivileges):Promise<void> {
        if(!this._validateAppPrivileges(appPrivs)){
            this._logger.warn("Invalid AppPrivileges received in processAppBootstrap");
            throw new InvalidAppPrivilegesError();
        }

        const foundAppPrivs = await this._authzRepo.fetchAppPrivileges(appPrivs.boundedContextName, appPrivs.applicationName);

        if(foundAppPrivs) {
            if (semver.compare(foundAppPrivs.applicationVersion, appPrivs.applicationVersion)==0) {
                const err = new CannotCreateDuplicateAppPrivilegesError(`Received duplicate AppPrivileges set for BC: ${foundAppPrivs.boundedContextName}, APP: ${foundAppPrivs.applicationName}, version: ${foundAppPrivs.applicationVersion}, IGNORING with error`);
                this._logger.warn(err.message);
                throw err;
            } else if (semver.compare(foundAppPrivs.applicationVersion, appPrivs.applicationVersion)==1) {
                const err = new CannotOverrideAppPrivilegesError(`received AppPrivileges with lower version than latest for BC: ${foundAppPrivs.boundedContextName}, APP: ${foundAppPrivs.applicationName}, version: ${foundAppPrivs.applicationVersion}, IGNORING with error`);
                this._logger.error(err);
                throw err;
            }
        }

        try {
            // TODO: maybe mark older versions as inactive
            await this._authzRepo.storeAppPrivileges(appPrivs);
            this._logger.info(`Created AppPrivileges set for BC: ${appPrivs.boundedContextName}, APP: ${appPrivs.applicationName}, version: ${appPrivs.applicationVersion}`);
        }catch(err:any){
            this._logger.error(err);
            throw new CouldNotStoreAppPrivilegesError(err?.message);
        }
    }

    async getAllPrivileges():Promise<PrivilegeWithOwnerAppInfo[]> {
        const allPrivs = await this._authzRepo.fetchAllPrivileges();

        return allPrivs;
    }

    /**
     * Returns only the roles which include privileges for a certain app (and their relationship)
     * @param bcName BoundedContext name
     * @param appName Application name
     */
    async getAppPrivilegesByRole(bcName:string, appName:string):Promise<PrivilegesByRole>{
        const allPrivs = await this._authzRepo.fetchAllPrivileges();

        if(allPrivs.length<=0){
            throw new ApplicationsPrivilegesNotFoundError();
        }

        const allRoles = await this.getAllRoles();

        const ret:PrivilegesByRole = {};

        allRoles.forEach(role => {
            if(!role.privileges || role.privileges.length<=0) return;

            role.privileges.forEach(rolePriv => {
                const privDefinition = allPrivs.find(item => item.id === rolePriv);
                if(!privDefinition) return;

                if (!ret[role.id]){
                    ret[role.id] = {
                        roleName: role.labelName,
                        privileges: []
                    };
                }
                ret[role.id].privileges.push(rolePriv);
            });
        });

        return ret;
    }

    async getAllRoles():Promise<PlatformRole[]> {
        const allRoles = await this._authzRepo.fetchAllPlatformRoles();

        if(!allRoles || allRoles.length ==0) {
            return [];
        }

        return allRoles;
    }

    async createPlatformRole(role:PlatformRole):Promise<string>{
        if(role.isExternal && !role.externalId){
            throw new InvalidPlatformRoleError();
        }

        if(!role.labelName && !role.description){
            throw new InvalidPlatformRoleError();
        }

        if((role.privileges && role.privileges.length>0)
                // || (role.memberUserIds && role.memberUserIds.length>0)
                // || (role.memberAppIds && role.memberAppIds.length>0)
        ){
            throw new NewRoleWithPrivsUsersOrAppsError();
        }

        if(!role.id){
            role.id = Crypto.randomUUID();
        }

        const existingRole = await this._authzRepo.fetchPlatformRole(role.id);
        if(existingRole){
            throw new CannotCreateDuplicateRoleError();
        }


        try {
            await this._authzRepo.storePlatformRole(role);
        }catch(err:any){
            this._logger.error(err);
            throw new CannotStorePlatformRoleError(err?.message);
        }

        await this._sendRoleChangedEvt(role.id);
        return role.id;
    }

    async associatePrivilegesToRole(privilegeIds:string[], roleId:string):Promise<void>{
        const role:PlatformRole  | null = await this._authzRepo.fetchPlatformRole(roleId);
        if(!role) {
            throw new PlatformRoleNotFoundError();
        }

        if(!role.privileges) role.privileges = [];

        for (const privId of privilegeIds) {
            const priv:PrivilegeWithOwnerAppInfo | null = await this._authzRepo.fetchPrivilegeById(privId);
            if(!priv) {
                throw new PrivilegeNotFoundError();
            }

            if(role.privileges.findIndex(value => value === privId) <= -1){
                role.privileges.push(privId);
            }
        }

        try {
            await this._authzRepo.storePlatformRole(role);
        }catch(err:any){
            this._logger.error(err);
            throw new CannotStorePlatformRoleError(err?.message);
        }

        await this._sendRoleChangedEvt(roleId);
    }

    async dissociatePrivilegesToRole(privilegeIds:string[], roleId:string):Promise<void>{
        const role:PlatformRole  | null = await this._authzRepo.fetchPlatformRole(roleId);
        if(!role) {
            throw new PlatformRoleNotFoundError();
        }

        if(!role.privileges) {
            throw new PrivilegeNotFoundError("Role has no privileges to remove");
        }

        // filter out selected privilege ids
        role.privileges = role.privileges.filter(value => !privilegeIds.includes(value));

        try {
            await this._authzRepo.storePlatformRole(role);
        }catch(err:any){
            this._logger.error(err);
            throw new CannotStorePlatformRoleError(err?.message);
        }

        await this._sendRoleChangedEvt(roleId);
    }

}
