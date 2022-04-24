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

"use strict"

import semver from "semver";
import * as uuid from "uuid";
import {ILogger} from "@mojaloop/logging-bc-logging-client-lib/dist/index";
import {AppPrivileges, PlatformRole} from "@mojaloop/security-bc-public-types-lib";
import {IAMAuthorizationAdapter, IAuthorizationRepository} from "./interfaces";
import {
    CannotCreateDuplicateAppPrivilegesError,
    CannotCreateDuplicateRoleError,
    CannotOverrideAppPrivilegesError,
    CouldNotStoreAppPrivilegesError,
    InvalidAppPrivilegesError,
    InvalidPlatformRoleError,
    NewRoleWithPrivsUsersOrAppsError
} from "./errors";
import {AllPrivilegesResp} from "../domain/types";


export class AuthorizationAggregate{
    private _logger:ILogger
    //private _iamAuthNAdapter:IAMAuthorizationAdapter;
    private _authzRepo:IAuthorizationRepository;


    // constructor(authzRepo:IAuthorizationRepository, iamAuthN:IAMAuthorizationAdapter, logger:ILogger) {
    constructor(authzRepo:IAuthorizationRepository, logger:ILogger) {
        this._logger = logger;
        this._authzRepo = authzRepo;
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

    async processAppBootstrap(appPrivs: AppPrivileges):Promise<void> {
        if(!this._validateAppPrivileges(appPrivs)){
            this._logger.warn("Invalid AppPrivileges received in processAppBootstrap");
            throw new InvalidAppPrivilegesError();
        }

        const foundAppPrivs = await this._authzRepo.fetchAppPrivileges(appPrivs.boundedContextName, appPrivs.applicationName);

        if(foundAppPrivs) {
            if (semver.compare(foundAppPrivs.applicationVersion, appPrivs.applicationVersion)==0) {
                this._logger.warn(`received duplicate AppPrivileges set for BC: ${foundAppPrivs.boundedContextName}, APP: ${foundAppPrivs.applicationName}, version: ${foundAppPrivs.applicationVersion}, IGNORING with error`);
                throw new CannotCreateDuplicateAppPrivilegesError();
            } else if (semver.compare(foundAppPrivs.applicationVersion, appPrivs.applicationVersion)==1) {
                this._logger.error(`received AppPrivileges with lower version than latest for BC: ${foundAppPrivs.boundedContextName}, APP: ${foundAppPrivs.applicationName}, version: ${foundAppPrivs.applicationVersion}, IGNORING with error`);
                throw new CannotOverrideAppPrivilegesError();
            }
        }

        this._logger.info(`Created AppPrivileges set for BC: ${appPrivs.boundedContextName}, APP: ${appPrivs.applicationName}, version: ${appPrivs.applicationVersion}`);
        const stored = await this._authzRepo.storeAppPrivileges(appPrivs);
        if(!stored){
            throw new CouldNotStoreAppPrivilegesError();
        }
    }

    async getAllPrivileges():Promise<AllPrivilegesResp[]> {
        const ret : AllPrivilegesResp[] = [];
        const allPrivs = await this._authzRepo.fetchAllAppPrivileges();

        if(!allPrivs || allPrivs.length ==0) {
            return ret;
        }

        allPrivs.forEach(appPrivs => {
            appPrivs.privileges.forEach(priv=>{
                ret.push({
                    id: priv.id,
                    labelName: priv.labelName,
                    description: priv.description,
                    boundedContextName: appPrivs.boundedContextName,
                    applicationName: appPrivs.applicationName,
                    applicationVersion: appPrivs.applicationVersion
                });
            })
        })

        return ret;
    }


    async createLocalRole(role:PlatformRole):Promise<void>{
        if(role.isExternal && !role.externalId){
            throw new InvalidPlatformRoleError();
        }

        if(!role.labelName && !role.description){
            throw new InvalidPlatformRoleError();
        }

        if((role.appPrivileges && role.appPrivileges.length>0)
                || (role.memberUsers && role.memberUsers.length>0)
                || (role.memberApps && role.memberApps.length>0)){
            throw new NewRoleWithPrivsUsersOrAppsError();
        }

        if(!role.id){
            role.id = uuid.v4();
        }

        const existingRole = await this._authzRepo.fetchPlatformRole(role.id);
        if(existingRole){
            throw new CannotCreateDuplicateRoleError();
        }

        await this._authzRepo.storePlatformRole(role);
    }


}
