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
    PrivilegeWithOwnerAppInfo, CallSecurityContext, ForbiddenError
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
import {
    IMessage,
    IMessageConsumer,
    IMessageProducer,
    MessageTypes
} from "@mojaloop/platform-shared-lib-messaging-types-lib";
import {
    AuthTokenInvalidatedEvt,
    PlatformRoleChangedEvt,
    SecurityBCTopics
} from "@mojaloop/platform-shared-lib-public-messages-lib";
import {AuthorizationPrivileges, AuthorizationPrivilegesDefinition} from "./privileges";

export class AuthorizationAggregate{
    private _logger:ILogger;
    //private _iamAuthNAdapter:IAMAuthorizationAdapter;
    private _authzRepo:IAuthorizationRepository;
    private _messageProducer:IMessageProducer;
    private _messageConsumer:IMessageConsumer;
    private _bcName:string;
    private _appName:string;
    private _appVersion:string;
    private _authzPrivsByRole: PrivilegesByRole;
    private _lastChangedEvtMsgId:string | null = null;

    async init():Promise<void>{
        // bootstrap my own privs
        this._logger.info("Bootstraping own privileges...");
        await this._bootstrapLocalAppPrivileges();
        this._logger.info("Bootstraping own privileges - done");

        // load role priv/associations to mem
        this._logger.info("Reloading role privilege/associations to memory...");
        await this._reloadFromRepo();
        this._logger.info("Reloading role privilege/associations to memory - done");

        this._logger.info("Starting message consumer...");
        this._messageConsumer.setTopics([SecurityBCTopics.DomainEvents]);
        this._messageConsumer.setCallbackFn(this._messageHandler.bind(this));
        await this._messageConsumer.connect();
        await this._messageConsumer.startAndWaitForRebalance();
        this._logger.info("Starting message consumer - done");
        this._logger.info("Init complete");
    }

    constructor(
        authzRepo:IAuthorizationRepository,
        producer:IMessageProducer,
        consumer:IMessageConsumer,
        bcName:string,
        appName:string,
        appVersion:string,
        logger:ILogger
    ) {
        this._logger = logger.createChild(this.constructor.name);
        this._authzRepo = authzRepo;
        this._messageProducer = producer;
        this._messageConsumer = consumer;
        this._bcName = bcName;
        this._appName = appName;
        this._appVersion = appVersion;
    }

    private async _bootstrapLocalAppPrivileges(){
        const appPrivileges:AppPrivileges = {
            boundedContextName: this._bcName,
            applicationName: this._appName,
            applicationVersion: this._appVersion,
            privileges: AuthorizationPrivilegesDefinition.map(item=>{
                return {
                    id: item.privId,
                    labelName: item.labelName,
                    description: item.description
                };
            })
        };

        await this._localProcessAppBootstrap(appPrivileges, true);
    }

    private async _reloadFromRepo():Promise<void>{
        this._authzPrivsByRole = await this._localGetAppPrivilegesByRole(this._bcName, this._appName);
        if(!this._authzPrivsByRole) this._logger.warn("Not able to reloadFromRepo - Possible problem?");
    }

    private async _messageHandler(message:IMessage):Promise<void>{
        if(message.msgType !== MessageTypes.DOMAIN_EVENT) return;

        //ignore events sent from self
        if(message.msgId === this._lastChangedEvtMsgId) return;

        // we only care about PlatformRoleChangedEvt for now
        if(message.msgName !== PlatformRoleChangedEvt.name) return;


        this._logger.info("PlatformRoleChangedEvt received, reloading all data from the repo...");
        await this._reloadFromRepo();
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
        this._lastChangedEvtMsgId = evt.msgId;
        await this._messageProducer.send(evt);
    }

    private _roleHasPrivilege(roleId:string, privilegeId:string):boolean{
        if(!this._authzPrivsByRole || !this._authzPrivsByRole[roleId]) return false;

        return this._authzPrivsByRole[roleId].privileges.includes(privilegeId);
    }

    private _enforcePrivilege(secCtx: CallSecurityContext, privName: string): void {
        for (const roleId of secCtx.platformRoleIds) {
            if (this._roleHasPrivilege(roleId, privName)) return;
        }
        throw new ForbiddenError(
            `Required privilege "${privName}" not held by caller`
        );
    }

    private async _localProcessAppBootstrap(appPrivs: AppPrivileges, ignoreDuplicates:boolean  = false):Promise<void> {
        if(!this._validateAppPrivileges(appPrivs)){
            this._logger.warn("Invalid AppPrivileges received in processAppBootstrap");
            throw new InvalidAppPrivilegesError();
        }

        const foundAppPrivs = await this._authzRepo.fetchAppPrivileges(appPrivs.boundedContextName, appPrivs.applicationName);

        if(foundAppPrivs) {
            if (semver.compare(foundAppPrivs.applicationVersion, appPrivs.applicationVersion)==0 && !ignoreDuplicates) {
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

    async bootstrapDefaultRoles(defaultRoles: PlatformRole[]){
        for(const role of defaultRoles){
            await this._localCreatePlatformRole(role);
        }
    }

    async processAppBootstrap(secCtx: CallSecurityContext, appPrivs: AppPrivileges):Promise<void> {
        this._enforcePrivilege(secCtx, AuthorizationPrivileges.BOOTSTRAP_PRIVILEGES);
        return this._localProcessAppBootstrap(appPrivs);
    }

    async getAllPrivileges(secCtx: CallSecurityContext):Promise<PrivilegeWithOwnerAppInfo[]> {
        this._enforcePrivilege(secCtx, AuthorizationPrivileges.VIEW_PRIVILEGE);
        const allPrivs = await this._authzRepo.fetchAllPrivileges();

        return allPrivs;
    }

    /**
     * Returns only the roles which include privileges for a certain app (and their relationship)
     * WITHOUT enforce privileges, for local agg usage
     * @param bcName BoundedContext name
     * @param appName Application name
     */
    private async _localGetAppPrivilegesByRole(bcName:string, appName:string):Promise<PrivilegesByRole>{
        const allPrivs = await this._authzRepo.fetchAllPrivileges();

        if(allPrivs.length<=0){
            throw new ApplicationsPrivilegesNotFoundError();
        }

        const allRoles = await this._authzRepo.fetchAllPlatformRoles();

        const ret:PrivilegesByRole = {};

        allRoles.forEach(role => {
            if(!role.privileges || role.privileges.length<=0) return;

            role.privileges.forEach(rolePriv => {
                const privDefinition = allPrivs.find(item => item.id === rolePriv);
                if(!privDefinition || privDefinition.boundedContextName!=bcName || privDefinition.applicationName!=appName){
                    return;
                }

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

    /**
     * Returns only the roles which include privileges for a certain app (and their relationship) WITH enforce privileges
     * @param secCtx CallSecurityContext
     * @param bcName BoundedContext name
     * @param appName Application name
     */
    async getAppPrivilegesByRole(secCtx: CallSecurityContext, bcName:string, appName:string):Promise<PrivilegesByRole>{
        this._enforcePrivilege(secCtx, AuthorizationPrivileges.FETCH_APP_ROLE_PRIVILEGES_ASSOCIATIONS);
        return this._localGetAppPrivilegesByRole(bcName, appName);
    }

    async getAllRoles(secCtx: CallSecurityContext):Promise<PlatformRole[]> {
        this._enforcePrivilege(secCtx, AuthorizationPrivileges.VIEW_ROLE);
        const allRoles = await this._authzRepo.fetchAllPlatformRoles();

        if(!allRoles || allRoles.length ==0) {
            return [];
        }

        return allRoles;
    }

    private async _localCreatePlatformRole(role:PlatformRole):Promise<void>{
        if(role.isExternal && !role.externalId){
            throw new InvalidPlatformRoleError("External roles require an externalId");
        }

        if(!role.labelName || !role.description){
            throw new InvalidPlatformRoleError("Roles must have labelName and description");
        }

        if(!role.privileges) role.privileges = [];

        let existingRole = await this._authzRepo.fetchPlatformRoleByLabelName(role.labelName);
        if (existingRole) {
            throw new CannotCreateDuplicateRoleError();
        }

        if (role.id) {
            existingRole = await this._authzRepo.fetchPlatformRole(role.id);
            if (existingRole) {
                throw new CannotCreateDuplicateRoleError();
            }
        } else {
            role.id = Crypto.randomUUID();
        }

        try {
            await this._authzRepo.storePlatformRole(role);
        }catch(err:any){
            this._logger.error(err);
            throw new CannotStorePlatformRoleError(err?.message);
        }
    }

    async createPlatformRole(secCtx: CallSecurityContext, role:PlatformRole):Promise<string>{
        this._enforcePrivilege(secCtx, AuthorizationPrivileges.CREATE_ROLE);
        await this._localCreatePlatformRole(role);

        await this._sendRoleChangedEvt(role.id);
        await this._reloadFromRepo();
        return role.id;
    }

    async associatePrivilegesToRole(secCtx: CallSecurityContext, privilegeIds:string[], roleId:string):Promise<void>{
        this._enforcePrivilege(secCtx, AuthorizationPrivileges.ADD_PRIVILEGES_TO_ROLE);
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
        await this._reloadFromRepo();
    }

    async dissociatePrivilegesFromRole(secCtx: CallSecurityContext, privilegeIds:string[], roleId:string):Promise<void>{
        this._enforcePrivilege(secCtx, AuthorizationPrivileges.REMOVE_PRIVILEGES_FROM_ROLE);
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
        await this._reloadFromRepo();
    }

}
