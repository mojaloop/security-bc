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

// import axios, { AxiosResponse, AxiosInstance, AxiosError } from "axios";
import {ILogger} from "@mojaloop/logging-bc-public-types-lib";
import {
    BoundedContextPrivileges, ForbiddenError,
    IAuthenticatedHttpRequester,
    IAuthorizationClient,
    Privilege, UnauthorizedError
} from "@mojaloop/security-bc-public-types-lib";
import {
    IMessage,
    IMessageConsumer,
    MessageTypes
} from "@mojaloop/platform-shared-lib-messaging-types-lib";
import {PlatformRoleChangedEvt, SecurityBCTopics} from "@mojaloop/platform-shared-lib-public-messages-lib";
import crypto from "crypto";

export type PrivilegesByRole = {
    [roleId: string]: {
        roleName: string;
        privileges: string[]
    }
}


export class AuthorizationClient implements IAuthorizationClient{
    private readonly _boundedContextName: string;
    private readonly _privilegeSetVersion: string;
    private readonly _authSvcBaseUrl:string;
    private readonly _authRequester: IAuthenticatedHttpRequester;
    private readonly _messageConsumer:IMessageConsumer | null;
    private readonly _logger:ILogger;
    private _rolePrivileges:PrivilegesByRole | null = null;
    private _lastFetchTimestamp:number | null = null;
    private _privileges:Privilege[] = [];

    constructor(
        boundedContextName: string,
        privilegeSetVersion: string,
        authSvcBaseUrl:string, logger:ILogger,
        authRequester: IAuthenticatedHttpRequester, messageConsumer:IMessageConsumer|null = null
    ) {
        this._logger = logger.createChild(this.constructor.name);
        this._boundedContextName = boundedContextName;
        this._privilegeSetVersion = privilegeSetVersion;
        this._authSvcBaseUrl = authSvcBaseUrl;
        this._authRequester = authRequester;
        this._messageConsumer = messageConsumer;
    }

    async bootstrap(ignoreDuplicateError = true): Promise<boolean>{
        const appPrivileges:BoundedContextPrivileges = {
            boundedContextName: this._boundedContextName,
            privilegeSetVersion: this._privilegeSetVersion,
            privileges: this._privileges
        };

        const url = new URL("/bootstrap",this._authSvcBaseUrl).toString();
        const request = new Request(url, {
            method: "POST",
            body: JSON.stringify(appPrivileges),
        });

        try{
            const resp = await this._authRequester.fetch(request);
            if(resp.status === 200 || (ignoreDuplicateError === true && resp.status === 409)){
                this._logger.info("Boostrap completed successfully");
                return true;
            }else{
                throw new Error("Could not bootstrap privileges to Authorization Service - http response code: "+resp.status);
            }
        }catch (err:any) {
            if(err instanceof UnauthorizedError){
                throw new UnauthorizedError(`Could not bootstrap privileges to Authorization Service - UnauthorizedError - ${err.message}`);
            }else if(err instanceof ForbiddenError){
                throw new ForbiddenError(`Could not bootstrap privileges to Authorization Service - Forbidden - ${err.message}`);
            }
            this._logger.error(err, "Could not bootstrap privileges to Authorization Service");
            throw new Error(err?.message  || "Could not bootstrap privileges to Authorization Service");
        }
    }

    async fetch(): Promise<void>{
        const url = new URL("/appRoles",this._authSvcBaseUrl);
        url.searchParams.append("bcName", this._boundedContextName);

        try{
            const resp = await this._authRequester.fetch(url.toString());
            if(resp.status === 200){
                this._logger.info("Role privileges associations received successfully");
                const data = await resp.json();
                this._rolePrivileges = data;
                this._lastFetchTimestamp = Date.now();
                return;
            }else{
                throw new Error("Invalid response from Authorization Service fetching role privileges association - http response code: "+resp.status);
            }
        }catch(err:any){
            if(err instanceof UnauthorizedError){
                throw new UnauthorizedError(`Error boostrapBoundedContextConfigs - UnauthorizedError - ${err.message}`);
            }else if(err instanceof ForbiddenError){
                throw new ForbiddenError(`Error boostrapBoundedContextConfigs - Forbidden - ${err.message}`);
            }
            this._logger.error(err, "Could not fetch role privileges association from Authorization Service");
            throw new Error(err?.message  || "Unknown error fetching role privileges association from Authorization Service");
        }
    }

    async init():Promise<void>{
        if(this._messageConsumer){
            this._messageConsumer.setTopics([SecurityBCTopics.DomainEvents]);
            this._messageConsumer.setCallbackFn(this._messageHandler.bind(this));
            await this._messageConsumer.connect();
            await this._messageConsumer.startAndWaitForRebalance();
        }
    }

    async destroy():Promise<void>{
        if(this._messageConsumer){
            await this._messageConsumer.stop();
            await this._messageConsumer.destroy(false);
        }
    }

    private async _messageHandler(message:IMessage):Promise<void>{
        if(message.msgType !== MessageTypes.DOMAIN_EVENT) return;
        if(message.msgName !== PlatformRoleChangedEvt.name) return;

        // for now, simply fetch everything
        this._logger.info("PlatformRoleChangedEvt received, fetching updated Role privileges associations...");

        // randomize wait time, so we don't have all clients fetching at the exact same time
        setTimeout(async ()=>{
            await this.fetch();
        }, crypto.randomInt(0,5000));
    }

    roleHasPrivilege(roleId:string, privilegeId:string):boolean{
        if(!this._rolePrivileges || !this._rolePrivileges[roleId]) return false;

        return this._rolePrivileges[roleId].privileges.includes(privilegeId);
    }

    rolesHavePrivilege(roleIds: string[], privilegeId: string): boolean{
        for (const roleId of roleIds) {
            if (this.roleHasPrivilege(roleId, privilegeId)) return true;
        }
        return false;
    }

    private _hasPrivilege(privId: string):boolean{
        if(this._privileges.length<=0) return false;

        return this._privileges.findIndex(value => value.id===privId) != -1;
    }

    addPrivilege(privId: string, labelName: string, description: string){
        if(this._hasPrivilege(privId)) return;
        this._privileges.push( { id:privId, labelName, description });
    }


    addPrivilegesArray(privsArray:{privId: string, labelName: string, description: string}[]): void{
        for(const privObj of privsArray){
            this.addPrivilege(privObj.privId, privObj.labelName, privObj.description);
        }
    }

}
