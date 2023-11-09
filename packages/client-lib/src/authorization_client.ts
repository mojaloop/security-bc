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

// import axios, { AxiosResponse, AxiosInstance, AxiosError } from "axios";
import {ILogger} from "@mojaloop/logging-bc-public-types-lib";
import {
    AppPrivileges, ForbiddenError,
    IAuthenticatedHttpRequester,
    IAuthorizationClient,
    Privilege, UnauthorizedError
} from "@mojaloop/security-bc-public-types-lib";
import {
    IMessage,
    IMessageConsumer,
    MessageTypes
} from "@mojaloop/platform-shared-lib-messaging-types-lib";
import {SecurityAuthorizationBCTopics} from "@mojaloop/platform-shared-lib-public-messages-lib";

export type PrivilegesByRole = {
    [roleId: string]: {
        roleName: string;
        privileges: string[]
    }
}


export class AuthorizationClient implements IAuthorizationClient{
    private readonly _boundedContextName: string;
    private readonly _applicationName: string;
    private readonly _applicationVersion: string;
    private readonly _authSvcBaseUrl:string;
    private readonly _authRequester: IAuthenticatedHttpRequester;
    private readonly _messageConsumer:IMessageConsumer | null;
    private readonly _logger:ILogger;
    private _rolePrivileges:PrivilegesByRole | null = null;
    private _lastFetchTimestamp:number | null = null;
    private _privileges:Privilege[] = [];

    constructor(
        boundedContext: string, application: string, version: string,
        authSvcBaseUrl:string, logger:ILogger,
        authRequester: IAuthenticatedHttpRequester, messageConsumer:IMessageConsumer|null = null
    ) {
        this._logger = logger.createChild(this.constructor.name);
        this._boundedContextName = boundedContext;
        this._applicationName = application;
        this._applicationVersion = version;
        this._authSvcBaseUrl = authSvcBaseUrl;
        this._authRequester = authRequester;
        this._messageConsumer = messageConsumer;
    }

    async bootstrap(ignoreDuplicateError = true): Promise<boolean>{
        const appPrivileges:AppPrivileges = {
            boundedContextName: this._boundedContextName,
            applicationName: this._applicationName,
            applicationVersion: this._applicationVersion,
            privileges: this._privileges
        };

        const url = new URL("/bootstrap",this._authSvcBaseUrl).toString();
        const request = new Request(url, {
            method: "POST",
            body: JSON.stringify(appPrivileges),
        });

        try{
            const resp = await this._authRequester.fetch(request);
            if(resp.status === 401){
                throw new UnauthorizedError(`Could not bootstrap privileges to Authentication Service - UnauthorizedError - ${await resp.text()}`);
            }else if(resp.status === 403){
                throw new ForbiddenError(`Could not bootstrap privileges to Authentication Service - Forbidden - ${await resp.text()}`);
            }else if(resp.status === 200 || (ignoreDuplicateError === true && resp.status === 409)){
                this._logger.info("Boostrap completed successfully");
                return true;
            }else{
                throw new Error("Could not bootstrap privileges to Authentication Service - http response code: "+resp.status);
            }
        }catch (err:any) {
            this._logger.error(err, "Could not bootstrap privileges to Authentication Service");
            throw new Error(err?.message  || "Could not bootstrap privileges to Authentication Service");
        }
    }

    async fetch(): Promise<void>{
        const url = new URL("/appRoles",this._authSvcBaseUrl);
        url.searchParams.append("bcName", this._boundedContextName);
        url.searchParams.append("appName", this._applicationName);

        try{
            const resp = await this._authRequester.fetch(url.toString());
            if(resp.status === 401){
                throw new UnauthorizedError(`Error boostrapBoundedContextConfigs - UnauthorizedError - ${await resp.text()}`);
            }else if(resp.status === 403){
                throw new ForbiddenError(`Error boostrapBoundedContextConfigs - Forbidden - ${await resp.text()}`);
            }else if(resp.status === 200){
                this._logger.info("Role privileges associations received successfully");
                const data = await resp.json();
                this._rolePrivileges = data;
                this._lastFetchTimestamp = Date.now();
                return;
            }else{
                throw new Error("Invalid response from Authentication Service fetching role privileges association - http response code: "+resp.status);
            }
        }catch(err:any){
            this._logger.error(err, "Could not fetch role privileges association from Authentication Service");
            throw new Error(err?.message  || "Unknown error fetching role privileges association from Authentication Service");
        }
    }

    async init():Promise<void>{
        if(this._messageConsumer){
            this._messageConsumer.setTopics([SecurityAuthorizationBCTopics.DomainEvents]);
            this._messageConsumer.setCallbackFn(this._messageHandler.bind(this));
            await this._messageConsumer.connect();
            await this._messageConsumer.startAndWaitForRebalance();
        }
    }

    private async _messageHandler(message:IMessage):Promise<void>{
        if(message.msgType !== MessageTypes.DOMAIN_EVENT) return;

        // for now, simply fetch everything

        this._logger.info("PlatformRoleChangedEvt received, fetching updated Role privileges associations...");
        await this.fetch();
        // if(message.msgName === "PlatformRoleChangedEvt"){
        //     const
        //     await this._roleChangedHandler();
        // }
    }

    roleHasPrivilege(roleId:string, privilegeId:string):boolean{
        if(!this._rolePrivileges || !this._rolePrivileges[roleId]) return false;

        return this._rolePrivileges[roleId].privileges.includes(privilegeId);
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
