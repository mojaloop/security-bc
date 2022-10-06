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
import axios, { AxiosResponse, AxiosInstance, AxiosError } from "axios";
import {ILogger} from "@mojaloop/logging-bc-public-types-lib";
import {AppPrivileges, IAuthorizationClient, Privilege} from "@mojaloop/security-bc-public-types-lib";

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
    private _logger:ILogger;
    private _authSvcBaseUrl:string;
    private _client:AxiosInstance;
    private _rolePrivileges:PrivilegesByRole | null = null;
    private _lastFetchTimestamp:number | null = null;
    private _privileges:Privilege[] = [];

    constructor(boundedContext: string, application: string, version: string, authSvcBaseUrl:string, logger:ILogger) {
        this._boundedContextName = boundedContext;
        this._applicationName = application;
        this._applicationVersion = version;
        this._logger = logger;
        this._authSvcBaseUrl = authSvcBaseUrl;

        axios.defaults.baseURL = authSvcBaseUrl;
        this._client = axios.create({
            baseURL: authSvcBaseUrl,
            timeout: 1000,
            //headers: {'X-Custom-Header': 'foobar'} TODO config svc authentication
        })
    }

    async bootstrap(ignoreDuplicateError = false): Promise<boolean>{
        const appPrivileges:AppPrivileges = {
            boundedContextName: this._boundedContextName,
            applicationName: this._applicationName,
            applicationVersion: this._applicationVersion,
            privileges: this._privileges
        }

        return await new Promise<boolean>((resolve, reject) => {
            this._client.post("/bootstrap", appPrivileges).then((resp:AxiosResponse)=>{
                this._logger.debug(resp.data);
                resolve(true);
            }).catch((err:AxiosError) => {
                if(err.response && err.response.status === 409 && ignoreDuplicateError === true){
                    resolve(true);
                }
                this._logger.error(err, "Could not bootstrap privileges to Authentication Service");
                reject(err);
            });
        });

    }

    async fetch(): Promise<void>{
        const url = `/appRoles?bcName=${this._boundedContextName}&appName=${this._applicationName}`;

        return await new Promise<void>((resolve, reject) => {
            this._client.get(url).then((resp: AxiosResponse) => {
                this._logger.debug(resp.data);
                this._rolePrivileges = resp.data;
                this._lastFetchTimestamp = Date.now();
                resolve();
            }).catch((err: AxiosError) => {
                this._logger.error(err, "Could not fetch role privileges association from Authentication Service");
                reject(err);
            });
        });
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
