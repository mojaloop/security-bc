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

import {IAMAuthenticationAdapter} from "../domain/interfaces";

import {UserLoginResponse, LoginResponse} from "@mojaloop/security-bc-public-types-lib";
import {ILogger} from "@mojaloop/logging-bc-public-types-lib";

export class BuiltinIamAdapter implements IAMAuthenticationAdapter{
    private readonly _logger:ILogger;
    private readonly _builtinIamSvcUrl: string;

    constructor(builtinIamSvcUrl:string, logger:ILogger) {
        this._logger = logger.createChild(this.constructor.name);
        this._builtinIamSvcUrl = builtinIamSvcUrl;


        this._logger.info(`Starting BuiltinIamAdapter with url: "${this._builtinIamSvcUrl}"`);
    }

    async init(): Promise<void>{
        return Promise.resolve();
    }

    private async _login(type:"USER"|"APP",client_id:string, client_secret?:string, username?: string, password?: string): Promise<UserLoginResponse | LoginResponse | null> {
        try {
            const url = new URL("/login", this._builtinIamSvcUrl).toString();
            const headers = new Headers();
            headers.append("Accept", "application/json");
            headers.append("Content-Type", "application/json");

            const body:any={
                client_id: client_id,
            };
            if(type==="USER"){
                body.grant_type = "password";
                body.username = username;
                body.password = password;
            }else{
                body.grant_type = "client_credentials";
                body.client_secret = client_secret;
            }

            const bodyStr =  JSON.stringify(body);

            const svcResponse = await fetch(url, {
                method: "POST",
                headers: headers,
                body: bodyStr
            });

            if(svcResponse.status === 200){
                const data:UserLoginResponse|LoginResponse = await svcResponse.json();
                // TODO confirm response contents
                return data;
            }

            return null;
        } catch (e: unknown) {
            this._logger.error(e);
            // handle everything else
            return null;
        }

    }

    async loginApp(client_id: string, client_secret: string): Promise<LoginResponse | null> {
        return this._login("APP", client_id, client_secret);
    }

    async loginUser(client_id:string, client_secret:string|null, username: string, password: string): Promise<UserLoginResponse | null> {
        const resp:UserLoginResponse|null = await this._login("USER", client_id, undefined, username, password) as UserLoginResponse|null;
        return resp;
    }
}
