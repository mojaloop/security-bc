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

import axios, { AxiosResponse, AxiosInstance } from "axios";
import * as jwt from "jsonwebtoken";
import {Jwt} from "jsonwebtoken";
import {AuthToken} from "./types";
import {ILogger} from "@mojaloop/logging-bc-public-types-lib";
import {TokenEndpointResponse} from "@mojaloop/security-bc-public-types-lib";

const AUTH_HTTPCLIENT_TIMEOUT_MS = 5000;

export class LoginHelper{
    private _logger:ILogger;
    private _authBaseUrl:string;
    private _httpClient: AxiosInstance;

    constructor(authBaseUrl:string, logger:ILogger) {
        this._logger = logger;
        this._authBaseUrl = authBaseUrl;

        this._httpClient = axios.create({
            baseURL: this._authBaseUrl,
            timeout: AUTH_HTTPCLIENT_TIMEOUT_MS,
        });
    }

    async init():Promise<void> {
        return;
    }

    /**
     * Login using username and password
     * @param username
     * @param password
     * @returns Promise with access token
     */
    async loginUser(username:string, password:string):Promise<AuthToken|null>{
        try {
            const resp: AxiosResponse<any> = await this._httpClient.post("/login", {
                username: username,
                password: password
            }, {
                validateStatus: (status) => {
                    // Resolve only if the status code is 200 or 404, everything else throws
                    return status == 200 || status == 404;
                }
            });
            if(resp.status != 200){
                return null;
            }

            const tokenResp: TokenEndpointResponse = resp.data as TokenEndpointResponse;
            if(!tokenResp || ! tokenResp.access_token || !tokenResp.token_type || tokenResp.expires_in == undefined){
                return null;
            }

            const token = jwt.decode(tokenResp.access_token, {complete: true}) as Jwt;
            if(!token){
                return null;
            }

            return {
                accessToken: tokenResp.access_token,
                refreshToken: tokenResp.refresh_token ?? null,
                payload: token.payload,
                scope: tokenResp.scope
            }
        }catch(err){
            this._logger.error(err);
            return null;
        }
    }

    // loginApp(username:string, password:string):Promise<AuthToken|null>{
    //     throw new Error("not implemented");
    // }


}
