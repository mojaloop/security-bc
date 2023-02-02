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

import jwt, {Jwt} from "jsonwebtoken";
import {AuthToken, ConnectionRefusedError, UnauthorizedError} from "./types";
import {ILogger} from "@mojaloop/logging-bc-public-types-lib";
import {TokenEndpointResponse} from "@mojaloop/security-bc-public-types-lib";

const AUTH_HTTPCLIENT_TIMEOUT_MS = 5000;

export class LoginHelper{
    private _logger:ILogger;
    private _authBaseUrl:string;

    constructor(authBaseUrl:string, logger:ILogger) {
        this._logger = logger;
        this._authBaseUrl = authBaseUrl;
    }

    async init():Promise<void> {
        return Promise.resolve();
    }

    /**
     * Tries to login and return a valid user token using the password flow (user to service)
     * @param username
     * @param password
     * @returns Promise with access token
     */
    async loginUser(client_id: string, username: string, password: string):Promise<AuthToken>{
        return this._requestToken({
            grant_type: "password",
            client_id: client_id,
            username: username,
            password: password
            // audience
            // scope
        });
    }

    /**
     * Tries to login and return a valid application token using the client_credentials flow (service to service)
     * @param client_id
     * @param client_secret
     * @param scope (optional)
     */

    async loginApp(client_id: string, client_secret: string, scope?:string):Promise<AuthToken>{
        return this._requestToken({
            grant_type: "client_credentials",
            client_id: client_id,
            client_secret: client_secret,
            // audience
            // scope
        });
    }

    private _requestToken(payload: any): Promise<AuthToken> {
        return new Promise<AuthToken>((resolve, reject) => {
            const headers = new Headers();
            headers.append("Accept", "application/json");
            headers.append("Content-Type", "application/json");

            const reqInit: RequestInit = {
                method: "POST",
                headers: headers,
                body: JSON.stringify(payload)//body
            };

            fetch(this._authBaseUrl, reqInit).then(async resp => {
                if (resp.status===200) {
                    const respObj: TokenEndpointResponse = await resp.json();
                    const accessToken = respObj.access_token;

                    let token: jwt.Jwt;
                    try {
                        token = jwt.decode(accessToken, {complete: true}) as Jwt;
                        if (!token) {
                            return reject(new UnauthorizedError("Error decoding received token"));
                        }
                    } catch (err) {
                        // don't care, it's not a valid token
                        return reject(new UnauthorizedError("Error decoding received token"));
                    }

                    const respAuthToken: AuthToken = {
                        accessToken: respObj.access_token,
                        accessTokenExpiresIn: respObj.expires_in,
                        refreshToken: respObj.refresh_token,
                        refreshTokenExpiresIn: respObj.refresh_token_expires_in,
                        payload: token.payload,
                        scope: respObj.scope
                    };

                    return resolve(respAuthToken);
                } else if (resp.status===401) {
                    // login failed
                    this._logger.warn("Login failed");
                    return reject(new UnauthorizedError("Login failed"));
                } else {
                    //generic error
                    const err = new Error("Unsupported response in fetching token - status code: " + resp.status);
                    this._logger.error(err);
                    return reject(err);
                }
            }).catch(reason => {
                if (reason && reason.cause && (reason.cause.code==="ECONNREFUSED" || reason.cause.code==="UND_ERR_SOCKET")) {
                    const err = new ConnectionRefusedError();
                    this._logger.error(err);
                    return reject(err);
                }else if(reason && reason.cause && reason.cause.code ==="ENOTFOUND"){
                    this._logger.error(reason.cause);
                    return reject(reason.cause); // reason.cause is an Error obj
                }
                const err = new Error("Unknown error fetching token - err: " + (reason instanceof Error) ? reason.message:reason);
                this._logger.error(err);
                reject(err);
            });
        });
    }

}
