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

import {ILogger} from "@mojaloop/logging-bc-public-types-lib";
import {AuthToken, TokenEndpointResponse, UnauthorizedError, ILoginHelper} from "@mojaloop/security-bc-public-types-lib";
import jwt, {Jwt} from "jsonwebtoken";
import {ConnectionRefusedError} from "./errors";
import {DEFAULT_JWKS_PATH, TokenHelper} from "./token_helper";

const JWKS_FETCH_KEYS_TIMEOUT_MS = 5*1000*60; // 5 mins

// private
declare type AuthMode = "APP_CREDS" | "USER_CREDS" | "PROVIDED_TOKEN";

export class LoginHelper implements ILoginHelper {
	private readonly _logger: ILogger;
	private readonly _authTokenUrl: string;
	private readonly _tokenHelper: TokenHelper;
	private _authMode: AuthMode;

	private _client_id: string | null = null;
	private _client_secret: string | null = null;
	private _username: string | null = null;
	private _password: string | null = null;

	private _responseObj: TokenEndpointResponse | null = null;
	private _decodedToken: jwt.Jwt | null = null;
	private _access_token: string | null = null;
	private _access_token_expires_in: number | null = null;
	private _access_token_expires_at: number | null = null;
	private _refreshToken: string | null = null;
	private _refresh_token_expires_in: number | null = null;
	private _refresh_token_expires_at: number | null = null;

	private _initialised = false;
	private _tokenHelperNeedsInit = true;

	constructor(authTokenUrl: string, logger: ILogger) {
		this._logger = logger.createChild(this.constructor.name);
		this._authTokenUrl = authTokenUrl;

		const url = new URL(authTokenUrl);

		this._tokenHelper = new TokenHelper(`${url.protocol}//${url.hostname}:${url.port}${DEFAULT_JWKS_PATH}`, this._logger);

		// fetch new jwks every 5 mins

	}

	get initialised(): boolean {
		return this._initialised;
	}

	/**
	 * Set a caller provided token to be used on getToken()
	 * This disables the auto token fetching mechanism
	 * This call can throw an UnauthorizedError if the token cannot be decoded (no valid check is performed, only decode)
	 * @param accessToken
	 */

	setToken(accessToken: string): void {
		this._resetPrivateData();
		this._authMode = "PROVIDED_TOKEN";
		this._parseAndLoadAccessToken(accessToken);
		this._initialised = true;
	}

	setUserCredentials(client_id: string, username: string, password: string): void {
		this._resetPrivateData();
		this._authMode = "USER_CREDS";
		this._client_id = client_id;
		this._username = username;
		this._password = password;
		this._initialised = true;
	}

	setAppCredentials(client_id: string, client_secret: string): void {
		this._resetPrivateData();
		this._authMode = "APP_CREDS";
		this._client_id = client_id;
		this._client_secret = client_secret;
		this._initialised = true;
	}

	async getToken(): Promise<AuthToken> {
		if (!this._initialised) {
			return Promise.reject(new Error("Uninitialised, please call setUserCredentials() or setAppCredentials() before using getToken()"));
		}

		if (this._tokenHelperNeedsInit) {
			await this._tokenHelper.init();
			this._tokenHelperNeedsInit = false;

			// schedule flag reset in JWKS_FETCH_KEYS_TIMEOUT_MS
			setTimeout(() => {
				this._tokenHelperNeedsInit = true;
			}, JWKS_FETCH_KEYS_TIMEOUT_MS);
		}

		if (await this._haveValidToken()) {
			return Promise.resolve(this._constructAuthTokenObj());
		}

		if (this._authMode==="PROVIDED_TOKEN") {
			throw new UnauthorizedError("Invalid provided token");
		}

		// only for authMode not PROVIDED_TOKEN
		await this._requestToken();

		return Promise.resolve(this._constructAuthTokenObj());
	}

	private _constructAuthTokenObj(): AuthToken {
		return {
			payload: this._decodedToken!.payload,
			accessToken: this._access_token!,
			accessTokenExpiresIn: this._access_token_expires_in!,
			refreshToken: this._refreshToken,
			refreshTokenExpiresIn: this._refresh_token_expires_in,
			scope: this._responseObj?.scope
		};
	}

	private async _haveValidToken(): Promise<boolean> {
		if (!this._decodedToken || !this._access_token) return false;

		return this._tokenHelper.verifyToken(this._access_token);
	}

	private _resetPrivateData() {
		this._responseObj = null;
		this._decodedToken = null;
		this._access_token = null;
		this._access_token_expires_in = null;
		this._access_token_expires_at = null;
		this._refreshToken = null;
		this._refresh_token_expires_in = null;
		this._refresh_token_expires_at = null;
	}

	private _parseAndLoadAccessToken(accessToken: string) {
		let token: jwt.Jwt;
		try {
			token = jwt.decode(accessToken, {complete: true}) as Jwt;
			if (!token) {
				throw new UnauthorizedError("Error decoding received token");
			}
		} catch (err) {
			// don't care, it's not a valid token
			throw new UnauthorizedError("Error decoding received token");
		}

		this._decodedToken = token;
		this._access_token = accessToken;

		const tokenPayload = token.payload as jwt.JwtPayload;

		if (tokenPayload.exp)
			this._access_token_expires_at = tokenPayload.exp * 1000;
		if (tokenPayload.exp && tokenPayload.iat)
			this._access_token_expires_in = tokenPayload.exp - tokenPayload.iat;
	}

	private _requestToken(): Promise<void> {
		// make sure old values are not kept
		this._resetPrivateData();

		let payload: any;
		if (this._authMode==="USER_CREDS") {
			payload = {
				grant_type: "password",
				client_id: this._client_id,
				username: this._username,
				password: this._password
				// audience
				// scope
			};
		} else if (this._authMode==="APP_CREDS") {
			payload = {
				grant_type: "client_credentials",
				client_id: this._client_id,
				client_secret: this._client_secret,
				// audience
				// scope
			};
		}

		return new Promise<void>((resolve, reject) => {
			const headers = new Headers();
			headers.append("Accept", "application/json");
			headers.append("Content-Type", "application/json");

			const reqInit: RequestInit = {
				method: "POST",
				headers: headers,
				body: JSON.stringify(payload)//body
			};

			fetch(this._authTokenUrl, reqInit).then(async resp => {
				if (resp.status===200) {
                    const respObj: TokenEndpointResponse = await resp.json();
                    const accessToken = respObj.access_token;

                    try {
                        this._parseAndLoadAccessToken(accessToken);
                    } catch (err) {
                        return reject(err);
                    }

                    this._responseObj = respObj;

                    // load refresh token if received
                    if (respObj.refresh_token){
                        this._refreshToken = respObj.refresh_token;
                        this._refresh_token_expires_in = respObj.refresh_token_expires_in;
                        if (respObj.access_token && respObj.refresh_token_expires_in)
                            this._refresh_token_expires_at = Date.now() + respObj.refresh_token_expires_in * 1000;
                    }
					return resolve();
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
				} else if (reason && reason.cause && reason.cause.code==="ENOTFOUND") {
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
