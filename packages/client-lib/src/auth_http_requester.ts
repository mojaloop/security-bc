/// <reference lib="dom" />

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

/*
NOTES on Fetch API usage and node version
- This helper requires Node v18 or higher.
- Until a better solution is found, this file requires "/// <reference lib="dom" />" on the first line,
  to avoid adding "dom" to tsconfig.json compilerOptions->lib array in client projects
*/
import {randomUUID} from "crypto";
import {ILogger} from "@mojaloop/logging-bc-public-types-lib";

import {
    TokenEndpointResponse,
    UnauthorizedError,
    IAuthenticatedHttpRequester
} from "@mojaloop/security-bc-public-types-lib";
import {ConnectionRefusedError, MaxRetriesReachedError, RequestTimeoutError} from "./errors";


const MAX_RETRIES = 3;
const DEFAULT_TIMEOUT_MS = 5000;

// private
declare type AuthMode = "APP" | "USER";
declare type QueueItemCallback = (err: Error | null, response: Response | null) => void;

class AuthenticatedHttpRequesterQueueItem {
	readonly id: string;
	readonly requestInfo: RequestInfo;
	readonly callback: QueueItemCallback;
	readonly timeoutMs: number = 0;
	tries: number;

	constructor(requestInfo: RequestInfo, callback: QueueItemCallback, timeoutMs:number) {
		this.id = randomUUID();
		this.requestInfo = requestInfo;
		this.callback = callback;
		this.tries = 0;
		this.timeoutMs = timeoutMs;
	}
}

export class AuthenticatedHttpRequester implements IAuthenticatedHttpRequester{
	private readonly _logger: ILogger;
	private readonly _authTokenUrl: string;
	private _authMode: AuthMode;

	private _client_id: string | null = null;
	private _client_secret: string | null = null;
	private _username: string | null = null;
	private _password: string | null = null;

	private _access_token:string | null = null;
	private _access_token_expires_in: number | null = null;
	private _access_token_expires_at: number | null = null;
	private _refreshToken: string | null = null;
	private _refresh_token_expires_in: number | null = null;
	private _refresh_token_expires_at: number | null = null;

	private _queue: AuthenticatedHttpRequesterQueueItem[] = []
	private _queue_processing = false;
	private _initialised = false;

	constructor(
		logger: ILogger,
		authTokenUrl: string,
		timeoutMs: number = DEFAULT_TIMEOUT_MS
	) {
		this._logger = logger;
		this._authTokenUrl = authTokenUrl;
	}

	get initialised(): boolean {
		return this._initialised;
	}

	setUserCredentials(client_id: string, username: string, password: string):void {
		this._authMode = "USER";
		this._client_id = client_id;
		this._username = username;
		this._password = password;
		this._initialised = true;
	}

	setAppCredentials(client_id: string, client_secret: string): void{
		this._authMode = "APP";
		this._client_id = client_id;
		this._client_secret = client_secret;
		this._initialised = true;
	}

	async fetch(requestInfo: RequestInfo, timeoutMs:number = DEFAULT_TIMEOUT_MS): Promise<Response>{
		if(!this._initialised) {
			return Promise.reject(new Error("Uninitialised, please call setUserCredentials() or setAppCredentials() before using fetch()"));
		}

		setImmediate(this._processQueue.bind(this));

		return new Promise<Response>((resolve, reject) => {
			const callback: QueueItemCallback = (err:Error| null, response: Response | null)=>{
				if(err){
					return reject(err);
				}
				resolve(response!); // make sure below we only call either with error or with proper response
			}
			this._queue.push(new AuthenticatedHttpRequesterQueueItem(requestInfo, callback, timeoutMs));
		});
	}

	private async _processQueue():Promise<void>{

		const shifted: AuthenticatedHttpRequesterQueueItem | undefined = this._queue.shift();
		if (!shifted) return;

		const item: AuthenticatedHttpRequesterQueueItem = shifted;

		await this._checkAndFetchToken().catch((err:Error) => {
			item.callback(err, null);
			setImmediate(this._processQueue.bind(this));
			return;
		});

		if(item.tries >= MAX_RETRIES){
			item.callback(new MaxRetriesReachedError(), null);
			setImmediate(this._processQueue.bind(this));
			return;
		}

		this._queue_processing = true;

		const controller = new AbortController();
		const options: RequestInit = {
			signal: controller.signal,
			headers: [
				["Content-Type", "application/json"],
				["Authorization", `Bearer: ${this._access_token}`]
			]
		};

		const timeoutId = setTimeout(() => {
			controller.abort();
		}, item.timeoutMs);


		fetch(item.requestInfo, options).then( (response) => {
			if (response.status === 403) {
				item.tries++;
				this._queue.unshift(item);
				return;
			}

			clearTimeout(timeoutId);
			item.callback(null, response);
		}).catch(reason => {
			// When abort() is called, the fetch() promise rejects with a DOMException named AbortError
			clearTimeout(timeoutId);

			if(reason instanceof DOMException && reason.name === "AbortError"){
				item.callback(new RequestTimeoutError(), null);
			}else if(reason && reason.cause && reason.cause.code ==="ECONNREFUSED"){
				item.callback(new ConnectionRefusedError(), null);
			}else {
				item.callback(new Error(reason && reason.name ? reason.name : reason), null);
			}
		}).finally(()=>{
			this._queue_processing = false;
			setImmediate(this._processQueue.bind(this));
		});
	}


	/**
	 * Checks for valid token and fetches it if no token is found
	 * @private
	 * @returns Promise<boolean> - true if token exists (or fetched ok), false if not able to fetch a token
	 */
	private async _checkAndFetchToken():Promise<void>{
		// TODO properly check the token, not just if it exists
		if(this._access_token && this._access_token_expires_at && this._access_token_expires_at > Date.now()){
			return Promise.resolve();
		}

		const payload = {
			grant_type: this._authMode==="USER" ? "password" : "client_credentials",
			client_id: this._client_id,
			client_secret: this._client_secret,
			username: this._username,
			password: this._password
			// audience
			// scope
		}

		// const body = new FormData();
		// body.append("json", JSON.stringify(payload));

		const headers = new Headers();
		headers.append("Accept", "application/json");
		headers.append("Content-Type", "application/json");

		return new Promise<void>((resolve, reject)=>{
			const reqInit: RequestInit = {
				method: "POST",
				headers: headers,
				body: JSON.stringify(payload)//body
			};

			fetch(this._authTokenUrl, reqInit).then(async resp => {
				if(resp.status === 200){
					const respObj: TokenEndpointResponse = await resp.json();

					this._access_token = respObj.access_token;
					this._access_token_expires_in = respObj.expires_in;
					if(respObj.expires_in)
						this._access_token_expires_at = Date.now() + respObj.expires_in * 1000;

					this._refreshToken = respObj.refresh_token;
					this._refresh_token_expires_in = respObj.refresh_token_expires_in;
					if (respObj.access_token && respObj.refresh_token_expires_in)
						this._refresh_token_expires_at = Date.now() + respObj.refresh_token_expires_in * 1000;

					return resolve();
				}else if (resp.status === 401){
					// login failed
					this._logger.warn("Login failed");
					return reject(new UnauthorizedError("Login failed"));
				}else {
					//generic error
					const err = new Error("Unsupported response in fetching token - status code: " + resp.status);
					this._logger.error(err);
					return reject(err);
				}
			}).catch(reason => {
				const err = new Error("Unknown error fetching token - err: " + (reason instanceof Error) ? reason.message:reason);
				this._logger.error(err);
				reject(err);
			});

		});
	}

}
