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

import {ILogger} from "@mojaloop/logging-bc-public-types-lib";
import {CallSecurityContext, ITokenHelper} from "@mojaloop/security-bc-public-types-lib";
import jwt, {Jwt} from "jsonwebtoken";
import jwks, {JwksClient, SigningKeyNotFoundError} from "jwks-rsa";

export const DEFAULT_JWKS_PATH = "/.well-known/jwks.json";
const PUB_KEYS_UPDATE_INTERVAL_MS = 5*60*1000;

export class TokenHelper implements ITokenHelper {
    private _logger:ILogger;
    private _jwksUrl: string;
    private _issuerName: string | null;
    private _audience: string | null;
    private _jwksClient: JwksClient;
    private _updateTimer: NodeJS.Timeout;

    constructor( jwksUrl: string, logger:ILogger, issuerName?: string, audience?: string) {
        this._jwksUrl = jwksUrl;
        this._logger = logger.createChild(this.constructor.name);
        this._issuerName = issuerName || null;
        this._audience = audience || null;

        this._jwksClient = new jwks.JwksClient({
            jwksUri: jwksUrl,
            requestHeaders: {}, // Optional
            cache: true,
            cacheMaxAge: 5 * 60 * 1000, //5 mins
            timeout: 3000 // Defaults to 30s
        });
    }

    private async _preFetch(): Promise<void> {
        // do an initial request to test it works and cache it
        const keys = await this._jwksClient.getSigningKeys();
        for (const k of keys) {
            k.getPublicKey();
        }
    }

    private async _getSigningKey(kid:string):Promise<jwks.SigningKey | null> {
        let key: jwks.SigningKey;
        try{
            // this can throw a SigningKeyNotFoundError
            key = await this._jwksClient.getSigningKey(kid);
            return key;
        }catch(err:any) {
            return null;
        }
    }

    /**
     * Prefetches the public keys and starts the automatic update timer
     */
    async init(): Promise<void> {
        await this._preFetch();

        // start the timer
        this._updateTimer = setInterval(()=>{
            this.preFetch();
        }, PUB_KEYS_UPDATE_INTERVAL_MS);

        return Promise.resolve();
    }

    async destroy(): Promise<void> {
        if(this._updateTimer) clearInterval(this._updateTimer);
    }

    /**
     * @deprecated the new init already prefetches and starts the automatic update timer
     */
    async preFetch(): Promise<void> {
        return this._preFetch();
    }

    /**
     * Decode an access token string to return the payload
     * @param accessToken string
     */
    decodeToken(accessToken: string): any | null {
        const token = jwt.decode(accessToken, {complete: true}) as Jwt;

        return token && token.payload ? token.payload:null;
    }

    /**
     * Perform a full verification of an access token (sig, expiry, audience, issuer, etc..)
     * This will verify the signature against a public key available at the registered jwks url.
     * @param accessToken
     * @param audience
     */
    async verifyToken(accessToken: string): Promise<boolean> {
        const verify_opts: jwt.VerifyOptions = {complete: true};
        if (this._issuerName) verify_opts.issuer = this._issuerName;
        if (this._audience) verify_opts.audience = this._audience;

        const token = jwt.decode(accessToken, {complete: true}) as Jwt;
        if (!token || !token.header || !token.header || !token.header.kid) {
            this._logger.warn("could not decode token or token without kid");
            return false;
        }

        let key: jwks.SigningKey | null = await this._getSigningKey(token.header.kid);
        // if not found, let's re-fetch the keys and try once more
        if(!key){
            await this._preFetch();
            key = await this._getSigningKey(token.header.kid);
        }

        if (!key) {
            // still not found... we give up
            this._logger.warn(`Public signing key not found for kid: ${token.header.kid}`);
            return false;
        }

        const signingKey = key.getPublicKey();

        try {
            const decoded = jwt.verify(accessToken, signingKey, verify_opts) as Jwt;

            if (!decoded) {
                this._logger.warn("Error verifying token, could not decode access token");
                return false;
            }
            return true;
        } catch (err: any) {
            this._logger.warn(`Error verifying token: ${err.message}`);
            return false;
        }

    }

    async getCallSecurityContextFromAccessToken(accessToken:string):Promise<CallSecurityContext|null>{
        try {
            const verified = await this.verifyToken(accessToken);
            if (!verified) {
                return null;
            }

            const decoded = this.decodeToken(accessToken);
            if (!decoded.sub || decoded.sub.indexOf("::") == -1) {
                return null;
            }

            const subSplit = decoded.sub.split("::");
            const subjectType = subSplit[0];
            const subject = subSplit[1];

            return {
                accessToken: accessToken,
                clientId: subjectType.toUpperCase().startsWith("APP") ? subject : null,
                username: subjectType.toUpperCase().startsWith("USER") ? subject : null,
                platformRoleIds: decoded.platformRoles,
            };
        } catch (err) {
            this._logger.error(err, "unable to verify token");
            return null;
        }
    }

}
