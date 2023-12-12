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
import jwks, {JwksClient} from "jwks-rsa";
import {IMessage, IMessageConsumer, MessageTypes} from "@mojaloop/platform-shared-lib-messaging-types-lib";
import {AuthTokenInvalidatedEvt, SecurityBCTopics} from "@mojaloop/platform-shared-lib-public-messages-lib";
import crypto from "crypto";

export const DEFAULT_JWKS_PATH = "/.well-known/jwks.json";
const PUB_KEYS_UPDATE_INTERVAL_MS = 5*60*1000;

class BlockedJwt{
    jwtId:string;
    expirationTimestamp:number;
}

export class TokenHelper implements ITokenHelper {
    private _logger:ILogger;
    private _jwksUrl: string;
    private _updateTimer: NodeJS.Timeout;
    private readonly _issuerName: string | null;
    private readonly _audience: string | null;
    private readonly _jwksClient: JwksClient;
    private readonly _messageConsumer:IMessageConsumer | null;
    private readonly _blockedJwts: BlockedJwt[] = [];

    constructor( jwksUrl: string, logger:ILogger, issuerName?: string, audience?: string, messageConsumer:IMessageConsumer|null = null) {
        this._jwksUrl = jwksUrl;
        this._logger = logger.createChild(this.constructor.name);
        this._issuerName = issuerName || null;
        this._audience = audience || null;
        this._messageConsumer = messageConsumer;

        this._jwksClient = new jwks.JwksClient({
            jwksUri: jwksUrl,
            requestHeaders: {}, // Optional
            cache: true,
            cacheMaxAge: 5 * 60 * 1000, //5 mins
            timeout: 3000 // Defaults to 30s
        });
    }

    private async _preFetch(): Promise<number> {
        // do an initial request to test it works and cache it
        try{
            this._logger.debug("PreFetch() starting...");
            const keys = await this._jwksClient.getSigningKeys() || [];
            for (const k of keys) {
                k.getPublicKey();
            }
            this._logger.debug(`PreFetch() completed, loaded ${keys.length} keys.`);
            return keys.length;
        }catch (err){
            this._logger.error(err, "PreFetch() failed");
            return 0;
        }
    }

    private async _getSigningKey(kid:string):Promise<jwks.SigningKey | null> {
        let key: jwks.SigningKey;
        try{
            // this can throw a SigningKeyNotFoundError
            key = await this._jwksClient.getSigningKey(kid);
            return key;
        }catch(err:any) {
            this._logger.error(err, "getSigningKey() Error");
            return null;
        }
    }

    /**
     * Prefetches the public keys and starts the automatic update timer
     */
    async init(): Promise<void> {
        const keysFetched = await this._preFetch();
        if(keysFetched<=0){
            throw new Error("Could not get authentication service public keys, cannot continue");
        }

        // start the pub key fetch timer
        this._updateTimer = setInterval(async ()=>{
            // update public keys
            await this._preFetch();

            // Use the same interval (5 mins byt default)
            // NOTE: if PUB_KEYS_UPDATE_INTERVAL_MS is changed, consider a separate timer and interval for this
            this._cleanBlockedJwtsList();
        }, PUB_KEYS_UPDATE_INTERVAL_MS + crypto.randomInt(0,5000)); // random extra to avoid all clients at same time


        // if we have a consumer, start it and hook the msg handler
        if(this._messageConsumer){
            this._messageConsumer.setTopics([SecurityBCTopics.DomainEvents]);
            this._messageConsumer.setCallbackFn(this._messageHandler.bind(this));
            await this._messageConsumer.connect();
            await this._messageConsumer.startAndWaitForRebalance();
        }

        return Promise.resolve();
    }

    async destroy(): Promise<void> {
        if(this._updateTimer) clearInterval(this._updateTimer);
    }

    private async _messageHandler(message:IMessage):Promise<void>{
        if(message.msgType !== MessageTypes.DOMAIN_EVENT) return;

        if(message.msgName !== AuthTokenInvalidatedEvt.name) return;

        this._blockedJwts.push({
           jwtId: message.payload.tokenId,
           expirationTimestamp:message.payload.tokenExpirationDateTimestamp
        });
        this._logger.debug("AuthTokenInvalidatedEvt received, token id added to local JWT ID block list");
    }

    /**
     * Removes expired entries from the local list of blocked JWT ids
     * @private
     */
    private _cleanBlockedJwtsList(){
        if(!this._blockedJwts || this._blockedJwts.length<=0) return;

        this._logger.debug(`CleanBlockedJwtsList() starting, have ${this._blockedJwts.length} in the block list...`);
        const now = Date.now();

        for(let i=0; i< this._blockedJwts.length; i++){
            if(this._blockedJwts[i] && this._blockedJwts[i].expirationTimestamp > now) {
                this._blockedJwts.splice(i, 1);
            }
        }
        this._logger.debug(`CleanBlockedJwtsList() completed, have ${this._blockedJwts.length} in the block list.`);
    }

    private _isTokenIdBlocked(jwtId:string):boolean{
        // reject mistakes safe default
        if(!jwtId) return true;
        // check against invalidated token ids list
        const blocked = this._blockedJwts.find(value => value.jwtId.toUpperCase() === jwtId.toUpperCase());
        return blocked !== undefined;
    }

    /**
     * @deprecated the new init, which is required, already prefetches and starts the automatic update timer
     */
    async preFetch(): Promise<void> {
        await this._preFetch();
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

        try {
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

            const decoded = jwt.verify(accessToken, signingKey, verify_opts) as Jwt;

            if (!decoded) {
                this._logger.warn("Error verifying token, could not decode access token");
                return false;
            }

            const payload: any = decoded.payload;
            if(!payload || !payload.jti){
                this._logger.warn("Error verifying token, invalid payload or payload.jti");
                return false;
            }

            // check against invalidated token ids list
            if(this._isTokenIdBlocked(payload.jti)){
                this._logger.warn(`Error verifying token - blocked JWT Id used, jti: ${payload.jti}`);
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

            if(!decoded || !decoded.jti){
                this._logger.warn("Error verifying token, invalid payload or payload.jti");
                return null;
            }

            // check against invalidated token ids list
            if(this._isTokenIdBlocked(decoded.jti)){
                this._logger.warn(`Error verifying blocked JWT Id used - jti: ${decoded.jti}`);
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
