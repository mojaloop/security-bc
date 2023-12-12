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
import {Redis} from "ioredis";
import {IJwtIdsRepository} from "../domain/interfaces";

declare type CacheItem = {
    secPrincipalId:string;
    tokens: {
        jti: string;
        tokenExpirationDateTimestamp: number;
    }[]
}

export class JwtIdRedisRepo implements IJwtIdsRepository{
    private readonly _logger: ILogger;
    private readonly _keyPrefix= "jwtIdRedisRepo_";
    private _redisClient: Redis;

    constructor(
        logger: ILogger,
        redisHost: string,
        redisPort: number
    ) {
        this._logger = logger.createChild(this.constructor.name);
        this._redisClient = new Redis({
            port: redisPort,
            host: redisHost,
            lazyConnect: true
        });
    }

    async init(): Promise<void> {
        try{
            await this._redisClient.connect();
        }catch(error: unknown){
            this._logger.error(`Unable to connect to redis cache: ${(error as Error).message}`);
            throw error;
        }
    }

    async destroy(): Promise<void> {
        return Promise.resolve();
    }

    private _getKeyWithPrefix (key: string): string {
        return this._keyPrefix + key;
    }


    // Set jwt id / secPrincipalId association that will expire and be automatically removed after tokenExpirationDateTimestamp
    async set(secPrincipalId:string, jti:string, tokenExpirationDateTimestamp:number):Promise<void>{
        const keyId = this._getKeyWithPrefix(secPrincipalId);
        // try to get existing
        let cachedList = await this.get(secPrincipalId); // not key
        if(!cachedList || cachedList.length<=0){
            cachedList = [{jti: jti, tokenExpirationDateTimestamp: tokenExpirationDateTimestamp}];
        }else{
            // remove expired values when we can (as we only expire the whole key)
            const now = Date.now();
            cachedList = cachedList.filter(value => value.tokenExpirationDateTimestamp > now);
            // add the new
            cachedList.push({jti: jti, tokenExpirationDateTimestamp: tokenExpirationDateTimestamp});
        }

        const cacheItem:CacheItem = {
            secPrincipalId: secPrincipalId,
            tokens: cachedList
        };

        // get max expire timestamp
        const tsArray = cacheItem.tokens.map(value => value.tokenExpirationDateTimestamp);
        const maxTs = Math.max(...tsArray);

        await this._redisClient.set(keyId, JSON.stringify(cacheItem), "PXAT", maxTs);
    }

    // Get a list of jwt ids associated with the secPrincipalId (not expired)
    async get(secPrincipalId:string):Promise<{jti:string, tokenExpirationDateTimestamp:number}[]>{
        const keyId = this._getKeyWithPrefix(secPrincipalId);
        // try to get existing
        const existingStr = await this._redisClient.get(keyId);
        if(!existingStr) return [];

        try{
            const obj:CacheItem = JSON.parse(existingStr);
            if(!obj || !obj.tokens) return [];
            return obj.tokens;
        }catch (e) {
            this._logger.error(e);
            return [];
        }
    }

    // remove all token association for secPrincipalId
    async del(secPrincipalId:string):Promise<void>{
        const keyId = this._getKeyWithPrefix(secPrincipalId);
        await this._redisClient.del(keyId);
    }
}
