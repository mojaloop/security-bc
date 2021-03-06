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
'use strict'
import * as jwt from "jsonwebtoken";
import * as jwks from "jwks-rsa";
import {Jwt} from "jsonwebtoken";
import {JwksClient} from "jwks-rsa";
import {ILogger} from "@mojaloop/logging-bc-public-types-lib";

export class TokenHelper {
    private _logger:ILogger;
    private _jwksUrl: string;
    private _issuerName: string;
    private _audience: string;
    private _jwksClient: JwksClient;

    constructor(issuerName: string, jwksUrl: string, audience:string, logger:ILogger) {
        this._logger = logger;
        this._issuerName = issuerName;
        this._audience = audience;
        this._jwksUrl = jwksUrl;

        this._jwksClient = new jwks.JwksClient({
            jwksUri: jwksUrl,
            requestHeaders: {}, // Optional
            cache: true,
            cacheMaxAge: 5 * 60 * 1000, //5 mins
            timeout: 3000 // Defaults to 30s
        });
    }

    async init(): Promise<void> {

        // do an initial request to test it works and cache it
        const keys = await this._jwksClient.getSigningKeys();
        for(const k of keys){
            k.getPublicKey();
        }
        // TODO setup timer
    }

    /**
     * Decode an access token string to return the payload
     * @param accessToken string
     */
    decodeToken(accessToken: string):any|null{
        const token = jwt.decode(accessToken, {complete: true}) as Jwt;

        return token && token.payload ? token.payload : null;
    }

    /**
     * Perform a full verification of an access token (sig, expiry, audience, issuer, etc..)
     * This will verify the signature against a public key available at the registered jwks url.
     * @param accessToken
     * @param audience
     */
    async verifyToken(accessToken: string): Promise<boolean> {
        const verify_opts: jwt.VerifyOptions = {
            complete: true,
            issuer: this._issuerName,
            audience: this._audience,

        };

        const token = jwt.decode(accessToken, {complete: true}) as Jwt;
        if(!token || !token.header || !token.header || !token.header.kid){
            this._logger.warn("could not decode token or token without kid");
            return false;
        }

        const key = await this._jwksClient.getSigningKey(token.header.kid);
        if(!key){
            this._logger.warn(`public signing key not found for kid: ${token.header.kid}`);
            return false;
        }

        const signingKey = key.getPublicKey();

        const decoded = jwt.verify(accessToken, signingKey, verify_opts) as Jwt;

        if (!decoded) {
            return false;
        }

        return true;
    }


}
