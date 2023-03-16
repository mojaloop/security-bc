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

import {readFileSync, writeFileSync} from "fs";
import * as jwt from "jsonwebtoken";
import * as Crypto from "crypto";


import {ICryptoAuthenticationAdapter} from "../domain/interfaces";
import {ILogger} from "@mojaloop/logging-bc-public-types-lib";
import crypto from "crypto";
import * as nodejose from "node-jose";

const HASH_ALG = "SHA-256"; // these must match
const SIGNATURE_ALG = "RS256";

export class SimpleCryptoAdapter2 implements ICryptoAuthenticationAdapter{
    private readonly _logger: ILogger;
    private readonly _issuerName:string;
    private readonly _privateCertPath:string;
    private _privateKey: Buffer;
    private _privateKeyObj: crypto.KeyObject;
    private _publicKeyObj: crypto.KeyObject;


    private _publicKeyId: string;
    private _joseKeyStore: nodejose.JWK.KeyStore;

    constructor(privCertPath:string, issuerName:string, logger: ILogger) {
        this._logger = logger;
        this._issuerName = issuerName;
        this._privateCertPath = privCertPath;
    }

    async init():Promise<void>{
        try {
            this._privateKey =  readFileSync(this._privateCertPath);

            this._privateKeyObj =  crypto.createPrivateKey(this._privateKey);
            this._publicKeyObj = crypto.createPublicKey(this._privateKey);

            this._joseKeyStore = nodejose.JWK.createKeyStore();
            const key  = await this._joseKeyStore.add(this._privateKey, "pem");

            const keyId = await key.thumbprint(HASH_ALG);
            this._publicKeyId = Buffer.from(keyId).toString("base64");
            this._publicKeyId = this._publicKeyId.replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
        }catch(err){
            // log
            this._logger.error(err);
            throw err;
        }
    }

    async generateJWT(additionalPayload:any, sub:string, aud:string, lifeInSecs:number):Promise<string>{

        // https://datatracker.ietf.org/doc/html/rfc7519
        const signOptions: jwt.SignOptions = {
            algorithm: SIGNATURE_ALG,
            audience: aud,
            expiresIn: lifeInSecs,
            issuer: this._issuerName,
            jwtid: Crypto.randomUUID(),
            keyid: this._publicKeyId,
            subject: sub
        };

        const accessCode = jwt.sign(additionalPayload, this._privateKey, signOptions);
        return accessCode;
    }
    async getJwsKeys():Promise<any>{
        return this._joseKeyStore.toJSON();
    }


    static createRsaPrivateKeyFileSync(filePath:string, modulusLength = 2048):void{
        const keyOptions = {
            modulusLength: modulusLength,
            publicKeyEncoding: {
                type: "spki",
                format: "pem"
            },
            privateKeyEncoding: {
                type: "pkcs8",
                format: "pem",
                //cipher: 'aes-256-cbc',   // *optional*
                //passphrase: 'top secret' // *optional*
            }
        };
        const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", keyOptions);
        writeFileSync(filePath, Buffer.from(privateKey.toString()));
    }
}
