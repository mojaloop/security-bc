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

import fs from "fs";
import * as jwt from "jsonwebtoken";
import * as  uuid from "uuid";
import { BerReader } from "asn1";
import { createHash } from "crypto";

import {ICryptoAuthenticationAdapter} from "../domain/interfaces";
import {ILogger} from "@mojaloop/logging-bc-client-lib/dist/index";
import crypto from "crypto";
import * as nodejose from "node-jose";
import {urlencoded} from "express";

const PUBLIC_RSA_OID = "1.2.840.113549.1.1.1";
const PUBLIC_OPENING_BOUNDARY = "-----BEGIN PUBLIC KEY-----";
const PUBLIC_CLOSING_BOUNDARY = "-----END PUBLIC KEY-----";

const HASH_ALG = "SHA-256"; // these must match
const SIGNATURE_ALG = "RS256";

export class SimpleCryptoAdapter implements ICryptoAuthenticationAdapter{
    private readonly _logger: ILogger;
    private readonly _issuerName:string;
    private readonly _privateCertPath:string;
    private readonly _publicCertPath:string;
    private _privateCert: Buffer;
    private _publicCert: Buffer;
    private _privateKeyStr: string;
    private _publicKeyStr: string;
    private _publicKeyId: string;
    private _joseKeyStore: nodejose.JWK.KeyStore;

    constructor(privCertPath:string, pubCertPath:string, issuerName:string, logger: ILogger) {
        this._logger = logger;
        this._issuerName = issuerName;
        this._privateCertPath = privCertPath;
        this._publicCertPath = pubCertPath;
    }

    async init():Promise<void>{
        try {
            this._privateCert = fs.readFileSync(this._privateCertPath);
            this._privateKeyStr = this._privateCert.toString();

            this._publicCert = fs.readFileSync(this._publicCertPath);
            this._publicKeyStr = this._publicCert.toString();


            this._joseKeyStore = nodejose.JWK.createKeyStore();
            const key  = await this._joseKeyStore.add(this._publicCert, "pem");

            //this._publicKeyId = toSHA256(this._publicKeyStr);

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
            jwtid: uuid.v4(),
            keyid: this._publicKeyId,
            subject: sub
        };

        const accessCode = jwt.sign(additionalPayload, this._privateCert, signOptions);
        return accessCode;
    }
    async getJwsKeys():Promise<any>{
        // https://datatracker.ietf.org/doc/html/rfc7517
        // const keys = [createJWS(this._publicKeyStr)];
        // return keys;

        // const keystore = nodejose.JWK.createKeyStore();
        // const key = await keystore.add(this._publicCert, "pem");
        // this._logger.debug(key);
        return this._joseKeyStore.toJSON();
    }


    async generateRandomToken(length:number):Promise<string>{
        return generateRandomToken(length);
    }
}

/*
* HELPER FUNCTIONS to avoid having another file (this whole implementation should
* */

function generateRandomToken(length:number):string{
    return crypto.randomBytes(length / 2).toString("hex");
}

function createJWS(publicKey: string) {
    const kid = toSHA256(publicKey);
    const pem = trimSurroundingText(publicKey).replace(/\s+|\n\r|\n|\r$/gm, "");
    const buffer = Buffer.from(pem, "base64");
    let e = "";
    let n = "";

    try {
        const reader = new BerReader(buffer);
        reader.readSequence();

        const header = new BerReader(reader.readString(0x30, true));

        if (header.readOID(0x06) !== PUBLIC_RSA_OID) {
            throw Error("Invalid public key format");
        }

        const body = new BerReader(reader.readString(0x03, true));
        body.readByte(false);
        body.readSequence();

        n = body.readString(0x02, true).toString("base64"); // modulus
        e = body.readString(0x02, true).toString("base64"); // publicExponent
    } catch (e) {
        throw Error("Invalid public key format");
    }

    return {
        alg: "RS256",
        e,
        kid,
        kty: "RSA",
        n,
        use: "sig",
    };
}

function toSHA256(data: string) {
    return createHash("SHA256").update(data).digest("base64");
}

/*
 * Strips everything around the opening and closing lines, including the lines
 * themselves.
 */
function trimSurroundingText(data: string): string {
    let trimStartIndex = 0;
    let trimEndIndex = data.length;

    const openingBoundaryIndex = data.indexOf(PUBLIC_OPENING_BOUNDARY);
    if (openingBoundaryIndex >= 0) {
        trimStartIndex = openingBoundaryIndex + PUBLIC_OPENING_BOUNDARY.length;
    }

    const closingBoundaryIndex = data.indexOf(
            PUBLIC_CLOSING_BOUNDARY,
            openingBoundaryIndex,
    );
    if (closingBoundaryIndex >= 0) {
        trimEndIndex = closingBoundaryIndex;
    }

    return data.substring(trimStartIndex, trimEndIndex);
}
