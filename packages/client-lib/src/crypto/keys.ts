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

import crypto, {KeyObject} from "crypto";

import {writeFileSync} from "fs";

import {ICryptoKeyManagement} from "@mojaloop/security-bc-public-types-lib";
import {pki} from "node-forge";

export class CryptoKeyManagementHelper implements ICryptoKeyManagement {
    /***
     * Creates an RSA key pair in PEM format using pkcs8 encoding for the private key and spki (SubjectPublicKeyInfo) encoded public key
     *
     * @param modulusLength - Key size in bits, default modulus length is 2048 bits
     * @return crypto.KeyPairKeyObjectResult
     */
    createRsaKeyPairSync(modulusLength = 2048): crypto.KeyPairKeyObjectResult {
        const keyOptions = {
            modulusLength: modulusLength,
            publicKeyEncoding: {
                type: "spki",
                format: "pem",
            },
            privateKeyEncoding: {
                type: "pkcs8",
                format: "pem",
            }
        };
        return crypto.generateKeyPairSync("rsa", keyOptions);
    }

    /***
     * Generates and saves in a file, a private RSA key file in PEM format using pkcs8 encoding
     *
     * Note: typical files have a "pem" extension.
     * @param filePath - destination of file to be created
     * @param modulusLength - Key size in bits, default modulus length is 2048 bits
     */
    createPrivateRsaKeyPemFileSync(filePath: string, modulusLength = 2048): void {
        const result = this.createRsaKeyPairSync(modulusLength);
        writeFileSync(filePath, Buffer.from(result.privateKey.toString()));
    }

    getPubKeyPemFromPrivateKeyPem(privateKeyPemStr: string) {
        const pubKeyObject = crypto.createPublicKey({
            key: privateKeyPemStr,
            format: "pem"
        });

        const publicKey = pubKeyObject.export({
            format: "pem",
            type: "spki"
        });

        return publicKey;
    }

    getHexEncodedRsaPublicKeyFingerprint(publicKey: KeyObject): string{
        try{
            const fingerprint = pki.getPublicKeyFingerprint(publicKey, {encoding: "hex", delimiter: "", type: "RSAPublicKey"});
            return fingerprint.toUpperCase();
        }catch(e){
            throw new Exception("Invalid public key in getHexEncodedRsaPublicKeyFingerprint()");
        }
    }
}
