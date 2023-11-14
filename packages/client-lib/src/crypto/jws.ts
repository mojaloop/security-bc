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
import crypto from "crypto";
import {
    Jwt,
    sign as jwsSign, SignOptions,
    verify as jwsVerify, VerifyOptions
} from "jsonwebtoken";

const minSignatureKeyLengthBits = 2048;

export enum AllowedSigningAlgorithms {
    RS256 = "RS256",
    RS384 = "RS384",
    RS512 = "RS512"
}

export class JsonWebSignatureHelper{
    private static _testPrivateKey(privateKeyPem:string){
        let loadedPrivateKey: crypto.KeyObject;
        try{
            loadedPrivateKey = crypto.createPrivateKey(privateKeyPem);
        }catch(err:any){
            throw new Error("Invalid private key");
        }

        // must be private, rsa and key of size 2048 bits or larger
        if(!loadedPrivateKey || loadedPrivateKey.type !==  "private"
            || loadedPrivateKey.asymmetricKeyType!=="rsa"
            || !loadedPrivateKey.asymmetricKeyDetails?.modulusLength
            || loadedPrivateKey.asymmetricKeyDetails?.modulusLength < minSignatureKeyLengthBits) {
            throw new Error("Invalid private key");
        }
    }

    private static _testPublicKey(publicKeyPem:string){
        let loadedPublicKey: crypto.KeyObject;
        try{
            loadedPublicKey = crypto.createPublicKey(publicKeyPem);
        }catch(err:any){
            throw new Error("Invalid public key");
        }

        // must be private, rsa and key of size 2048 bits or larger
        if(!loadedPublicKey || loadedPublicKey.type !==  "public"
            || loadedPublicKey.asymmetricKeyType!=="rsa"
            || !loadedPublicKey.asymmetricKeyDetails?.modulusLength
            || loadedPublicKey.asymmetricKeyDetails?.modulusLength < minSignatureKeyLengthBits) {
            throw new Error("Invalid public key");
        }
    }

    static sign(privateKeyPem:string, header:any, payload:any, alg:AllowedSigningAlgorithms): string{
        // test the key
        this._testPrivateKey(privateKeyPem);

        // check the alg
        if(!Object.values(AllowedSigningAlgorithms).includes(alg)) throw new Error("Invalid algorithm");

        const options: SignOptions = {
            algorithm: alg,
            encoding: "utf8",
            header: header,
        };

        try{
            const signedToken = jwsSign(payload, privateKeyPem, options);
            return signedToken;
        }catch(err:any){
            throw new Error(`Unable to sign - ${err?.message || "unknown error"}`);
        }
    }

    static verify(publicKeyPem:string, token:string, matchingAlgorithm:AllowedSigningAlgorithms): {
        header:any, payload:string, signature:string
    } {
        this._testPublicKey(publicKeyPem);

        const options:VerifyOptions={
            complete: true,
            algorithms: Object.values(AllowedSigningAlgorithms),

        };

        let decoded:Jwt;
        try{
            decoded = jwsVerify(token, publicKeyPem, options) as Jwt;
        }catch(err:any){
            throw new Error(`Unable to verify token - ${err?.message || "unknown error"}`);
        }

        if(decoded.header.alg !== matchingAlgorithm)
            throw new Error("Algorithm in token does not match provided algorithm");

        return {
            header:decoded.header,
            payload: decoded.payload.toString(),
            signature: decoded.signature
        };
    }

}
