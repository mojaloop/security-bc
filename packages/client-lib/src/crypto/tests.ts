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
import forge, {pki} from "node-forge";

import {CryptoKeyManagementHelper} from "./keys";
import {CertificatesHelper} from "./certificate";

const certHelper = new CertificatesHelper();
const keyHelper = new CryptoKeyManagementHelper();

/**
 *
 * CERTIFICATE AUTHORITY Vars and functions
 *
 *
 * */

const CA_Store: pki.CAStore = pki.createCaStore();

/**
 *
 * ROOT CA keys and cert
 *
 * */

let CA_root_PrivateKeyPEM:string;
let CA_root_PrivateKey: forge.pki.rsa.PrivateKey;
let CA_root_PublicKey:  forge.pki.rsa.PublicKey;
let CA_root_cert_PEM:string;
let CA_root_cert:forge.pki.Certificate;

function CA_root_loadKeys(){
    CA_root_PrivateKeyPEM = `-----BEGIN PRIVATE KEY-----
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
GfBpgZtxXcCF99MbNGhFnSM1kKxzT2g=
-----END PRIVATE KEY-----`;
    CA_root_PrivateKey = pki.privateKeyFromPem(CA_root_PrivateKeyPEM);
    CA_root_PublicKey = pki.setRsaPublicKey(CA_root_PrivateKey.n, CA_root_PrivateKey.e);

    console.log("\nCA KEYS LOADED");
}

function CA_root_createKeys(){
    const CA_KeyPair = keyHelper.createRsaKeyPairSync(4096);
    CA_root_PrivateKeyPEM = CA_KeyPair.privateKey.toString();
    CA_root_PrivateKey = pki.privateKeyFromPem(CA_KeyPair.privateKey.toString());
    CA_root_PublicKey = pki.publicKeyFromPem(CA_KeyPair.publicKey.toString());


    console.log("\nCA KEYPAIR CREATED - Private key:");
    console.log(CA_root_PrivateKeyPEM);
}

function CA_root_loadCert(){
    CA_root_cert_PEM = `-----BEGIN CERTIFICATE-----
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
Lmzc7JmdTYNS8Q7C+GBdWxmLcgYYIRAN6UM=
-----END CERTIFICATE-----`;
    CA_root_cert = pki.certificateFromPem(CA_root_cert_PEM);

    CA_Store.addCertificate(CA_root_cert);

    console.log("\nCA ROOT CERTIFICATE LOADED");
}

function CA_root_createCert(){
    CA_root_cert_PEM = certHelper.createX590CertificateAuthorityCert(
        CA_root_PrivateKeyPEM, //CA_KeyPair.privateKey.toString(),
        "Dev Switch 1 - ROOT Cert", "Portugal", "(none)", "Lisbon", "Mojaloop", "vNextTeam", 10
    );
    CA_root_cert = forge.pki.certificateFromPem(CA_root_cert_PEM);

    CA_Store.addCertificate(CA_root_cert);

    console.log("\nCA ROOT CERTIFICATE CREATED:");
    console.log(CA_root_cert_PEM);
}

/**
 *
 * Intermediate CA keys and cert
 * */


let CA_intermediate_PrivateKeyPEM:string;
let CA_intermediate_PrivateKey: forge.pki.rsa.PrivateKey;
let CA_intermediate_PublicKey:  forge.pki.rsa.PublicKey;
let CA_intermediate_cert_PEM:string;
let CA_intermediate_cert:forge.pki.Certificate;



function CA_intermediate_loadKeys(){
    CA_intermediate_PrivateKeyPEM = `-----BEGIN PRIVATE KEY-----
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
S9xI/hJ1M2mOvF7UBgFQQrvYpIKa
-----END PRIVATE KEY-----`;
    CA_intermediate_PrivateKey = pki.privateKeyFromPem(CA_intermediate_PrivateKeyPEM);
    CA_intermediate_PublicKey = pki.setRsaPublicKey(CA_intermediate_PrivateKey.n, CA_intermediate_PrivateKey.e);

    console.log("\nCA INTERMEDIATE KEYS LOADED");
}

function CA_intermediate_createKeys(){
    const CA_KeyPair = keyHelper.createRsaKeyPairSync(4096);
    CA_intermediate_PrivateKeyPEM = CA_KeyPair.privateKey.toString();
    CA_intermediate_PrivateKey = pki.privateKeyFromPem(CA_KeyPair.privateKey.toString());
    CA_intermediate_PublicKey = pki.publicKeyFromPem(CA_KeyPair.publicKey.toString());

    console.log("\nCA INTERMEDIATE KEYPAIR CREATED - Private key:");
    console.log(CA_intermediate_PrivateKeyPEM);
}



function CA_intermediate_loadCert(){
    CA_intermediate_cert_PEM = `-----BEGIN CERTIFICATE-----
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
-----END CERTIFICATE-----`;
    CA_intermediate_cert = pki.certificateFromPem(CA_intermediate_cert_PEM);

    CA_Store.addCertificate(CA_intermediate_cert);

    console.log("\nCA INTERMEDIATE CERTIFICATE LOADED");
}


function CA_intermediate_createCert(){
    // create the root CA's subject attributes as its issuer attributes
    CA_intermediate_cert_PEM = certHelper.createX590CertificateAuthorityCert(
        CA_intermediate_PrivateKeyPEM, //CA_KeyPair.privateKey.toString(),
        "Dev Switch 1 - INTERMEDIATE Cert", "Portugal", "(none)", "Lisbon", "Mojaloop", "vNextTeam", 5,
        CA_root_cert.subject.attributes
    );
    CA_intermediate_cert = forge.pki.certificateFromPem(CA_intermediate_cert_PEM);

    CA_intermediate_cert.setIssuer(CA_root_cert.subject.attributes);

    // sign the certificate with the root CA's private key
    CA_intermediate_cert.sign(CA_root_PrivateKey, forge.md.sha256.create());

    CA_Store.addCertificate(CA_intermediate_cert);

    console.log("\nCA INTERMEDIATE CERTIFICATE CREATED:");
    console.log(CA_intermediate_cert_PEM);
}

/**
 *
 *
 * CREATE DFSPA CERTIFICATE AND CSR
 *
 *
 * */

let DFSP_A_PrivateKeyPEM:string;
let DFSP_A_PrivateKey: forge.pki.rsa.PrivateKey;
let DFSP_A_PublicKey:  forge.pki.rsa.PublicKey;
let DFSP_A_CSR: forge.pki.CertificateRequest;
let DFSP_A_CSR_PEM: string;

function DFSP_A_loadKeys(){
    DFSP_A_PrivateKeyPEM = `-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC0gS19Qivc9NTv
EugrMR6M+qRwMzQ8TxG0VYOd7LqPTvkPxSr5QWPD6WXDpeMJSHispNwqAA3CEmC3
g14hfqaPx9ZgNKtBYY0ThxbNz2afzvanSHK7Gy7J17ZvHrMgs9XqQMIFZWQB1xeg
8QLa1TPGYX/55zZLYUzCMuUVPiors4mZjn3ndikI2nHLHuFkPtwjYNDzl9L0Hu6R
TAAfMrShDsTerKahtbRt7rVJHpI1UIu1Vuk2nN6XNz47CAjT3G0g8NgA8FeS5f9K
p8ZAVc1q2VgOkPAHmYHzuA1c/1nzxM+yAqWVQfD2slfZtdP/p3wfWsB3sCQHxObh
lV6Y4Z5dAgMBAAECggEAIWw15xaklpJDB02h7bV3qbUTU683gd9GMPUQnOJjnPuL
hI8GqQahmXoTHMoPov1nUthn5+MAqSnL/M73VA5mewMOv9ugxkdw3ufJoixAHWEu
LMVucRTUcg1eO28czfZeqrR4+JTQksKoHmXiGHEX2CjfkH9uf0Cx/Nd9sZRELLkP
IbFDpgcW27G3jFbdzOI3J1uIVW0O3xsbXbs5qKykZ8yhV0lPKqObCZ3GQ9+y4Qbj
P9z9d2eNWAf0wxtawaCxtXeMqddcM+jJsy+GpQoM5k8qJ78abaJHMag3ONHbn2gl
cxBz1FoCWnM+K0P679+Hu0eqhX26XkxUm3cyKrTzQQKBgQDdjOaAgMo8nhLD/R/s
9/mNFjVfeJ5TP8t3FSvEOPsHe5CF+AIUZFMTnjLl4h3B3rDRMdCAey1RmDdVCQZ3
O8T8/uZYWyO9GT0KTILuA543Sk3H/jmTxjsntwGhyZuBowLyqGNc6eOQuDe8MhQn
fjIsfrSCK8+ql90XjkV57GlQDQKBgQDQkmWCV4e5pMLCKT+cb9CFQY7FEEiqdmjj
6/bmD8/84Un86hzBHb7+SH26JR8B5g+CrYsQerEUi/TyAxt01zOH4jhbzBvsaAuG
mRF2Bfq8fkCT57namtfI4xaOqFuWTOw0xXvzRuRMsxBgaBDuDdegc0jbA+nCcykg
BZ6hnI+jkQKBgDXRdGzi3D29aHGTm53E3yoWqwB2HH+8j4Bt9CPGc7Rtn73rcRXj
CQtK8rJFK1Vc8zbeEvgi8+9OOqK9foSYUFHk2a+89AGLj/hgfa2z00s7EYnzh6kO
DnCnVA4pG01ye9TWcsyvREhzd5aP07WEQkvsu4yjd97I5TxDozzq4OpBAoGBAMjn
u4/J8JsJ8fBE+1kc+6bgdz2radOJK5AggzsokBfuiu5sNDZxCMC34yOjDjMuAFLI
B+RfyqMYDWHxTElH4gNKDS+fdGZL8o48c21UZSmcE2hlFclUzfZbiCbyVQZ6IizS
7YpxBwg6k9PJakVkYAfWBJ+zLUB43WxS/XJ+9H2BAoGBAKcSaRwLCEpKQ7MdJFjq
bODjAkAd+0WJAqxDrVfbv6HIOvLrIatVOk2RyhihQiB2NtkBry+NH6ubLe8EgxzO
93gg4RKTAL/a1PtPx/ysz0iHeJwiKt4TfJZGlitXBohB5LfZMmL/Y66+lKv4I4O3
mFnUirvlLei29FFKeoeNX5d/
-----END PRIVATE KEY-----
`;
    DFSP_A_PrivateKey = pki.privateKeyFromPem(DFSP_A_PrivateKeyPEM);
    DFSP_A_PublicKey = pki.setRsaPublicKey(DFSP_A_PrivateKey.n, DFSP_A_PrivateKey.e);
}

function DFSP_A_createKeys(){
    const DFSP_A_KeyPair = keyHelper.createRsaKeyPairSync(4096);
    DFSP_A_PrivateKeyPEM = DFSP_A_KeyPair.privateKey.toString();
    DFSP_A_PrivateKey = pki.privateKeyFromPem(DFSP_A_KeyPair.privateKey.toString());
    DFSP_A_PublicKey = pki.publicKeyFromPem(DFSP_A_KeyPair.publicKey.toString());

    console.log("\nDFSP A KEYPAIR CREATED - Private key:");
    console.log(DFSP_A_PrivateKeyPEM);
}

function DFSP_A_loadCsr(){
    DFSP_A_CSR_PEM=`-----BEGIN CERTIFICATE REQUEST-----
MIICVjCCAT4CAQAwETEPMA0GA1UEAwwGREZTUF9BMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB
CgKCAQEAtIEtfUIr3PTU7xLoKzEejPqkcDM0PE8RtFWDney6j075D8Uq+UFjw+llw6XjCUh4rKTc
KgANwhJgt4NeIX6mj8fWYDSrQWGNE4cWzc9mn872p0hyuxsuyde2bx6zILPV6kDCBWVkAdcXoPEC
2tUzxmF/+ec2S2FMwjLlFT4qK7OJmY5953YpCNpxyx7hZD7cI2DQ85fS9B7ukUwAHzK0oQ7E3qym
obW0be61SR6SNVCLtVbpNpzelzc+OwgI09xtIPDYAPBXkuX/SqfGQFXNatlYDpDwB5mB87gNXP9Z
88TPsgKllUHw9rJX2bXT/6d8H1rAd7AkB8Tm4ZVemOGeXQIDAQABoAAwDQYJKoZIhvcNAQELBQAD
ggEBAGfqAzu1TzsidaJiZUH6IFBOvcuxMmnfYDjimjt8NGvIzbW21pZWiHUSwIscn2a3tgF4Kiu8
QyD8iRmLKYpe5qC6hKfbr0JK6c/z+3r4PDpV7MJAWijEK/9OBaMjogUmqT7tX4FDyxgkh5K1vSYo
ONdsZCZYCWannXRRSp249O1ZWTPnO6dzet8P8r/w+mu2gTsxhM7Nvcl8aXgX0MctR0hNAFixupUG
lUHnAQpXHB6OKdyul/RPeeeblau2FB2g0YwoyQRBXDPMG+4qAfpd2FhohzLIVApfvikUdiJM02uH
Lcj8spjtXWxsYHiiPGKQw+NW/jOmhfInQxD1/ue30/0=
-----END CERTIFICATE REQUEST-----`;

}

function DFSP_A_createCsr(){
    DFSP_A_CSR = pki.createCertificationRequest();
    DFSP_A_CSR.publicKey = DFSP_A_PublicKey;
    DFSP_A_CSR.setSubject([{ name: "commonName", value: "DFSP A" }]);
    // set (optional) attributes
// DFSP_A_CSR.setExtensions([
//     {
//         name: "extensionRequest",
//         extensions: [
//             {
//                 name: "subjectAltName",
//                 altNames: [
//                     {
//                         // 2 is DNS type
//                         type: 2,
//                         value: "localhost",
//                     },
//                     {
//                         type: 2,
//                         value: "127.0.0.1",
//                     },
//                     {
//                         type: 2,
//                         value: "www.domain.net",
//                     },
//                 ],
//             },
//         ],
//     },
// ]);

    DFSP_A_CSR.sign(DFSP_A_PrivateKey, forge.md.sha256.create());

    // // verify certification request
    // const verified = DFSP_A_CSR.verify();

    DFSP_A_CSR_PEM = forge.pki.certificationRequestToPem(DFSP_A_CSR);

    // Convert CSR -> DER -> Base64
    //const DFSP_A_CSR_der = forge.asn1.toDer(forge.pki.certificationRequestToAsn1(DFSP_A_CSR));
    //const DFSP_A_CSR_der_base64 = Buffer.from(DFSP_A_CSR_der.data).toString("base64");

    console.log("DFSP_A_CSR:");
    console.log(DFSP_A_CSR_PEM);
}


/**
 *
 *
 * HUB SIGNS the DFSP_A's CSR and returns a signed cert
 *
 *
 * */

let DFSP_A_signed_cert:forge.pki.Certificate;
let DFSP_A_signed_cert_PEM:string;

function CA_signDfspCsr() {
    const RECEIVED_DFSP_A_CSR = forge.pki.certificationRequestFromPem(DFSP_A_CSR_PEM);

    console.log("Creating certificate from CSR...");
    const DFSP_A_signed_cert = forge.pki.createCertificate();
    DFSP_A_signed_cert.serialNumber =  crypto.randomUUID().replace(/-/g, "");

    DFSP_A_signed_cert.validity.notBefore = new Date();
    DFSP_A_signed_cert.validity.notAfter = new Date();
    DFSP_A_signed_cert.validity.notAfter.setFullYear(
        DFSP_A_signed_cert.validity.notBefore.getFullYear() + 1
    );

    // subject from CSR
    DFSP_A_signed_cert.setSubject(RECEIVED_DFSP_A_CSR.subject.attributes);
    // issuer from CA Intermediate
    DFSP_A_signed_cert.setIssuer(CA_intermediate_cert.subject.attributes);

    DFSP_A_signed_cert.setExtensions([
        {
            name: "basicConstraints", cA: false
        },
        {
            name: "keyUsage",
            keyCertSign: true,
            digitalSignature: true,
            nonRepudiation: true,
            keyEncipherment: true,
            dataEncipherment: true,
        },
        {
            name: "subjectAltName",
            altNames: [
                {
                    type: 6, // URI
                    value: "http://example.org/webid#me",
                },
            ],
        },
    ]);

    DFSP_A_signed_cert.publicKey = RECEIVED_DFSP_A_CSR.publicKey;
    DFSP_A_signed_cert.sign(CA_intermediate_PrivateKey, forge.md.sha256.create());

    DFSP_A_signed_cert_PEM = pki.certificateToPem(DFSP_A_signed_cert);

    console.log("DFSP_A_cert Certificate created:");
    console.log(DFSP_A_signed_cert_PEM);
}


/**
 *
 * MAIN
 *
 * */

(()=>{
    // CA_root_createKeys();
    CA_root_loadKeys();

    const fingerprint = pki.getPublicKeyFingerprint(CA_root_PublicKey!, {encoding: "hex", delimiter: "", type: "RSAPublicKey"});
    const fingerprint1 = pki.getPublicKeyFingerprint(CA_root_PublicKey!, {});
    const str1 = new Buffer(fingerprint1.data).toString("hex");

    const fingerprint2 = pki.getPublicKeyFingerprint(CA_root_PublicKey!, {type: "SubjectPublicKeyInfo"});
    const str2 = new Buffer(fingerprint2.data).toString("hex");

    // CA_root_createCert();
    CA_root_loadCert();

    CA_intermediate_loadKeys();
    // CA_intermediate_createKeys();
    CA_intermediate_loadCert();
    //CA_intermediate_createCert();

    // DFSP
    // DFSP_A_createKeys();
    DFSP_A_loadKeys();

    // CSR
    // DFSP_A_createCsr();
    DFSP_A_loadCsr();

    CA_signDfspCsr();

    try {
        if (CA_root_cert!.verify(CA_intermediate_cert!)) {
            console.log("Certification request (CSR) verified.");
        } else {
            throw new Error("Signature not verified.");
        }

        const certToVerify = pki.certificateFromPem(DFSP_A_signed_cert_PEM!);
        const verified = pki.verifyCertificateChain(CA_Store, [certToVerify]);
        if (verified) {
            console.log("Certificate got verified successfully.!");
        }
    }catch (e) {
        console.error(e);
    }



})();
