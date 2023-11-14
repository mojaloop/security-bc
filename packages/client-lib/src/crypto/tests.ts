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
//
// "use strict";
// import crypto from "crypto";
// import forge from "node-forge";
// const pki = forge.pki;
//
// import {CryptoKeyManagementHelper} from "./keys";
// import {CertificatesHelper} from "./certificate";
// import * as fs from "fs";
//
//
// const certHelper = new CertificatesHelper();
// const keyHelper = new CryptoKeyManagementHelper();
//
// /**
//  *
//  * CERTIFICATE AUTHORITY Vars and functions
//  *
//  *
//  * */
//
// let CA_PrivateKeyPEM:string;
// let CA_PrivateKey: forge.pki.rsa.PrivateKey;
// let CA_PublicKey:  forge.pki.rsa.PublicKey;
// let CA_cert_PEM:string;
// let CA_cert:forge.pki.Certificate;
//
// function CA_loadKeys(){
//     CA_PrivateKeyPEM = `-----BEGIN PRIVATE KEY-----
// MIIJQgIBADANBgkqhkiG9w0BAQEFAASCCSwwggkoAgEAAoICAQDe4mE4etrNJ4RI
// xmeEvRfGxfdc2S/WbDXAHkVcezyaLE7dMq+bTPPeFTuttNZ1cXNVHSWRds9BfgoU
// At6Gtrq93oZiVT+V+XrF9cyy6bRI5MF5nDoa2uOJtEfu7pndn+anlkMaC+BcfXjc
// 83NCY33kLqIgNlv1A2XAfQ8zjIR3g8utv72NhxoOUwO/T+l0uM7JRnhP+FtZBLWS
// IDEoC5RG1WbxsANPX3TNlItmzA7dCMnZln23M0zVWVjbgM73GwqrjiYBp6SeD3j7
// wIVenRzT9yzLQfw/LZokC8liEREN7q3Br6Ht+JPY893ExDRk2XqL8W5HGB0ipTch
// SD1PIm2X1wulK9+h5Ez3T+YPiqDyPUQYB11/HunZ/UPx6dW44D2LqotN6K38nExj
// Ps9XHw1HO3fjF2Mj7S5hNoQhX42WY9Pjg7FBW2vbS1hiyq3pbhQqo5bmRvqvCxBQ
// S9Iq1+KZXHHATNhX9750NdxnMHYNxpdH1UzJiyNazaqnBmbLfwSCaPY4kT0P0d71
// LLFWv+b/w43DiP4VMD9nkep47OMhj9MUAQ7+5tyZ4+x25hlGIP2J9dUmjuhYBlit
// mwe2zTp4GRkQxaXZN53KUvlSlbf1B+xUOO9s2nxtvCNq9+Y/KFnchcyCG5BAaQg8
// tQfV7MmQyolFW2ewQInCWCP59mIApQIDAQABAoICAAhKKC6HFzs5JIjmZDRCKi+4
// 7jXUWBykAq3GEnNZnAvp6Pb+KxzeFFXmuUUBLFbK5Oy9/Ec4QYYgj3RmFOuywShN
// rfbbT9WepUvWlAn1ekCZzX5d6qVUDdFx1JkU48Ej8Nq70nwWA/68pfGl1lwaQjTp
// 7RrAmtP2j+LEY/vZVpXxX3JzZrPsWfI9cS685KR0OTCwP8pNpOwfKjeondts7tNh
// nYYQs1bQ6JG63CJzJXxgFs3SdJOLQ2jN/WmQlWIIbfGqhExcdVlxnuDSLMOzmT5i
// +5YFusGIyypbC97rXpSDk4/YHfAxZiJUE6P9XiuAEThCPwVC5taCiZXhz3HxiFzj
// GMo73WAvjoZaFoOlxAhanoHdmI57dv3dzgeGwHkdMl0bkccgYWOkT9w1es4tdnbk
// ikWIrg1dZabgMuLW+0BY/M8rX8akkB3/2Sb95sUqyNqrs/1NVftg3gmqUiLt5IO0
// tpnM4H26Hx8czrzlPKpQdh5nidl7pSwUM4lWb6K3w+gk92M/QKKE5Upana5lgR9d
// BJ0xbrfhv15v8LYF84JgC4GpjlDiMLBVAKb4K3ZjMm8OInb+dNj0huqlKRUVHN2O
// K2U+IDzfzaQIhop7cWj0/azr3IkpxPtn0akPiuFmPHnnhIoZBD/8X+yAP+zi3nLK
// PRqeDMQjv4eEO232IUCjAoIBAQD4kJK0kUK75giFHAB1a0uFVGw/z4bzGGy81xEi
// 4+F6sXfpAG8aQvJzJIf7LsYpKe9KCC73gX6ljsuHI/EIeAxzzopx1l3P2C46CMX1
// EUBpRuRJVvc0eXnguBQTtnMn0ix36+E+CwYqXH5+aTYzQU33OMMsdSNGwF94JfTN
// X0eGF12w3HJOURB4CCL7+g8dyhmZbDN6Bof+5SfRas0R0Jw+gKtEvnCTCwmI3Rbe
// qKYacjyQHX9PGxORU2Ad188hHPLtria38oSHNczYZGq0YoBywdoRqG5Bf3VBZtBi
// 6BLQU5wyqBltFXWSAhsNGxEsoxiQtVIbjB5nQdGWDoI2/AUbAoIBAQDljSeB5vf6
// Ky7LHlE4N3oDnyujK94EfRvgz3ZbSyCU6oQJE7K7P9G9qWdHuMIVl0SDTLjohhxv
// yz8o3OcZRFh/eC1Oq62UNtOrDXaZdQ7wvV49Z0Pzi3pJwZKQqmvNvWRqB+RCSVgK
// GncdmmWpfoY+IDMXMpl0XfgyUphIyTgaDIDJlYZWrdilUe/5kuMarinWvj0ixg0r
// jL84eZVqbc5o6Z/Qo7Crj1fHgCzz6Y5dUGiyYk51VDwReEmlwXHrB/jneKEcZ/mT
// NR9VBvZ6/2W7YZ/1cnj5EkW/J21zwig8T4tdwXZvHNi+JHHFtRc3omIZLRRebrDU
// bp1XHvPG1S0/AoIBAQD3ndZ4CSlo09zy9ZVDY9LFDPgVjWCLdW6FpN5OWqN5vaeN
// tz/28nBi4iaQxOTlhv/5STO4nwkSVrFMfDKW1DjbeQsUIpAsCNjsOWczHq+C8Ptk
// UD1NyiHvCpH9nUkUh1yDTrmBPCw1MRVWSuuSneDUgnh0JnEw/11b7Lv1h5BR9Z8B
// HGrGuBzm5nwrds1uSLG91DtnuW/rLk+/YFzP/XhZD4cOoYS2B03FSTKKN4nZWKoa
// izgTDw8sO9nJgP63pwYeXtn1b6Q0qhTaERb3ghUhvRnHc3n6x8WAlLLNhRGQ9Wnq
// UOmbcMBB5tUZ9jfitss3BVq5VJnJFZl7mhKAQgm3AoIBADlsB/f82QdhigERgmu3
// pPQG+xmEPbONwE2KWCcaMfpOd9z1an5gxozVNZrBYvuXrXHS3WZ9NdvZUeFc8Qpn
// CGRKobrOQ0uSM3zUj1hv6d7a4BooHN1thJeyroE1wGXk/Jtxge36/uT4Hdfv6YJu
// vhIIZ/9jjvOHFjEwbBu5Cimp+wVyO/qu3kTsrEUYM2tXKewoBo8OT/kW6jasY24O
// LdYcqve8GtOvtduX+qbBQ/WfybDl2o6LFcOg/XtTWrXadq8gg9zhPZNPdJkGdt3p
// yX8IOsVhb1WO9peMu1p7tSjxFQHNBV1iL+3QnA1C8Z3fJv75QeEle2KIkR9cBMs2
// RG0CggEASRMlEfIBvUEKNNCGKhph7xNRWeDnI70by8Oxbl/uXLscrR5OhQYc4R8O
// 3MxPD0mvtzqVAMR1hkjIfORDSHSpEwHx5s18nCHjp/qomp2vl9Fft5sgaq7ORhjM
// pRzYFEV8UI8Wuv/17nLTeckRwnoxgS1Y/ZWJ1VPKq5XTo6rvcq6g4ktyQSe6nRNT
// eNYyNv6edK5LWzzuVjqZwFYqtRxuOCRLesvamaT/G/fkR6OrG0G9zIMEWNQnoQFm
// jqVt5cNfouZUqeRoMhE1+gwpK1p5/fAReLECMZqUPsiXb8w2TuRleyyR04CirK5/
// FczA5F9+y3NWFVxtKJYeaLfOzg4miA==
// -----END PRIVATE KEY-----`;
//     CA_PrivateKey = pki.privateKeyFromPem(CA_PrivateKeyPEM);
//     CA_PublicKey = pki.setRsaPublicKey(CA_PrivateKey.n, CA_PrivateKey.e);
// }
//
// function CA_createKeys(){
//     const CA_KeyPair = keyHelper.createRsaKeyPairSync(4096);
//     CA_PrivateKeyPEM = CA_KeyPair.privateKey.toString();
//     CA_PrivateKey = pki.privateKeyFromPem(CA_KeyPair.privateKey.toString());
//     CA_PublicKey = pki.publicKeyFromPem(CA_KeyPair.publicKey.toString());
//
//     console.log("\nCA KEYPAIR CREATED - Private key:");
//     console.log(CA_PrivateKeyPEM);
// }
//
// function CA_loadRootCert(){
//     CA_cert_PEM = `-----BEGIN CERTIFICATE-----
// MIIFRDCCAyygAwIBAgIEZVKMkTANBgkqhkiG9w0BAQsFADBTMSIwIAYJKoZIhvcN
// AQkBFhNwZWRyb0BjeWJlcmJvbmVzLmlvMREwDwYDVQQLDAhNeSBDQSBPVTEaMBgG
// A1UEAwwRTXkgQ0EgQ29tbW9uIE5hbWUwHhcNMjMxMTEzMjA1MjMzWhcNMzMxMTEz
// MjA1MjMzWjBTMSIwIAYJKoZIhvcNAQkBFhNwZWRyb0BjeWJlcmJvbmVzLmlvMREw
// DwYDVQQLDAhNeSBDQSBPVTEaMBgGA1UEAwwRTXkgQ0EgQ29tbW9uIE5hbWUwggIi
// MA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDe4mE4etrNJ4RIxmeEvRfGxfdc
// 2S/WbDXAHkVcezyaLE7dMq+bTPPeFTuttNZ1cXNVHSWRds9BfgoUAt6Gtrq93oZi
// VT+V+XrF9cyy6bRI5MF5nDoa2uOJtEfu7pndn+anlkMaC+BcfXjc83NCY33kLqIg
// Nlv1A2XAfQ8zjIR3g8utv72NhxoOUwO/T+l0uM7JRnhP+FtZBLWSIDEoC5RG1Wbx
// sANPX3TNlItmzA7dCMnZln23M0zVWVjbgM73GwqrjiYBp6SeD3j7wIVenRzT9yzL
// Qfw/LZokC8liEREN7q3Br6Ht+JPY893ExDRk2XqL8W5HGB0ipTchSD1PIm2X1wul
// K9+h5Ez3T+YPiqDyPUQYB11/HunZ/UPx6dW44D2LqotN6K38nExjPs9XHw1HO3fj
// F2Mj7S5hNoQhX42WY9Pjg7FBW2vbS1hiyq3pbhQqo5bmRvqvCxBQS9Iq1+KZXHHA
// TNhX9750NdxnMHYNxpdH1UzJiyNazaqnBmbLfwSCaPY4kT0P0d71LLFWv+b/w43D
// iP4VMD9nkep47OMhj9MUAQ7+5tyZ4+x25hlGIP2J9dUmjuhYBlitmwe2zTp4GRkQ
// xaXZN53KUvlSlbf1B+xUOO9s2nxtvCNq9+Y/KFnchcyCG5BAaQg8tQfV7MmQyolF
// W2ewQInCWCP59mIApQIDAQABoyAwHjAPBgNVHRMBAf8EBTADAQH/MAsGA1UdDwQE
// AwICBDANBgkqhkiG9w0BAQsFAAOCAgEAozgUZavkRzZji+k9xWIG1oT9z4eHOv7r
// u+7hPS2Odx3RKKnOQzR7og+AbcgYD+KFG5fx3Kvg3GahM61arZE33IoeJluyrvn1
// 9EO/LeJSVPP8xO1WNBIWprYD914lBJ62kICnHA5UdYRzIpy4BlLB+g3HgbyJiFpz
// socuoHcIhSfhJ+OHzP9gkG7SQvpCGnnfCtPOykPBwfa3DxCVOeZIA4wK+eYJ1xIt
// Zsa7BfCbZ9acmrpG+uIrsc62ly2iQafe98Zf88xpdkiFHDDqT5NIxvuYKULEv+eH
// bPAmx6tXc472E4HvKxhAG/U6jhjMYF4f8bmqI5mRjUBhiaA5f6QSOuXFFL0pGeYR
// +P6bR8iiCbliapScRs51RrGV/e/V8kTAIw5BgcerULRoFuaAhCdZqLhHDXg/ZcMl
// mpeJs6oeiVSEIEVdf6YxkNhYvsTVkPxzHxU+Dy9Y03+Tvit2IwA8fdkwoKjdUf6o
// xAOwD1ay0wYOmE2BGhRoAQir0dncYy+pbb87LGE9Cgx2tNjg+ou7y6EhduyeaZ8T
// 1JwEoB5anUNubBXa2pxd2ySH09WsLDpGKSXTCGjd2oD7YgxW1laQe09yisGcVMZS
// nmEZ65Esvo5f0zbsiOOy/UnoWuaSszVppul1q++3eb3u6gIubHoQqjdtwGkPxGBi
// TMravPsDeBQ=
// -----END CERTIFICATE-----`;
//     CA_cert = pki.certificateFromPem(CA_cert_PEM);
// }
//
// function CA_createRootCert(){
//     CA_cert_PEM = certHelper.createX590CertificateAuthorityCert(
//         CA_PrivateKeyPEM, //CA_KeyPair.privateKey.toString(),
//         "Dev Switch 1", "Portugal", "(none)", "Lisbon", "Mojaloop", "vNextTeam", 10
//     );
//     CA_cert = forge.pki.certificateFromPem(CA_cert_PEM);
//
//     console.log("\nCA CERTIFICATE CREATED:");
//     console.log(CA_cert_PEM);
// }
//
//
// /**
//  *
//  *
//  * CREATE DFSPA CERTIFICATE AND CSR
//  *
//  *
//  * */
//
// let DFSP_A_PrivateKeyPEM:string;
// let DFSP_A_PrivateKey: forge.pki.rsa.PrivateKey;
// let DFSP_A_PublicKey:  forge.pki.rsa.PublicKey;
// let DFSP_A_CSR: forge.pki.CertificateRequest;
// let DFSP_A_CSR_PEM: string;
//
// function DFSP_A_loadKeys(){
//     DFSP_A_PrivateKeyPEM = ``;
//     DFSP_A_PrivateKey = pki.privateKeyFromPem(DFSP_A_PrivateKeyPEM);
//     DFSP_A_PublicKey = pki.setRsaPublicKey(DFSP_A_PrivateKey.n, DFSP_A_PrivateKey.e);
// }
//
// function DFSP_A_createKeys(){
//     const DFSP_A_KeyPair = keyHelper.createRsaKeyPairSync(4096);
//     DFSP_A_PrivateKeyPEM = DFSP_A_KeyPair.privateKey.toString();
//     DFSP_A_PrivateKey = pki.privateKeyFromPem(DFSP_A_KeyPair.privateKey.toString());
//     DFSP_A_PublicKey = pki.publicKeyFromPem(DFSP_A_KeyPair.publicKey.toString());
//
//     console.log("\nDFSP A KEYPAIR CREATED - Private key:");
//     console.log(DFSP_A_PrivateKeyPEM);
// }
//
// function DFSP_A_createCsr(){
//     DFSP_A_CSR = pki.createCertificationRequest();
//     DFSP_A_CSR.publicKey = DFSP_A_PublicKey;
//     DFSP_A_CSR.setSubject([{ name: "commonName", value: "DFSP A" }]);
//     // set (optional) attributes
// // DFSP_A_CSR.setExtensions([
// //     {
// //         name: "extensionRequest",
// //         extensions: [
// //             {
// //                 name: "subjectAltName",
// //                 altNames: [
// //                     {
// //                         // 2 is DNS type
// //                         type: 2,
// //                         value: "localhost",
// //                     },
// //                     {
// //                         type: 2,
// //                         value: "127.0.0.1",
// //                     },
// //                     {
// //                         type: 2,
// //                         value: "www.domain.net",
// //                     },
// //                 ],
// //             },
// //         ],
// //     },
// // ]);
//
//     DFSP_A_CSR.sign(DFSP_A_PrivateKey, forge.md.sha256.create());
//
//     DFSP_A_CSR_PEM = forge.pki.certificationRequestToPem(DFSP_A_CSR);
//
//     // Convert CSR -> DER -> Base64
//     //const DFSP_A_CSR_der = forge.asn1.toDer(forge.pki.certificationRequestToAsn1(DFSP_A_CSR));
//     //const DFSP_A_CSR_der_base64 = Buffer.from(DFSP_A_CSR_der.data).toString("base64");
//
//     console.log("DFSP_A_CSR:");
//     console.log(DFSP_A_CSR_PEM);
// }
//
//
// /**
//  *
//  *
//  * HUB SIGNS the DFSP_A's CSR and returns a signed cert
//  *
//  *
//  * */
//
// function CA_signDfspCsr(csrPem:string): forge.pki.Certificate{
//     const RECEIVED_DFSP_A_CSR = forge.pki.certificationRequestFromPem(csrPem);
//
//     if (RECEIVED_DFSP_A_CSR.verify(CA_cert)) {
//         console.log("Certification request (CSR) verified.");
//     } else {
//         throw new Error("Signature not verified.");
//     }
//
// }
//
// const RECEIVED_DFSP_A_CSR = forge.pki.certificationRequestFromPem(DFSP_A_CSR_PEM);
//
//
// console.log("Creating certificate...");
// const DFSP_A_cert = forge.pki.createCertificate();
// DFSP_A_cert.serialNumber = "02";
//
// DFSP_A_cert.validity.notBefore = new Date();
// DFSP_A_cert.validity.notAfter = new Date();
// DFSP_A_cert.validity.notAfter.setFullYear(
//     DFSP_A_cert.validity.notBefore.getFullYear() + 1
// );
//
// // subject from CSR
// DFSP_A_cert.setSubject(RECEIVED_DFSP_A_CSR.subject.attributes);
// // issuer from CA
// DFSP_A_cert.setIssuer(CA_cert.subject.attributes);
//
// DFSP_A_cert.setExtensions([
//     {
//         name: "basicConstraints",
//         cA: false,
//     },
//     {
//         name: "keyUsage",
//         keyCertSign: true,
//         digitalSignature: true,
//         nonRepudiation: true,
//         keyEncipherment: true,
//         dataEncipherment: true,
//     },
//     {
//         name: "subjectAltName",
//         altNames: [
//             {
//                 type: 6, // URI
//                 value: "http://example.org/webid#me",
//             },
//         ],
//     },
// ]);
//
// DFSP_A_cert.publicKey = DFSP_A_CSR.publicKey;
// DFSP_A_cert.sign(CA_PrivateKey);
//
// const DFSP_A_signed_cert_PEM = pki.certificateToPem(DFSP_A_cert);
//
// console.log("DFSP_A_cert Certificate created:");
// console.log(DFSP_A_signed_cert_PEM);
//
//
// /**
//  *
//  *
//  * VERIFY
//  *
//  *
//  * */
//
//
// let caCert;
// let caStore;
//
// try {
//     caStore = pki.createCaStore([CA_cert]);
// } catch (e) {
//     console.log("Failed to load CA certificate (" + e + ")");
//     process.exit();
// }
//
// try {
//     const certToVerify = pki.certificateFromPem(DFSP_A_signed_cert_PEM);
//     const verified = pki.verifyCertificateChain(caStore, [certToVerify]);
//     if (verified) {
//         console.log("Certificate got verified successfully.!");
//     }
//     process.exit();
// } catch (e:any) {
//     console.log("Failed to verify certificate (" + (e.message || e) + ")");
//     process.exit();
// }
//
//
// /**
//  *
//  * MAIN
//  *
//  * */
//
// (()=>{
//     //CA_createKeys();
//     CA_loadKeys();
//     //CA_createRootCert();
//     CA_loadRootCert();
//
//
//     DFSP_A_createKeys();
//     DFSP_A_loadKeys();
//
// })();
