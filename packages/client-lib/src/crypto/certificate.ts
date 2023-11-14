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

import forge from "node-forge";
const pki = forge.pki;

export class CertificatesHelper{
    createX590Certificate(
        signingKeyPEM:string,
        commonName: string, country:string, state:string, locality:string, orgName:string, orgUnit:string,
        expirationYears:number
    ):string {
        const now = Date.now();
        const privateKey = pki.privateKeyFromPem(signingKeyPEM);
        const publicKey  = pki.setRsaPublicKey(privateKey.n, privateKey.e);

        // create a new certificate
        const cert = pki.createCertificate();

        // fill the required fields
        cert.publicKey = publicKey;
        cert.serialNumber = crypto.randomUUID().replace(/-/g, '');
        cert.validity.notBefore = new Date(now);
        cert.validity.notAfter = new Date(now);
        cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + expirationYears);

        // use your own attributes here, or supply a csr (check the docs)
        const attrs = [
            { name: "commonName", value: commonName },
            { name: "countryName", value: country },
            { shortName: "ST", value: state },
            { name: "localityName", value: locality },
            { name: "organizationName", value: orgName },
            { shortName: "OU", value: orgUnit }
        ];

        // here we set subject and issuer as the same one
        cert.setSubject(attrs);
        cert.setIssuer(attrs);

        cert.setExtensions([{
            name: "basicConstraints",
            cA: false,
        }, {
            name: "keyUsage",
            keyCertSign: true,
            digitalSignature: true,
            nonRepudiation: true,
            keyEncipherment: true,
            dataEncipherment: true
        }, {
            name: "extKeyUsage",
            serverAuth: true,
            clientAuth: true,
            codeSigning: true,
            emailProtection: true,
            timeStamping: true
        }, {
            name: "nsCertType",
            client: true,
            server: true,
            email: true,
            objsign: true,
        }, {
            name: "subjectKeyIdentifier"
        }]);

        // the actual certificate signing
        cert.sign(privateKey);

        // now convert the Forge certificate to PEM format
        const pem = pki.certificateToPem(cert);
        return pem;
    }

    createX590CertificateAuthorityCert(
        signingKeyPEM:string,
        commonName: string, country:string, state:string, locality:string, orgName:string, orgUnit:string,
        expirationYears:number
    ):string {
        const now = Date.now();
        const privateKey = pki.privateKeyFromPem(signingKeyPEM);
        const publicKey  = pki.setRsaPublicKey(privateKey.n, privateKey.e);

        // create a new certificate
        const cert = pki.createCertificate();

        // fill the required fields
        cert.publicKey = publicKey;
        cert.serialNumber = crypto.randomUUID().replace(/-/g, '');
        cert.validity.notBefore = new Date(now);
        cert.validity.notAfter = new Date(now);
        cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + expirationYears);

        // use your own attributes here, or supply a csr (check the docs)
        const attrs = [
            { name: "commonName", value: commonName },
            { name: "countryName", value: country },
            { shortName: "ST", value: state },
            { name: "localityName", value: locality },
            { name: "organizationName", value: orgName },
            { shortName: "OU", value: orgUnit }
        ];

        // here we set subject and issuer as the same one
        cert.setSubject(attrs);
        cert.setIssuer(attrs);

        cert.setExtensions([{
            name: "basicConstraints",
            cA: true,
        }, {
            name: "keyUsage",
            keyCertSign: true,
            digitalSignature: true,
            nonRepudiation: true,
            keyEncipherment: true,
            dataEncipherment: true
        }, {
            name: "extKeyUsage",
            serverAuth: true,
            clientAuth: true,
            codeSigning: true,
            emailProtection: true,
            timeStamping: true
        }, {
            name: "nsCertType",
            client: true,
            server: true,
            email: true,
            objsign: true,
            sslCA: true,
            emailCA: true,
            objCA: true
        }, {
            name: "subjectKeyIdentifier"
        }]);

        // the actual certificate signing
        cert.sign(privateKey);

        // now convert the Forge certificate to PEM format
        const pem = pki.certificateToPem(cert);

        return pem;
    }
}

