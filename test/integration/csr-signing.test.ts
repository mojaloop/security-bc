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

 * ThitsaWorks
 - Si Thu Myo <sithu.myo@thitsaworks.com>
 --------------
 ******/

"use strict";

import { pki } from "node-forge";

import {
    AuthenticatedHttpRequester,
    KeyMgmtHttpClient,
} from "@mojaloop/security-bc-client-lib";
import { ConsoleLogger } from "@mojaloop/logging-bc-public-types-lib";

const AUTH_N_SVC_BASEURL = "http://localhost:3201";

const AUTH_Z_SVC_BASE_URL = "http://localhost:3202";

const APP_CLIENT_ID = "security-bc-key-management-svc";
const APP_CLIENT_SECRET = "superServiceSecret";

const logger = new ConsoleLogger();

// DFSP_A_CSR_PEM is taken from packages/client-lib/src/crypto/tests.ts
const DFSP_A_CSR_PEM = `-----BEGIN CERTIFICATE REQUEST-----
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

describe('key-management-client-lib tests', () => {
    let authRequester: AuthenticatedHttpRequester;
    let keyMgmtHttpClient: KeyMgmtHttpClient;
    beforeAll(() => {
        authRequester = new AuthenticatedHttpRequester(logger, AUTH_N_SVC_BASEURL + "/token");
        authRequester.setAppCredentials(APP_CLIENT_ID, APP_CLIENT_SECRET);
        keyMgmtHttpClient = new KeyMgmtHttpClient('http://localhost:3204', authRequester);

    })
    test("Obtain Hub CA Public Cert", async () => {
        const hubCAPubCert = await keyMgmtHttpClient.getHubCAPubCert();
        expect(hubCAPubCert).toBeDefined();
        expect(hubCAPubCert).toContain('-----BEGIN CERTIFICATE-----');

        const cert = pki.certificateFromPem(hubCAPubCert);
        expect(cert).toBeDefined();
        expect(cert.subject.getField('CN').value).toBe('vNextHub CA');
        expect(cert.issuer.getField('CN').value).toBe('vNextHub CA');
        expect(cert.issuer.getField('O').value).toBe('Mojaloop');
    })

    test("Sign CSR", async () => {
        expect(DFSP_A_CSR_PEM).toContain('-----BEGIN CERTIFICATE REQUEST-----');

        const signedCertStr = await keyMgmtHttpClient.uploadCSR('dfsp_a', DFSP_A_CSR_PEM);
        expect(signedCertStr).toBeDefined();
        expect(signedCertStr).toContain('-----BEGIN CERTIFICATE-----');

        const cert = pki.certificateFromPem(signedCertStr);
        expect(cert).toBeDefined();
        expect(cert.subject.getField('CN').value).toBe('DFSP_A'); // The CN is the same as the CSR
        expect(cert.issuer.getField('CN').value).toBe('vNextHub CA'); // The issuer is the Hub CA
        expect(cert.issuer.getField('O').value).toBe('Mojaloop'); // The issuer is the Hub CA

        // Verify the signature with the CA public
        const hubCAPubCert = await keyMgmtHttpClient.getHubCAPubCert();
        const caCert = pki.certificateFromPem(hubCAPubCert);
        const verified = caCert.verify(cert);
        expect(verified).toBe(true);

        // Verify the signature with the API
        const verificationResult = await keyMgmtHttpClient.verifyCert(signedCertStr);
        expect(verificationResult).toEqual({ verified: true });
    });

});
