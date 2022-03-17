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
"use strict"

import nock from "nock";
import { URL } from "url";
import {LoginHelper} from "../../src/login_helper";
import {TokenHelper} from "../../src/token_helper";

// This token lasts for 100 years, so if the keys are ok, then should verify
const TEST_ACCESS_TOKEN = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6Inp1MGR4WXErTllrWHpPWmZsak5hU1F3MEVXMVQ1KzJ1ZHByQy9Vekt4aGc9In0.eyJ0ZXN0T2JqIjoicGVkcm8xIiwiaWF0IjoxNjQ3NDUyMDM5LCJleHAiOjQ4MDEwNTIwMzksImF1ZCI6InZOZXh0IHBsYXRmb3JtIiwiaXNzIjoidk5leHQgU2VjdXJpdHkgQkMgLSBBdXRob3JpemF0aW9uIFN2YyIsInN1YiI6InVzZXIiLCJqdGkiOiJ6dTBkeFlxK05Za1h6T1pmbGpOYVNRdzBFVzFUNSsydWRwckMvVXpLeGhnPSJ9.d_BXmofxhYr_WbxAte8RgbCQEZcMKiUeEeOLJRR2QaFjg7Wbz_QlgpZzRphFZWQYACIXrrpw4C7xg1NxA4fvokw6DrI41MTzOVd2dk79Le1hK1JotPMpscFiUCOED8Vurv_s-AnxoeHWv5RdB00-nlSB1HkFmArT3TOAVdsOMaiTGhBjI0phhcVo0UuY6f9qYpUcS-rYVW7zf0pAWDhYg_rfX6-ntHxpc6wuq8fQDJs-I-nRzdlS1yrBp9cWN5cDC9qAxXLC4f8ZVl5PSZl-V07MBivPk1zUXm1j62e5tF2MIVyoRSKf2h90J2hAdR-4MAb9wP5_HOhUw12w4YQyAQ";

const ISSUER_NAME = "vNext Security BC - Authorization Svc";
const FIX_AUDIENCE_CHANGE = "vNext platform";
const LOGIN_USERNAME = "user";
const LOGIN_PASSWORD = "superPass2";
const LOGIN_WRONG_PASSWORD = "WrongPass";
const LOGIN_BASE_URL = "http://localhost:3000";
const JWKS_URL = "http://localhost:3000/.well-known/jwks.json";

describe('client-lib ConfigurationSet tests', () => {
    beforeAll(async () => {
        const jwksUrl = new URL(JWKS_URL);
        nock(jwksUrl.origin).persist().get(jwksUrl.pathname).reply(200, {
            "isMock": true,
            "keys": [{
                "alg": "RS256",
                "e": "AQAB",
                "kid": "zu0dxYq+NYkXzOZfljNaSQw0EW1T5+2udprC/UzKxhg=",
                "kty": "RSA",
                "n": "ALvyNb619slh5kS/YkvRUEiYdru8Jlf7js+eNFe/L6OgOmxsYyqZYMRnZUYSrRQpBNardxOC/+uw1Nh3V1vyH6cj5SF" +
                        "Ivj/nS9EYY0p8QxRt+9Sfjd4qtPWVxmfVuYslVPW/RYtJ2oR5DhY1x0+pqh54mJkqTqPFB6rXd/vq/z5NehInefBsLi4DG" +
                        "+VTJg/j3b8Ree7OiysnTRePUyZQKH0OOzRIVtQvLTiYe964uOdhqQb/J+pQGawdClqzjd1s78O2Vm+CLgnNpJbYmbOvAtl" +
                        "ERK1Gn8rEGHO5VgwyDeIrBzld/yVVyGQ85WSI7JzUwlBr5NA9qaEyINCo6/4apGk=",
                "use": "sig"
            }]
        });

        nock(LOGIN_BASE_URL).persist().post("/login").reply((uri:string, requestBody:any) => {
            if(requestBody.username === LOGIN_USERNAME && requestBody.password === LOGIN_PASSWORD){
                return [200,
                    {
                        "isMock": true,
                        "token_type": "bearer",
                        "access_token": TEST_ACCESS_TOKEN,
                        "expires_in": 3600,
                        "refresh_token": null,
                        "refresh_token_expires_in": 0
                    },
                    //{ header: 'value' }, // optional headers
                ];
            }else{
                return [ 404, {}, {}];
            }
        });

    })

    afterAll(async () => {
        // Cleanup
    })

    test("Login and verify token", async () => {
        const loginHelper = new LoginHelper(LOGIN_BASE_URL);
        await loginHelper.init();

        const accessToken = await loginHelper.loginUser(LOGIN_USERNAME, LOGIN_PASSWORD);

        expect(accessToken).not.toBeNull();

        const tokenHelper = new TokenHelper(ISSUER_NAME, JWKS_URL);
        await tokenHelper.init();

        const verified = await tokenHelper.verifyToken(accessToken!.accessToken, FIX_AUDIENCE_CHANGE);
        expect(verified).toBe(true);

        console.log(verified)

    });

    test("Login with wrong pass", async () => {
        const loginHelper = new LoginHelper(LOGIN_BASE_URL);
        await loginHelper.init();

        const accessToken = await loginHelper.loginUser(LOGIN_USERNAME, LOGIN_WRONG_PASSWORD);
        expect(accessToken).toBeNull();
    });

    test("decode token", async () => {
        const accessToken = TEST_ACCESS_TOKEN;

        const tokenHelper = new TokenHelper(ISSUER_NAME, "http://not.used/");
        // not intialised to avoid calling jwks.json url
        const payload = tokenHelper.decodeToken(accessToken);
        expect(payload).not.toBeNull();
        expect(payload.testObj).toEqual("pedro1");

    });

})
