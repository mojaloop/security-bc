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

// import * as fetchMock from "fetch-mock-jest";
// import {MockRequest, MockResponseFunction} from "fetch-mock/types/index";
//

import nock from "nock";

import { URL } from "url";
import {LoginHelper, TokenHelper} from "../../dist/";
import {ConsoleLogger, ILogger} from "@mojaloop/logging-bc-public-types-lib";

const LOGIN_SVC_BASE_URL = "http://localhost:3201";
const TOKEN_URL = `${LOGIN_SVC_BASE_URL}/token`;
const JWKS_URL = `${LOGIN_SVC_BASE_URL}/.well-known/jwks.json`;

// This token lasts for 100 years, so if the keys are ok, then should verify
const TEST_USER_ACCESS_TOKEN = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6Inp1MGR4WXErTllrWHpPWmZsak5hU1F3MEVXMVQ1KzJ1ZHByQy9Vekt4aGc9In0.eyJ0ZXN0T2JqIjoicGVkcm8xIiwiaWF0IjoxNjQ3NDUyMDM5LCJleHAiOjQ4MDEwNTIwMzksImF1ZCI6InZOZXh0IHBsYXRmb3JtIiwiaXNzIjoidk5leHQgU2VjdXJpdHkgQkMgLSBBdXRob3JpemF0aW9uIFN2YyIsInN1YiI6InVzZXIiLCJqdGkiOiJ6dTBkeFlxK05Za1h6T1pmbGpOYVNRdzBFVzFUNSsydWRwckMvVXpLeGhnPSJ9.d_BXmofxhYr_WbxAte8RgbCQEZcMKiUeEeOLJRR2QaFjg7Wbz_QlgpZzRphFZWQYACIXrrpw4C7xg1NxA4fvokw6DrI41MTzOVd2dk79Le1hK1JotPMpscFiUCOED8Vurv_s-AnxoeHWv5RdB00-nlSB1HkFmArT3TOAVdsOMaiTGhBjI0phhcVo0UuY6f9qYpUcS-rYVW7zf0pAWDhYg_rfX6-ntHxpc6wuq8fQDJs-I-nRzdlS1yrBp9cWN5cDC9qAxXLC4f8ZVl5PSZl-V07MBivPk1zUXm1j62e5tF2MIVyoRSKf2h90J2hAdR-4MAb9wP5_HOhUw12w4YQyAQ";

// these must match the token
const ISSUER_NAME = "vNext Security BC - Authorization Svc";
const TEST_AUDIENCE = "vNext platform";

const APP_CLIENT_ID = "user";
const APP_CLIENT_SECRET = "participants-bc-participants-svc";

const CLIENT_ID = "security-bc-ui";
const LOGIN_USERNAME = "user";
const LOGIN_PASSWORD = "superPass";
const LOGIN_WRONG_PASSWORD = "WrongPass";

/****/

const logger: ILogger = new ConsoleLogger();

let jwksUrlNockScope: nock.Scope;
let loginNockScope: nock.Scope;

describe('authentication-client-lib tests', () => {
    beforeAll(async () => {
        const jwksUrl = new URL(JWKS_URL);
        jwksUrlNockScope = nock(jwksUrl.origin).persist().get(jwksUrl.pathname).reply(200, {
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

        /*fetchMock.post(TOKEN_URL, (url: string, opts: MockRequest)=>{
            if(!opts.body) return 403;
            const body = JSON.parse(opts.body.toString());
            if (!body) return 403;

            if (body.grant_type.toUpperCase()==="password".toUpperCase()) {
                if (body.client_id===CLIENT_ID && body.username===LOGIN_USERNAME && body.password===LOGIN_PASSWORD) {
                    return [200,
                        {
                            "isMock": true,
                            "token_type": "bearer",
                            "access_token": TEST_USER_ACCESS_TOKEN,
                            "expires_in": 3600,
                            "refresh_token": null,
                            "refresh_token_expires_in": 0
                        },//{ header: 'value' }, // optional headers
                    ];
                } else {
                    return [403, {}, {}];
                }
            } else if (body.grant_type.toUpperCase()==="client_credentials".toUpperCase()) {
                if (body.client_id===APP_CLIENT_ID && body.client_secret===APP_CLIENT_SECRET) {
                    return [200,
                        {
                            "isMock": true,
                            "token_type": "bearer",
                            "access_token": TEST_USER_ACCESS_TOKEN,
                            "expires_in": 3600,
                            "refresh_token": null,
                            "refresh_token_expires_in": 0
                        },//{ header: 'value' }, // optional headers
                    ];
                } else {
                    return [403, {}, {}];
                }
            } else {
                return [403, {}, {}];
            }
        });*/

        loginNockScope = nock(LOGIN_SVC_BASE_URL).persist().post("/token").reply((uri:string, requestBody:any) => {
            if(requestBody.grant_type.toUpperCase() === "password".toUpperCase()){
                if(requestBody.client_id===CLIENT_ID && requestBody.username === LOGIN_USERNAME && requestBody.password === LOGIN_PASSWORD){
                    return [200,
                        {
                            "isMock": true,
                            "token_type": "bearer",
                            "access_token": TEST_USER_ACCESS_TOKEN,
                            "expires_in": 3600,
                            "refresh_token": null,
                            "refresh_token_expires_in": 0
                        },//{ header: 'value' }, // optional headers
                    ];
                }else{
                    return [ 403, {}, {}];
                }
            }else if(requestBody.grant_type.toUpperCase() ==="client_credentials".toUpperCase()){
                if (requestBody.client_id===APP_CLIENT_ID && requestBody.client_secret===APP_CLIENT_SECRET) {
                    return [200,
                        {
                            "isMock": true,
                            "token_type": "bearer",
                            "access_token": TEST_USER_ACCESS_TOKEN,
                            "expires_in": 3600,
                            "refresh_token": null,
                            "refresh_token_expires_in": 0
                        },//{ header: 'value' }, // optional headers
                    ];
                } else {
                    return [403, {}, {}];
                }
            }else{
                return [403, {}, {}];
            }
        });
    })

    afterAll(async () => {
        // Cleanup
    })

    // NOTE: nock does work with fetch, which is what the new LoginHelper and AuthHtpRequester uses - have to try fetch-mock

    /*
    test("User Login - login and verify token", async () => {
        const loginHelper = new LoginHelper(TOKEN_URL, logger);
        await loginHelper.init();

        const accessToken = await loginHelper.loginUser(CLIENT_ID, LOGIN_USERNAME, LOGIN_PASSWORD);

        expect(accessToken).not.toBeNull();

        const tokenHelper = new TokenHelper(ISSUER_NAME, JWKS_URL, TEST_AUDIENCE, logger);
        await tokenHelper.init();

        const verified = await tokenHelper.verifyToken(accessToken!.accessToken);
        expect(verified).toBe(true);
    });

    test("User Login - wrong pass", async () => {
        const loginHelper = new LoginHelper(TOKEN_URL, logger);
        await loginHelper.init();

        const accessToken = await loginHelper.loginUser(CLIENT_ID, LOGIN_USERNAME, LOGIN_WRONG_PASSWORD);
        expect(accessToken).toBeNull();
    });

    test("User Login - wrong client_id", async () => {
        const loginHelper = new LoginHelper(TOKEN_URL, logger);
        await loginHelper.init();

        const accessToken = await loginHelper.loginUser("wrong_client_id", LOGIN_USERNAME, LOGIN_WRONG_PASSWORD);
        expect(accessToken).toBeNull();
    });

    test("User Login - wrong username", async () => {
        const loginHelper = new LoginHelper(TOKEN_URL, logger);
        await loginHelper.init();

        const accessToken = await loginHelper.loginUser(CLIENT_ID, "wrong_username", LOGIN_WRONG_PASSWORD);
        expect(accessToken).toBeNull();
    });

    test("Test login api not available", async () => {
        nock.cleanAll();
        const loginHelper = new LoginHelper(TOKEN_URL, logger);
        await loginHelper.init();

        const accessToken = await loginHelper.loginUser(CLIENT_ID, LOGIN_USERNAME, LOGIN_WRONG_PASSWORD);
        expect(accessToken).toBeNull();
    });

    // TODO client_credentials tests
*/



    test("TokenHelper - decode token", async () => {
        const accessToken = TEST_USER_ACCESS_TOKEN;

        const tokenHelper = new TokenHelper(JWKS_URL, logger, "http://not.used/", TEST_AUDIENCE);
        // not intialised to avoid calling jwks.json url
        const payload = tokenHelper.decodeToken(accessToken);
        expect(payload).not.toBeNull();
        expect(payload.testObj).toEqual("pedro1");
    });

    test("Verify invalid token", async () => {
        const tokenHelper = new TokenHelper(JWKS_URL, logger, ISSUER_NAME, TEST_AUDIENCE);
        await tokenHelper.init();

        const verified = await tokenHelper.verifyToken("blablabnot agoodtoken");
        expect(verified).toBe(false);
    });



})
