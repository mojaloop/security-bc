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

import {
    AuthenticatedHttpRequester,
    AuthorizationClient,
    LoginHelper,
    TokenHelper,
} from "@mojaloop/security-bc-client-lib";
import {ConsoleLogger} from "@mojaloop/logging-bc-public-types-lib";
import {AuthToken, UnauthorizedError} from "@mojaloop/security-bc-public-types-lib";
import nock from "nock";

const BC_NAME = "test-bc";
const APP_NAME = "test-app1";
const APP_VERSION = "0.0.2"; // NOTE increase this if the privs change

const AUTH_N_SVC_BASE_URL = "http://localhost:3201";
const AUTH_Z_SVC_BASE_URL = "http://localhost:3202";

const TOKEN_URL = `${AUTH_Z_SVC_BASE_URL}/token`;
const JWKS_URL = `${AUTH_Z_SVC_BASE_URL}/.well-known/jwks.json`;

// these must match the token
const AUTH_N_DEFAULT_AUDIENCE = "mojaloop.vnext.dev.default_audience";
const AUTH_N_ISSUER_NAME = "mojaloop.vnext.dev.default_issuer";

const APP_CLIENT_ID = "participants-bc-participants-svc";
const APP_CLIENT_SECRET = "superServiceSecret";

const CLIENT_ID = "security-bc-ui";
const LOGIN_USERNAME = "user";
const LOGIN_PASSWORD = "superPass";
const LOGIN_WRONG_PASSWORD = "WrongPass";

// TODO make sure this test role has the privileges below associated with it
const TEST_ROLE_ID = "tests";
const PRIV_TEST_ROLE_HAS = "TEST_EXAMPLE_PRIV";
const PRIV_TEST_ROLE_DOES_NOT_HAVE = "non-existent priv";

const logger = new ConsoleLogger();
let authorizationClient: AuthorizationClient;

describe("authorization-client-lib tests", () => {
    beforeAll(async () => {
        const loginHelper = new LoginHelper(TOKEN_URL, logger);
        loginHelper.setUserCredentials(CLIENT_ID, LOGIN_USERNAME, LOGIN_PASSWORD);

        const authRequester = new AuthenticatedHttpRequester(logger, AUTH_N_SVC_BASE_URL + "/token");
        authRequester.setAppCredentials(APP_CLIENT_ID, APP_CLIENT_SECRET);

        authorizationClient = new AuthorizationClient(BC_NAME, APP_NAME, APP_VERSION, AUTH_Z_SVC_BASE_URL, logger, authRequester);

        authorizationClient.addPrivilege(PRIV_TEST_ROLE_HAS, "test example prov", "desc");
        // await authorizationClient.bootstrap(true);
        // await authorizationClient.init();
        // await authorizationClient.fetch();
    });

    afterAll(async () => {
        // Cleanup
    });

    test("bootstrap", async () => {
        await authorizationClient.bootstrap(true);
    });

    test("fetch", async () => {
        await authorizationClient.fetch();
    });

    test("init", async () => {
      await authorizationClient.init();
    })

    test("test roleHasPrivilege", async () => {
        const hasPriv = authorizationClient.roleHasPrivilege(TEST_ROLE_ID, PRIV_TEST_ROLE_HAS);
        expect(hasPriv).toBe(true);
    });

    test("test roleHasPrivilege - inexistent_priv", async () => {
        const hasPriv = authorizationClient.roleHasPrivilege(TEST_ROLE_ID, PRIV_TEST_ROLE_DOES_NOT_HAVE);
        expect(hasPriv).toBe(false);
    });
});


describe('authentication-client-lib tests', () => {

    test("User Login - login and verify token", async () => {
        const loginHelper = new LoginHelper(TOKEN_URL, logger);
        loginHelper.setUserCredentials(CLIENT_ID, LOGIN_USERNAME, LOGIN_PASSWORD);

        const tokenResp: AuthToken = await loginHelper.getToken();

        expect(tokenResp).not.toBeNull();
        expect(tokenResp.accessToken).not.toBeNull();

        const tokenHelper = new TokenHelper(JWKS_URL, logger, AUTH_N_ISSUER_NAME, AUTH_N_DEFAULT_AUDIENCE);
        await tokenHelper.init();

        console.log('token: ', tokenResp.accessToken);

        const verified = await tokenHelper.verifyToken(tokenResp.accessToken);
        expect(verified).toBe(true);
    });

    test("App Login - login and verify token", async () => {
        const loginHelper = new LoginHelper(TOKEN_URL, logger);
        loginHelper.setAppCredentials(APP_CLIENT_ID, APP_CLIENT_SECRET);

        const tokenResp: AuthToken = await loginHelper.getToken();

        expect(tokenResp).not.toBeNull();
        expect(tokenResp.accessToken).not.toBeNull();

        const tokenHelper = new TokenHelper(JWKS_URL, logger, AUTH_N_ISSUER_NAME, AUTH_N_DEFAULT_AUDIENCE);
        await tokenHelper.init();

        const verified = await tokenHelper.verifyToken(tokenResp.accessToken);
        expect(verified).toBe(true);
    });

    test("Fixed/provided token Login - login and verify token", async () => {
        const tmpLoginHelper = new LoginHelper(TOKEN_URL, logger);
        tmpLoginHelper.setAppCredentials(APP_CLIENT_ID, APP_CLIENT_SECRET);
        const tmpTokenResp: AuthToken = await tmpLoginHelper.getToken();
        expect(tmpTokenResp).not.toBeNull();
        expect(tmpTokenResp.accessToken).not.toBeNull();

        const fixedToken = tmpTokenResp.accessToken;

        const loginHelper = new LoginHelper(TOKEN_URL, logger);
        loginHelper.setToken(fixedToken);

        const tokenResp: AuthToken = await loginHelper.getToken();

        expect(tokenResp).not.toBeNull();
        expect(tokenResp.accessToken).not.toBeNull();

        const tokenHelper = new TokenHelper(JWKS_URL, logger, AUTH_N_ISSUER_NAME, AUTH_N_DEFAULT_AUDIENCE);
        await tokenHelper.init();

        const verified = await tokenHelper.verifyToken(tokenResp.accessToken);
        expect(verified).toBe(true);
    });

    test("Fixed/provided token Login - expired token, should throw", async () => {
        const loginHelper = new LoginHelper(TOKEN_URL, logger);
        // old token used, should fail
        const accessToken = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InpTQlJmNmZSeFQ5alJrZzJGR1hUNnYwWWpDXzZrSUN1Q3hhZmZDOG1MakkifQ.eyJ0eXAiOiJCZWFyZXIiLCJhenAiOiJhY2NvdW50cy1hbmQtYmFsYW5jZXMtYmMtY29hLWdycGMtc3ZjIiwicm9sZXMiOlsiYWNjb3VudHMtYW5kLWJhbGFuY2VzLWJjLWNvYS1ncnBjLXN2YyJdLCJpYXQiOjE2NzU3MTg1MzcsImV4cCI6MTY3NTcyMjEzNywiYXVkIjoibW9qYWxvb3Audm5leHQuZGVmYXVsdF9hdWRpZW5jZSIsImlzcyI6Imh0dHA6Ly9sb2NhbGhvc3Q6MzIwMS8iLCJzdWIiOiJhcHA6OmFjY291bnRzLWFuZC1iYWxhbmNlcy1iYy1jb2EtZ3JwYy1zdmMiLCJqdGkiOiI2OTUxOGUyNi00NDU2LTQyZWItOTM0ZC1kZGExOGFkNGQ1ODkifQ.pRAsPJEW-yjHOjXJGOjob2XVUO6Ivu-WVIkC7Nfl2rDYVTdQ0J4sgA4nToahZa9hBV6sLzoJgV_RPXClLfL9PJL8l0DdG6dszrmX4R9KUSazC8roIoJtdvQ3otJVL4TFTLql7ChASHFgqAUSgFC8xByP8c8I5TUYCuIVlp9kAXrt2aJBX55-2_zI0VWqncV6g4x35uQixZ4PHfkRhk1W0IU1HLHG9rgucmcM05dLtKh6wWPTDalYfdFfkiluo27phy3odQfOw5OeHfYXtKycjLhdqr61hgsYf_aFax_MesC_MQeHdXL0IxclhKWsEW-tA3g83YIeo4E3SVxMbLZgJQ";
        loginHelper.setToken(accessToken);

        await expect(loginHelper.getToken()).rejects.toThrow(UnauthorizedError);
    });


    test("User Login - wrong pass", async () => {
        const loginHelper = new LoginHelper(TOKEN_URL, logger);
        loginHelper.setUserCredentials(CLIENT_ID, LOGIN_USERNAME, LOGIN_WRONG_PASSWORD);

        await expect(loginHelper.getToken()).rejects.toThrow(UnauthorizedError);
    });

    test("User Login - wrong client_id", async () => {
        const loginHelper = new LoginHelper(TOKEN_URL, logger);
        loginHelper.setUserCredentials("wrong_client_id", LOGIN_USERNAME, LOGIN_WRONG_PASSWORD);

        await expect(loginHelper.getToken()).rejects.toThrow(UnauthorizedError);
    });

    test("User Login - wrong username", async () => {
        const loginHelper = new LoginHelper(TOKEN_URL, logger);
        loginHelper.setUserCredentials(CLIENT_ID, "wrong_username", LOGIN_WRONG_PASSWORD);

        await expect(loginHelper.getToken()).rejects.toThrow(UnauthorizedError);
    });

    test("Test login wrong api address", async () => {
        nock.cleanAll();
        const loginHelper = new LoginHelper("http://nowaythiscan.exist.just_to_be_sure.void", logger);
        loginHelper.setUserCredentials(CLIENT_ID, LOGIN_USERNAME, LOGIN_WRONG_PASSWORD);

        await expect(loginHelper.getToken()).rejects.toThrow(Error("Could not get authentication service public keys, cannot continue"));
    });

    // test("Test login ConnectionRefusedError", async () => {
    //     nock.cleanAll();
    //     const loginHelper = new LoginHelper("http://127.0.0.1:0", logger);
    //     loginHelper.setUserCredentials(CLIENT_ID, LOGIN_USERNAME, LOGIN_WRONG_PASSWORD);
    //
    //     await expect(loginHelper.getToken()).rejects.toThrow(ConnectionRefusedError);
    // });

    // TODO client_credentials tests



});
