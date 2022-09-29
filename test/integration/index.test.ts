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

import {AuthorizationClient} from "@mojaloop/security-bc-client-lib";
import {ConsoleLogger} from "@mojaloop/logging-bc-public-types-lib";


const BC_NAME = "test-bc";
const APP_NAME = "test-app1";
const APP_VERSION = "0.0.1";
const AUTH_N_SVC_BASEURL = "http://localhost:3202";

// TODO make sure this test role has the privileges below associated with it
const TEST_ROLE_ID = "fc3455e0-469f-4221-8cd0-5bae2deb99f1";

const logger = new ConsoleLogger();
let authorizationClient:AuthorizationClient;

describe("authorization-client-lib tests", () => {
    beforeAll(async () => {
        authorizationClient = new AuthorizationClient(BC_NAME, APP_NAME, APP_VERSION, AUTH_N_SVC_BASEURL, logger);

        authorizationClient.addPrivilege("test_create", "test create", "desc");
        authorizationClient.addPrivilege("test_delete", "test delete", "desc");
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

    test("test roleHasPrivilege", async () => {
        const hasPriv = await authorizationClient.roleHasPrivilege("fc3455e0-469f-4221-8cd0-5bae2deb99f1", "test_create");
        expect(hasPriv).toBe(true);
    });

    test("test roleHasPrivilege - inexistent_priv", async () => {
        const hasPriv = await authorizationClient.roleHasPrivilege("fc3455e0-469f-4221-8cd0-5bae2deb99f1", "inexistent_priv");
        expect(hasPriv).toBe(false);
    });
});
