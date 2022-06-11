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

import express from "express";

import {ConsoleLogger, ILogger} from "@mojaloop/logging-bc-client-lib";
import {AppPrivileges} from "@mojaloop/security-bc-public-types-lib";
import {AuthorizationAggregate} from "../domain/authorization_agg";
import {IAMAuthorizationAdapter, IAuthorizationRepository} from "../domain/interfaces";
import {FileAuthorizationRepo} from "../infrastructure/file_authorization_repo";
import {
    CannotCreateDuplicateAppPrivilegesError, CannotOverrideAppPrivilegesError, CouldNotStoreAppPrivilegesError,
    InvalidAppPrivilegesError
} from "../domain/errors";
import {AllPrivilegesResp} from "../domain/types";
import {ExpressRoutes} from "./routes";

const logger: ILogger = new ConsoleLogger();
const app = express();
let authorizationAggregate: AuthorizationAggregate;
//let iamAuthNAdapter:IAMAuthorizationAdapter;
let authNRepo: IAuthorizationRepository;
let routes: ExpressRoutes;

function setupExpress() {
    app.use(express.json()); // for parsing application/json
    app.use(express.urlencoded({extended: true})); // for parsing application/x-www-form-urlencoded
}

function setupRoutes() {
    app.use("/", routes.MainRouter);
    app.use("/appPrivileges", routes.PrivilegesRouter);
    app.use("/platformRoles", routes.RolesRouter);

    app.use((req, res) => {
        // catch all
        res.send(404);
    })
}

async function start():Promise<void>{
    authNRepo = new FileAuthorizationRepo("./dist/iamTempStorageFile", logger);
    await authNRepo.init();

    authorizationAggregate = new AuthorizationAggregate(authNRepo, logger);

    routes = new ExpressRoutes(authorizationAggregate, logger);

    setupExpress();
    setupRoutes();

    const server = app.listen(3000, () =>console.log(`🚀 Server ready at: http://localhost:3000`))
}


async function _handle_int_and_term_signals(signal: NodeJS.Signals): Promise<void> {
    logger.info(`Service - ${signal} received - cleaning up...`);
    process.exit();
}

//catches ctrl+c event
process.on("SIGINT", _handle_int_and_term_signals.bind(this));

//catches program termination event
process.on("SIGTERM", _handle_int_and_term_signals.bind(this));

//do something when app is closing
process.on('exit', () => {
    logger.info("Microservice - exiting...");
});

start();
