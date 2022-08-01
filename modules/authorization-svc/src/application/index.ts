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

import {LogLevel, ILogger} from "@mojaloop/logging-bc-public-types-lib";
import {KafkaLogger} from "@mojaloop/logging-bc-client-lib";
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

const BC_NAME = "security-bc";
const APP_NAME = "authorization-svc";
const APP_VERSION = "0.0.1";
const LOGLEVEL = LogLevel.DEBUG;

const SVC_DEFAULT_HTTP_PORT = 3202;

const KAFKA_URL = process.env["KAFKA_URL"] || "localhost:9092";
const KAFKA_AUDITS_TOPIC = process.env["KAFKA_AUDITS_TOPIC"] || "audits";
const KAFKA_LOGS_TOPIC = process.env["KAFKA_LOGS_TOPIC"] || "logs";

// const logger: ILogger = new ConsoleLogger();

// kafka logger
const kafkaProducerOptions = {
    kafkaBrokerList: KAFKA_URL
}

const logger:KafkaLogger = new KafkaLogger(
        BC_NAME,
        APP_NAME,
        APP_VERSION,
        kafkaProducerOptions,
        KAFKA_LOGS_TOPIC,
        LOGLEVEL
);

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
    await logger.start();
    authNRepo = new FileAuthorizationRepo("./dist/authZ_TempStorageFile", logger);
    await authNRepo.init();

    authorizationAggregate = new AuthorizationAggregate(authNRepo, logger);

    routes = new ExpressRoutes(authorizationAggregate, logger);

    setupExpress();
    setupRoutes();

    let portNum = SVC_DEFAULT_HTTP_PORT;
    if(process.env["SVC_HTTP_PORT"] && !isNaN(parseInt(process.env["SVC_HTTP_PORT"]))) {
        portNum = parseInt(process.env["SVC_HTTP_PORT"])
    }

    const server = app.listen(portNum, () => {
        console.log(`🚀 Server ready at: http://localhost:${portNum}`);
        logger.info("Authorization service started");
    });
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
