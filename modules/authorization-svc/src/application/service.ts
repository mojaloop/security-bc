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

import {existsSync} from "fs";
import {Server} from "http";
import express from "express";

import {LogLevel, ILogger} from "@mojaloop/logging-bc-public-types-lib";
import {KafkaLogger} from "@mojaloop/logging-bc-client-lib";

import {AuthorizationAggregate} from "../domain/authorization_agg";
import { IAuthorizationRepository} from "../domain/interfaces";
import {FileAuthorizationRepo} from "../infrastructure/file_authorization_repo";
import {ExpressRoutes} from "./routes";

const BC_NAME = "security-bc";
const APP_NAME = "authorization-svc";
const APP_VERSION = process.env.npm_package_version || "0.0.1";
const PRODUCTION_MODE = process.env["PRODUCTION_MODE"] || false;
const LOG_LEVEL:LogLevel = process.env["LOG_LEVEL"] as LogLevel || LogLevel.DEBUG;

const SVC_DEFAULT_HTTP_PORT = 3202;

const KAFKA_URL = process.env["KAFKA_URL"] || "localhost:9092";
//const KAFKA_AUDITS_TOPIC = process.env["KAFKA_AUDITS_TOPIC"] || "audits";
const KAFKA_LOGS_TOPIC = process.env["KAFKA_LOGS_TOPIC"] || "logs";

const AUTHZ_STORAGE_FILE_PATH = process.env["AUTHZ_STORAGE_FILE_PATH"] || "/app/data/authZ_TempStorageFile.json";


// kafka logger
const kafkaProducerOptions = {
    kafkaBrokerList: KAFKA_URL
}

let globalLogger: ILogger;

export class Service {
    static logger: ILogger;
    static authNRepo: IAuthorizationRepository;
    static authorizationAggregate:AuthorizationAggregate;
    static expressServer: Server;

    static async start(logger?: ILogger, authNRepo?:IAuthorizationRepository):Promise<void>{
        if (!logger) {
            logger = new KafkaLogger(
                    BC_NAME,
                    APP_NAME,
                    APP_VERSION,
                    kafkaProducerOptions,
                    KAFKA_LOGS_TOPIC,
                    LOG_LEVEL
            );
            await (logger as KafkaLogger).start();
        }
        globalLogger = this.logger = logger.createChild("Service");

        if(!authNRepo){
            if(!existsSync(AUTHZ_STORAGE_FILE_PATH) && PRODUCTION_MODE){
                throw new Error("PRODUCTION_MODE and non existing AUTHZ_STORAGE_FILE_PATH in: "+AUTHZ_STORAGE_FILE_PATH);
            }
            authNRepo = new FileAuthorizationRepo(AUTHZ_STORAGE_FILE_PATH, logger);
            await authNRepo.init();
        }
        this.authNRepo = authNRepo;

        this.authorizationAggregate = new AuthorizationAggregate(this.authNRepo, this.logger);

        this.setupAndStartExpress();
    }

    static setupAndStartExpress():void {
        const app = express();
        app.use(express.json()); // for parsing application/json
        app.use(express.urlencoded({extended: true})); // for parsing application/x-www-form-urlencoded

        const routes = new ExpressRoutes(this.authorizationAggregate, this.logger);
        app.use("/", routes.MainRouter);
        app.use("/appPrivileges", routes.PrivilegesRouter);

        app.use("/platformRoles", routes.RolesRouter);

        app.use((req, res) => {
            // catch all
            res.send(404);
        });

        let portNum = SVC_DEFAULT_HTTP_PORT;
        if(process.env["SVC_HTTP_PORT"] && !isNaN(parseInt(process.env["SVC_HTTP_PORT"]))) {
            portNum = parseInt(process.env["SVC_HTTP_PORT"])
        }

        this.expressServer = app.listen(portNum, () => {
            console.log(`🚀 Server ready at: http://localhost:${portNum}`);
            this.logger.info("Authentication service started");
        }).on("error", err => {
            this.logger.fatal(err);
            process.exit(9);
        });
    }

    static async stop():Promise<void>{
        if(this.expressServer) this.expressServer.close();
    }
}


/**
 * process termination and cleanup
 */

async function _handle_int_and_term_signals(signal: NodeJS.Signals): Promise<void> {
    console.info(`Service - ${signal} received - cleaning up...`);
    await Service.stop();
    process.exit();
}

//catches ctrl+c event
process.on("SIGINT", _handle_int_and_term_signals);
//catches program termination event
process.on("SIGTERM", _handle_int_and_term_signals);

//do something when app is closing
process.on("exit", async () => {
    globalLogger.info("Microservice - exiting...");
});
process.on("uncaughtException", (err: Error) => {
    globalLogger.fatal(err);
    process.exit(99);
});
