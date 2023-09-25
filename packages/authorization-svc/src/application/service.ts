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

import {defaultDevRoles} from "../dev_defaults";
import {Server} from "http";
import express from "express";

import {LogLevel, ILogger} from "@mojaloop/logging-bc-public-types-lib";
import {KafkaLogger} from "@mojaloop/logging-bc-client-lib";

import {AuthorizationAggregate} from "../domain/authorization_agg";
import { IAuthorizationRepository} from "../domain/interfaces";
import {ExpressRoutes} from "./routes";
import {MongoDbAuthorizationRepo} from "../infrastructure/mongodb_authorization_repo";
import process from "process";

// eslint-disable-next-line @typescript-eslint/no-var-requires
const packageJSON = require("../../package.json");

const BC_NAME = "security-bc";
const APP_NAME = "authorization-svc";
const APP_VERSION = packageJSON.version;
const PRODUCTION_MODE = process.env["PRODUCTION_MODE"] || false;
const LOG_LEVEL:LogLevel = process.env["LOG_LEVEL"] as LogLevel || LogLevel.DEBUG;

const SVC_DEFAULT_HTTP_PORT = 3202;

const KAFKA_URL = process.env["KAFKA_URL"] || "localhost:9092";
const MONGO_URL = process.env["MONGO_URL"] || "mongodb://root:mongoDbPas42@localhost:27017/";

//const KAFKA_AUDITS_TOPIC = process.env["KAFKA_AUDITS_TOPIC"] || "audits";
const KAFKA_LOGS_TOPIC = process.env["KAFKA_LOGS_TOPIC"] || "logs";

// kafka logger
const kafkaProducerOptions = {
    kafkaBrokerList: KAFKA_URL
};

// global
let globalLogger: ILogger;

export class Service {
    static logger: ILogger;
    static authorizationRepo: IAuthorizationRepository;
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
            await (logger as KafkaLogger).init();
        }
        globalLogger = this.logger = logger.createChild("Service");

        if(!authNRepo){
            authNRepo = new MongoDbAuthorizationRepo(MONGO_URL, logger);
            await authNRepo.init();

            // hard insert dev defaults into the repository
            if (!PRODUCTION_MODE) {
                if((await authNRepo.fetchAllPlatformRoles()).length <=0 ){
                    this.logger.warn("Not in PRODUCTION_MODE and no platformRoles found - creating dev default platformRole(s)...");
                    for(const role of defaultDevRoles){
                        await authNRepo.storePlatformRole(role);
                    }
                    const newCount = (await authNRepo.fetchAllPlatformRoles()).length;
                    this.logger.info(`Created ${newCount} dev default platformRole(s)`);
                }
            }
        }
        this.authorizationRepo = authNRepo;

        this.authorizationAggregate = new AuthorizationAggregate(this.authorizationRepo, this.logger);

        if (!PRODUCTION_MODE && ! await this.authorizationAggregate.getAllRoles()) {
            // create default roles
        }

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
            portNum = parseInt(process.env["SVC_HTTP_PORT"]);
        }

        this.expressServer = app.listen(portNum, () => {
            console.log(`🚀 Server ready at: http://localhost:${portNum}`);
            this.logger.info(`Authorization service v: ${APP_VERSION} started`);
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
    console.error(err);
    process.exit(99);
});
