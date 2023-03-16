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

import {Server} from "http";
import {existsSync} from "fs";
import express from "express";
import {ILogger} from "@mojaloop/logging-bc-public-types-lib";
import {LocalRolesAssociationRepo} from "../infrastructure/local_roles_repo";
import {IAMAuthenticationAdapter, ICryptoAuthenticationAdapter, ILocalRoleAssociationRepo} from "../domain/interfaces";
import {FileIAMAdapter} from "../infrastructure/file_iam_adapter";
import {AuthenticationAggregate, AuthenticationAggregateOptions} from "../domain/authentication_agg";
import {LogLevel} from "@mojaloop/logging-bc-public-types-lib/dist/index";
import {KafkaLogger} from "@mojaloop/logging-bc-client-lib/dist/index";
import {AuthenticationRoutes} from "./authentication_routes";
import {SimpleCryptoAdapter2} from "../infrastructure/simple_crypto_adapter2";

// get configClient from dedicated file
import configClient, {configKeys} from "./config";
import {defaultDevApplications, defaultDevUsers} from "../dev_defaults";

// service constants
const PRODUCTION_MODE = process.env["PRODUCTION_MODE"] || false;
const LOG_LEVEL:LogLevel = process.env["LOG_LEVEL"] as LogLevel || LogLevel.DEBUG;

const SVC_DEFAULT_HTTP_PORT = 3201;

const KAFKA_URL = process.env["KAFKA_URL"] || "localhost:9092";
//const KAFKA_AUDITS_TOPIC = process.env["KAFKA_AUDITS_TOPIC"] || "audits";
const KAFKA_LOGS_TOPIC = process.env["KAFKA_LOGS_TOPIC"] || "logs";

const IAM_STORAGE_FILE_PATH = process.env["IAM_STORAGE_FILE_PATH"] || "/app/data/authN_TempIAMStorageFile.json";
const ROLES_STORAGE_FILE_PATH = process.env["ROLES_STORAGE_FILE_PATH"] || "/app/data/authN_TempRolesStorageFile.json";
const PRIVATE_CERT_PEM_FILE_PATH = process.env["PRIVATE_CERT_PEM_FILE_PATH"] || "/app/data/private.pem";

const AUTH_N_TOKEN_LIFE_SECS = process.env["AUTH_N_TOKEN_LIFE_SECS"] ? parseInt(process.env["AUTH_N_TOKEN_LIFE_SECS"]) : 3600;
const AUTH_N_DEFAULT_AUDIENCE = process.env["AUTH_N_DEFAULT_AUDIENCE"] || "mojaloop.vnext.default_audience";
const AUTH_N_ISSUER_NAME = process.env["AUTH_N_ISSUER_NAME"] || "http://localhost:3201";

// kafka logger
const kafkaProducerOptions = {
    kafkaBrokerList: KAFKA_URL
}

let globalLogger: ILogger;

export class Service {
    static logger: ILogger;
    static iam:IAMAuthenticationAdapter;
    static crypto:ICryptoAuthenticationAdapter;
    static localRoleAssociationRepo: ILocalRoleAssociationRepo | null;
    static authAgg: AuthenticationAggregate;
    static expressServer: Server;

    static async start(
        logger?: ILogger, iamAdapter?:IAMAuthenticationAdapter,
        cryptoAdapter?:ICryptoAuthenticationAdapter, localRoleAssociationRepo?: ILocalRoleAssociationRepo
    ):Promise<void>{
        console.log(`Service starting with PID: ${process.pid}`);

        /// start config client - this is not mockable (can use STANDALONE MODE if desired)
        await configClient.init();
        await configClient.bootstrap(true);
        await configClient.fetch();

        if (!logger) {
            logger = new KafkaLogger(
                configClient.boundedContextName,
                configClient.applicationName,
                configClient.applicationVersion,
                kafkaProducerOptions,
                KAFKA_LOGS_TOPIC,
                LOG_LEVEL
            );
            await (logger as KafkaLogger).init();
        }
        globalLogger = this.logger = logger.createChild("Service");

        // construct the aggregate options first, other things might need these options
        const aggregateOptions: AuthenticationAggregateOptions = {
            tokenLifeSecs: AUTH_N_TOKEN_LIFE_SECS,
            defaultAudience: AUTH_N_DEFAULT_AUDIENCE
        };

        const rolesFromIamProviderParam = configClient.appConfigs.getParam(configKeys.ROLES_FROM_IAM_PROVIDER);
        if (rolesFromIamProviderParam) {
            aggregateOptions.rolesFromIamProvider = rolesFromIamProviderParam.currentValue;
        }

        if(!iamAdapter){
            // not sure why we would be running this FileIAMAdapter in production, but...
            if(!existsSync(IAM_STORAGE_FILE_PATH) && PRODUCTION_MODE){
                throw new Error("PRODUCTION_MODE and non existing IAM_STORAGE_FILE_PATH in: "+IAM_STORAGE_FILE_PATH);
            }

            const fileIAMAdapter = new FileIAMAdapter(IAM_STORAGE_FILE_PATH, this.logger);
            await fileIAMAdapter.init();


            // hard insert dev defaults into the repository
            if(!PRODUCTION_MODE){
                if(!fileIAMAdapter.userCount()) {
                    this.logger.warn("In PRODUCTION_MODE and no users found - creating dev default users...");
                    for(const user of defaultDevUsers){
                        await fileIAMAdapter.createUser(user.username, user.password, user.roles);
                    }
                    this.logger.info(`Created ${fileIAMAdapter.userCount()} dev default users`);
                }
                if(!fileIAMAdapter.appCount()) {
                    this.logger.warn("In PRODUCTION_MODE and no apps found - creating dev default apps...");
                    for (const app of defaultDevApplications) {
                        await fileIAMAdapter.createApp(app.client_id, app.client_secret, app.roles);
                    }
                    this.logger.info(`Created ${fileIAMAdapter.appCount()} dev default apps`);
                }
            }

            iamAdapter = fileIAMAdapter;
        }
        this.iam = iamAdapter;

        if(!cryptoAdapter) {
            if(!existsSync(PRIVATE_CERT_PEM_FILE_PATH)){
                SimpleCryptoAdapter2.createRsaPrivateKeyFileSync(PRIVATE_CERT_PEM_FILE_PATH);
                if(PRODUCTION_MODE){
                    throw new Error("PRODUCTION_MODE and non existing PRIVATE_CERT_PEM_FILE_PATH in: "+PRIVATE_CERT_PEM_FILE_PATH);
                }
            }

            cryptoAdapter = new SimpleCryptoAdapter2(PRIVATE_CERT_PEM_FILE_PATH, AUTH_N_ISSUER_NAME, logger);
            await cryptoAdapter.init();
        }
        this.crypto = cryptoAdapter;

        if(!localRoleAssociationRepo && aggregateOptions.rolesFromIamProvider){
            if (!existsSync(ROLES_STORAGE_FILE_PATH) && PRODUCTION_MODE) {
                throw new Error("PRODUCTION_MODE and non existing IAM_STORAGE_FILE_PATH in: " + ROLES_STORAGE_FILE_PATH);
            }

            localRoleAssociationRepo = new LocalRolesAssociationRepo(ROLES_STORAGE_FILE_PATH, this.logger);
            await localRoleAssociationRepo!.init();
        }
        this.localRoleAssociationRepo = localRoleAssociationRepo || null;

        // construct the aggregate
        try {
            this.authAgg = new AuthenticationAggregate(this.iam, this.crypto, this.logger, this.localRoleAssociationRepo, aggregateOptions);
        }catch(err){
            await Service.stop();
        }

        this.setupAndStartExpress();
    }


    static setupAndStartExpress():void {
        const app = express();
        app.use(express.json()); // for parsing application/json
        app.use(express.urlencoded({extended: true})); // for parsing application/x-www-form-urlencoded

        app.use( (req: express.Request, res: express.Response, next: express.NextFunction) => {
            this.logger.debug(`Received request to: ${req.protocol}://${req.headers.host}${req.originalUrl}`);
            // CORS allow from any
            res.setHeader("Access-Control-Allow-Origin","*");
            next();
        });

        const globalConfigsRoutes = new AuthenticationRoutes(this.authAgg, this.crypto, AUTH_N_ISSUER_NAME, this.logger);
        app.use(globalConfigsRoutes.Router);

        // catch all rule
        app.use((req, res) => {
            // catch all
            this.logger.info("got unhandled/404 request to: " + req.path);
            res.send(404);
        });

        let portNum = SVC_DEFAULT_HTTP_PORT;
        if(process.env["SVC_HTTP_PORT"] && !isNaN(parseInt(process.env["SVC_HTTP_PORT"]))) {
            portNum = parseInt(process.env["SVC_HTTP_PORT"])
        }

        this.expressServer = app.listen(portNum, () => {
            console.log(`🚀 Server ready at: http://localhost:${portNum}`);
            this.logger.info(`Authentication service v: ${configClient.applicationVersion} started - with IssuerName: ${AUTH_N_ISSUER_NAME} tokenLifeSecs: ${AUTH_N_TOKEN_LIFE_SECS}`);
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
    globalLogger.error(err);
});
