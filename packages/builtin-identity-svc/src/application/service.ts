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
import express, {Express} from "express";
import process from "process";

import {ILogger} from "@mojaloop/logging-bc-public-types-lib";
import { IBuiltinIdentityRepository} from "../domain/interfaces";
import {LogLevel} from "@mojaloop/logging-bc-public-types-lib";
import {KafkaLogger} from "@mojaloop/logging-bc-client-lib";
import {IdentifyManagementRoutes} from "./routes";

import {IdentityManagementAggregate} from "../domain/identity_management_agg";

import {
    AuthorizationClient,
    TokenHelper
} from "@mojaloop/security-bc-client-lib";
import {IAuthorizationClient} from "@mojaloop/security-bc-public-types-lib";
import {BuiltinIdentityPrivilegesDefinition} from "../domain/privileges";
import {MongoDbBuiltinIdentityRepository} from "../infrastructure/mongodb_repo";
import {defaultDevApplications, defaultDevUsers} from "../dev_defaults";
import { MLKafkaJsonConsumer, MLKafkaJsonConsumerOptions } from "@mojaloop/platform-shared-lib-nodejs-kafka-client-lib";
import {existsSync} from "fs";
import {
    AuditClient,
    KafkaAuditClientDispatcher,
    LocalAuditClientCryptoProvider
} from "@mojaloop/auditing-bc-client-lib";
import {IAuditClient} from "@mojaloop/auditing-bc-public-types-lib";

// eslint-disable-next-line @typescript-eslint/no-var-requires
const packageJSON = require("../../package.json");

// service constants
const BC_NAME = "security-bc";
const APP_NAME = "identity-svc";
const APP_VERSION = packageJSON.version;
const PRODUCTION_MODE = process.env["PRODUCTION_MODE"] || false;
const LOG_LEVEL:LogLevel = process.env["LOG_LEVEL"] as LogLevel || LogLevel.DEBUG;

const SVC_DEFAULT_HTTP_PORT = 3203;

const KAFKA_URL = process.env["KAFKA_URL"] || "localhost:9092";
const MONGO_URL = process.env["MONGO_URL"] || "mongodb://root:mongoDbPas42@localhost:27017/";
const KAFKA_AUDITS_TOPIC = process.env["KAFKA_AUDITS_TOPIC"] || "audits";
const KAFKA_LOGS_TOPIC = process.env["KAFKA_LOGS_TOPIC"] || "logs";

const AUDIT_KEY_FILE_PATH = process.env["AUDIT_KEY_FILE_PATH"] || "/app/data/audit_private_key.pem";

// TODO: rename these env var to a specific name
const AUTH_N_TOKEN_LIFE_SECS = process.env["AUTH_N_TOKEN_LIFE_SECS"] ? parseInt(process.env["AUTH_N_TOKEN_LIFE_SECS"]) : 3600;
const AUTH_N_SVC_BASEURL = process.env["AUTH_N_SVC_BASEURL"] || "http://localhost:3201";
const AUTH_N_TOKEN_ISSUER_NAME = process.env["AUTH_N_TOKEN_ISSUER_NAME"] || "mojaloop.vnext.dev.default_issuer";
const AUTH_N_TOKEN_AUDIENCE = process.env["AUTH_N_TOKEN_AUDIENCE"] || "mojaloop.vnext.dev.default_audience";
const AUTH_N_SVC_JWKS_URL = process.env["AUTH_N_SVC_JWKS_URL"] || `${AUTH_N_SVC_BASEURL}/.well-known/jwks.json`;

const AUTH_Z_SVC_BASEURL = process.env["AUTH_Z_SVC_BASEURL"] || "http://localhost:3202";

const SERVICE_START_TIMEOUT_MS = 60_000;

// kafka logger
const kafkaProducerOptions = {
    kafkaBrokerList: KAFKA_URL
};

const kafkaConsumerOptions: MLKafkaJsonConsumerOptions = {
    kafkaBrokerList: KAFKA_URL,
    kafkaGroupId: `${BC_NAME}_${APP_NAME}_authz_client`
};

// global
let globalLogger: ILogger;

export class Service {
    static logger: ILogger;
    static app: Express;
    static expressServer: Server;
    static userManagementRepo: IBuiltinIdentityRepository;
    static aggregate: IdentityManagementAggregate;
    static tokenHelper: TokenHelper;
    static authorizationClient: IAuthorizationClient;
    static auditClient: IAuditClient;
    static startupTimer: NodeJS.Timeout;

    static async start(
        logger?: ILogger,
        authorizationClient?: IAuthorizationClient,
        userManagementRepo?: IBuiltinIdentityRepository,
        auditClient?: IAuditClient
    ):Promise<void>{
        console.log(`Service starting with PID: ${process.pid}`);

        this.startupTimer = setTimeout(()=>{
            throw new Error("Service start timed-out");
        }, SERVICE_START_TIMEOUT_MS);

        // /// start config client - this is not mockable (can use STANDALONE MODE if desired)
        // await configClient.init();
        // await configClient.bootstrap(true);
        // await configClient.fetch();

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

        // authorization client
        if (!authorizationClient) {
            const consumerHandlerLogger = logger.createChild("authorizationClientConsumer");
            const messageConsumer = new MLKafkaJsonConsumer(kafkaConsumerOptions, consumerHandlerLogger);

            // setup privileges - bootstrap app privs and get priv/role associations
            authorizationClient = new AuthorizationClient(
                BC_NAME, APP_NAME, APP_VERSION,
                AUTH_Z_SVC_BASEURL, logger.createChild("AuthorizationClient"),
                messageConsumer
            );
            authorizationClient.addPrivilegesArray(BuiltinIdentityPrivilegesDefinition);
            await (authorizationClient as AuthorizationClient).bootstrap(true);
            await (authorizationClient as AuthorizationClient).fetch();
            await (authorizationClient as AuthorizationClient).init(); // init
        }
        this.authorizationClient = authorizationClient;

        // token helper
        this.tokenHelper = new TokenHelper(AUTH_N_SVC_JWKS_URL, logger, AUTH_N_TOKEN_ISSUER_NAME, AUTH_N_TOKEN_AUDIENCE);

        // authorization client
        if (!userManagementRepo) {
            userManagementRepo = new MongoDbBuiltinIdentityRepository(MONGO_URL, logger);
        }
        this.userManagementRepo = userManagementRepo;

        // start auditClient
        if (!auditClient) {
            if (!existsSync(AUDIT_KEY_FILE_PATH)) {
                if (PRODUCTION_MODE) process.exit(9);
                // create e tmp file
                LocalAuditClientCryptoProvider.createRsaPrivateKeyFileSync(AUDIT_KEY_FILE_PATH, 2048);
            }
            const auditLogger = logger.createChild("AuditLogger");
            auditLogger.setLogLevel(LogLevel.INFO);
            const cryptoProvider = new LocalAuditClientCryptoProvider(AUDIT_KEY_FILE_PATH);
            const auditDispatcher = new KafkaAuditClientDispatcher(kafkaProducerOptions, KAFKA_AUDITS_TOPIC, auditLogger);
            // NOTE: to pass the same kafka logger to the audit client, make sure the logger is started/initialised already
            auditClient = new AuditClient(BC_NAME, APP_NAME, APP_VERSION, cryptoProvider, auditDispatcher);
            await auditClient.init();
        }
        this.auditClient = auditClient;

        // construct the aggregate
        try {
            this.aggregate = new IdentityManagementAggregate(
                this.logger,
                this.userManagementRepo,
                this.authorizationClient,
                this.auditClient,
                AUTH_N_TOKEN_LIFE_SECS
            );
            await this.aggregate.init();

            if(!PRODUCTION_MODE){
                const users = await userManagementRepo.fetchAllUsers();
                if(users.length<=0) {
                    await this.aggregate.boostrapDefaultUsers(defaultDevUsers);
                }

                const apps = await userManagementRepo.fetchAllApps();
                if(apps.length<=0) {
                    await this.aggregate.boostrapDefaultApps(defaultDevApplications);
                }
            }else{
                // TODO Inject default production user and apps
            }

        }catch(err){
            await Service.stop();
        }

        await this.setupExpress();

        // remove startup timeout
        clearTimeout(this.startupTimer);
    }

    static setupExpress(): Promise<void> {
        return new Promise<void>(resolve => {
            this.app = express();
            this.app.use(express.json()); // for parsing application/json
            this.app.use(express.urlencoded({extended: true})); // for parsing application/x-www-form-urlencoded

            this.app.use( (req: express.Request, res: express.Response, next: express.NextFunction) => {
                this.logger.debug(`Received request to: ${req.protocol}://${req.headers.host}${req.originalUrl}`);
                // CORS allow from any
                res.setHeader("Access-Control-Allow-Origin","*");
                next();
            });


            // Add health and metrics http routes - before others (to avoid authZ middleware)
            this.app.get("/health", (req: express.Request, res: express.Response) => {
                return res.send({ status: "OK" });
            });
            /* this.app.get("/metrics", async (req: express.Request, res: express.Response) => {
                 const strMetrics = await (this.metrics as PrometheusMetrics).getMetricsForPrometheusScrapper();
                 return res.send(strMetrics);
             });*/

            // app routes
            const globalConfigsRoutes = new IdentifyManagementRoutes(this.aggregate, this.tokenHelper, this.logger);
            this.app.use("/", globalConfigsRoutes.Router);

            this.app.use((req, res) => {
                // catch all
                res.send(404);
            });

            let portNum = SVC_DEFAULT_HTTP_PORT;
            if (process.env["SVC_HTTP_PORT"] && !isNaN(parseInt(process.env["SVC_HTTP_PORT"]))) {
                portNum = parseInt(process.env["SVC_HTTP_PORT"]);
            }

            this.expressServer = this.app.listen(portNum, () => {
                this.logger.info(`🚀 Server ready at port: ${portNum}`);
                this.logger.info(`Builtin Identity service v: ${APP_VERSION} started`);
                resolve();
            });
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
