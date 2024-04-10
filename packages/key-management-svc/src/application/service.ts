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

 * ThitsaWorks
 - Si Thu Myo <sithu.myo@thitsaworks.com>

 --------------
 ******/

"use strict";
import { Server } from "http";
import express from "express";
import Vault from "node-vault";
import { ILogger } from "@mojaloop/logging-bc-public-types-lib";

import { KeyManagementAggregate } from "../domain/aggregate";
import { LogLevel } from "@mojaloop/logging-bc-public-types-lib/dist/index";
import { KafkaLogger } from "@mojaloop/logging-bc-client-lib/dist/index";

import { AuthenticatedHttpRequester, TokenHelper, AuthorizationClient } from "@mojaloop/security-bc-client-lib";

import process from "process";
import util from "util";
import { KeyManagementRoutes } from "./routes";
import { CertificateManager } from "../domain//certificate_manager";


import { MLKafkaJsonConsumer } from "@mojaloop/platform-shared-lib-nodejs-kafka-client-lib";
import { ISecureCertificateStorage, SECURE_CERTIFICATE_STORAGE_TYPE } from "../domain/isecure_storage";
import { MongoCertificateStorage } from "../implementation/mongo_certificate_storage";
import { CertKeyMangementPriviledgesDefinition } from "../domain/privileges";
import { IAuthorizationClient } from "@mojaloop/security-bc-public-types-lib";

// eslint-disable-next-line @typescript-eslint/no-var-requires
const packageJSON = require("../../package.json");

// service constants
const BC_NAME = "security-bc";
const APP_NAME = "key-management-svc";
const APP_VERSION = packageJSON.version;
const PRODUCTION_MODE = process.env["PRODUCTION_MODE"] || false;
const LOG_LEVEL: LogLevel = process.env["LOG_LEVEL"] as LogLevel || LogLevel.DEBUG;

const SVC_DEFAULT_HTTP_PORT = 3204;

const KAFKA_URL = process.env["KAFKA_URL"] || "localhost:9092";
//const KAFKA_AUDITS_TOPIC = process.env["KAFKA_AUDITS_TOPIC"] || "audits";
const KAFKA_LOGS_TOPIC = process.env["KAFKA_LOGS_TOPIC"] || "logs";

const AUTH_N_TOKEN_LIFE_SECS = process.env["AUTH_N_TOKEN_LIFE_SECS"] ? parseInt(process.env["AUTH_N_TOKEN_LIFE_SECS"]) : 3600;
// const AUTH_N_DEFAULT_AUDIENCE = process.env["AUTH_N_DEFAULT_AUDIENCE"] || "mojaloop.vnext.dev.default_audience";
const AUTH_N_ISSUER_NAME = process.env["AUTH_N_ISSUER_NAME"] || "mojaloop.vnext.dev.default_issuer";

const AUTH_N_SVC_BASEURL = process.env["AUTH_N_SVC_BASEURL"] || "http://localhost:3201";
const AUTH_N_SVC_TOKEN_URL = AUTH_N_SVC_BASEURL + "/token"; // TODO this should not be known here, libs that use the base should add the suffix

const AUTH_N_TOKEN_ISSUER_NAME = process.env["AUTH_N_TOKEN_ISSUER_NAME"] || "mojaloop.vnext.dev.default_issuer";
const AUTH_N_TOKEN_AUDIENCE = process.env["AUTH_N_TOKEN_AUDIENCE"] || "mojaloop.vnext.dev.default_audience";
const AUTH_N_SVC_JWKS_URL = process.env["AUTH_N_SVC_JWKS_URL"] || `${AUTH_N_SVC_BASEURL}/.well-known/jwks.json`;

const AUTH_Z_SVC_BASEURL = process.env["AUTH_Z_SVC_BASEURL"] || "http://localhost:3202";

const INSTANCE_NAME = `${BC_NAME}_${APP_NAME}`;
const INSTANCE_ID = `${INSTANCE_NAME}__${crypto.randomUUID()}`;

const SVC_CLIENT_ID = process.env["SVC_CLIENT_ID"] || "security-bc-key-management-svc";
const SVC_CLIENT_SECRET = process.env["SVC_CLIENT_SECRET"] || "superServiceSecret";

// ---- Certificate Storage Environment Variables ----
const SECURE_STORAGE_TYPE =
    process.env["SECURE_STORAGE_TYPE"] as SECURE_CERTIFICATE_STORAGE_TYPE || SECURE_CERTIFICATE_STORAGE_TYPE.MONGO;
const CA_ENCRYPTION_SECRET_KEY = process.env["CA_ENCRYPTION_SECRET_KEY"] || "test_secret_key";

// mongo storage env
const MONGO_URL = process.env["MONGO_URL"] || "mongodb://root:mongoDbPas42@localhost:27017/";


// kafka logger
const kafkaProducerOptions = {
    kafkaBrokerList: KAFKA_URL
};

// global
let globalLogger: ILogger;

export class Service {
    static logger: ILogger;
    static keyManagementAgg: KeyManagementAggregate;
    static expressServer: Server;
    static tokenHelper: TokenHelper;
    static authorizationClient: IAuthorizationClient;
    static certificateManager: CertificateManager;
    static secureStorage: ISecureCertificateStorage;

    static async start(
        logger?: ILogger,
        certificateManager?: CertificateManager,
        authorizationClient?: IAuthorizationClient,
    ): Promise<void> {
        console.log(`Service starting with PID: ${process.pid}`);

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

        if (!this.secureStorage) {
            // add more secure storage if needed
            switch (SECURE_STORAGE_TYPE.toLowerCase()) {
                case SECURE_CERTIFICATE_STORAGE_TYPE.MONGO:
                case SECURE_CERTIFICATE_STORAGE_TYPE.MONGODB:
                    this.secureStorage = new MongoCertificateStorage(MONGO_URL, this.logger);
                    this.logger.info("Using MongoDB storage for certificates.");
                    break;
                default:
                    throw new Error(`Unknown secure storage type: ${SECURE_STORAGE_TYPE}`);
            }

            // await this.secureStorage.init(CA_ENCRYPTION_SECRET_KEY, CA_ENCRYPTION_ENABLED);
            await this.secureStorage.init(CA_ENCRYPTION_SECRET_KEY, false);
        }

        if (!certificateManager) {
            this.certificateManager = new CertificateManager(this.secureStorage, this.logger);
            this.certificateManager.init();
        }

        // token helper
        this.tokenHelper = new TokenHelper(
            AUTH_N_SVC_JWKS_URL,
            logger,
            AUTH_N_TOKEN_ISSUER_NAME,
            AUTH_N_TOKEN_AUDIENCE,
            new MLKafkaJsonConsumer({ kafkaBrokerList: KAFKA_URL, autoOffsetReset: "earliest", kafkaGroupId: INSTANCE_ID }, logger) // for jwt list - no groupId
        );

        await this.tokenHelper.init();

        // authorization client
        if (!authorizationClient) {
            // create the instance of IAuthenticatedHttpRequester
            const authRequester = new AuthenticatedHttpRequester(logger, AUTH_N_SVC_TOKEN_URL);
            authRequester.setAppCredentials(SVC_CLIENT_ID, SVC_CLIENT_SECRET);

            const messageConsumer = new MLKafkaJsonConsumer(
                {
                    kafkaBrokerList: KAFKA_URL,
                    kafkaGroupId: `${BC_NAME}_${APP_NAME}_authz_client`
                }, logger.createChild("authorizationClientConsumer")
            );

            // setup privileges - bootstrap app privs and get priv/role associations
            authorizationClient = new AuthorizationClient(
                BC_NAME, APP_NAME, APP_VERSION,
                AUTH_Z_SVC_BASEURL, logger.createChild("AuthorizationClient"),
                authRequester,
                messageConsumer
            );

            authorizationClient.addPrivilegesArray(CertKeyMangementPriviledgesDefinition);
            await (authorizationClient as AuthorizationClient).bootstrap(true);
            await (authorizationClient as AuthorizationClient).fetch();
            // init message consumer to automatically update on role changed events
            await (authorizationClient as AuthorizationClient).init();
        }

        this.authorizationClient = authorizationClient;
        try {
            this.keyManagementAgg = new KeyManagementAggregate(
                this.logger,
                this.certificateManager,
                this.secureStorage,
                this.authorizationClient
            );
        } catch (err) {
            await Service.stop();
        }

        // start express http server
        this.setupAndStartExpress();
    }

    static setupAndStartExpress(): void {
        const app = express();
        app.use(express.json()); // for parsing application/json
        app.use(express.urlencoded({ extended: true })); // for parsing application/x-www-form-urlencoded

        app.use((req: express.Request, res: express.Response, next: express.NextFunction) => {
            this.logger.debug(`Received request to: ${req.protocol}://${req.headers.host}${req.originalUrl}`);
            next();
        });

        // Add health route - before others (to avoid authZ middleware)
        app.get("/health", (req: express.Request, res: express.Response) => {
            return res.send({ status: "OK" });
        });

        const globalConfigsRoutes = new KeyManagementRoutes(
            this.keyManagementAgg,
            this.tokenHelper,
            this.authorizationClient,
            this.logger,
        );
        app.use(globalConfigsRoutes.Router);

        // catch all rule
        app.use((req, res) => {
            // catch all
            this.logger.info("got unhandled/404 request to: " + req.path);
            res.send(404);
        });

        let portNum = SVC_DEFAULT_HTTP_PORT;
        if (process.env["SVC_HTTP_PORT"] && !isNaN(parseInt(process.env["SVC_HTTP_PORT"]))) {
            portNum = parseInt(process.env["SVC_HTTP_PORT"]);
        }

        this.expressServer = app.listen(portNum, () => {
            console.log(`🚀 Server ready at: http://localhost:${portNum}`);
            this.logger.info(`Key Management Service v: ${APP_VERSION} started - with IssuerName: ${AUTH_N_ISSUER_NAME} tokenLifeSecs: ${AUTH_N_TOKEN_LIFE_SECS}`);
        }).on("error", err => {
            this.logger.fatal(err);
            process.exit(9);
        });

    }

    static async stop(): Promise<void> {
        if (this.expressServer) {
            const closeExpress = util.promisify(this.expressServer.close);
            await closeExpress();
        }
        if (this.logger && this.logger instanceof KafkaLogger) await this.logger.destroy();

        if (this.secureStorage) await this.secureStorage.destroy();

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
