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

'use strict'

import express from "express";

import {ConsoleLogger, ILogger} from "@mojaloop/logging-bc-logging-client-lib";
import {IAMAdapter, ICryptoAdapter} from "../domain/types";
import {FileIAMAdapter} from "../infrastructure/file_iam_adapter";
import {SimpleCryptoAdapter} from "../infrastructure/simple_crypto_adapter";

const ISSUER_NAME = "vNext Security BC - Authorization Svc";
const FIX_AUDIENCE_CHANGE = "vNext platform";
const TOKEN_LIFE_SECS = 3600;
const REFRESH_TOKEN_LENGTH = 128;

const logger: ILogger = new ConsoleLogger();
const app = express();
let iam:IAMAdapter;
let crypto:ICryptoAdapter;


function setupExpress() {
    app.use(express.json()); // for parsing application/json
    app.use(express.urlencoded({extended: true})); // for parsing application/x-www-form-urlencoded
}

function setupRoutes() {
    app.post("/login", async (req: express.Request, res: express.Response, next: express.NextFunction) => {
        const data: any = req.body;
        logger.debug(data);

        let username = req.body.username;
        let password = req.body.password;

        const authenticationHeader = req.get("Authorization");
        if (authenticationHeader) {
            [username, password] = Buffer.from(authenticationHeader.replace(/^Basic /i, ""), "base64").toString("ascii").split(":", 2);
        }

        const loginOk = await iam.loginUser(username, password);

        if (!loginOk) {
            return res.status(401).send();
        }

        const additionalPayload = {
            roles:["role1", "role2"],
            testObj: "pedro1"
        };//new types.TokenPayload(username, accountID, userID);

        const accessCode = await crypto.generateJWT(additionalPayload, username, FIX_AUDIENCE_CHANGE, TOKEN_LIFE_SECS);

        const ret = {
            token_type: "bearer",
            //scope: "",
            access_token: accessCode,
            expires_in: TOKEN_LIFE_SECS,
            refresh_token: null,
            refresh_token_expires_in: 0
        }

        return res.status(200).json(ret);
    });


    app.get("/.well-known/jwks.json", async (req: express.Request, res: express.Response, next: express.NextFunction) => {
        // https://datatracker.ietf.org/doc/html/rfc7517
        console.log("/.well-known/jwks.json - called");

        const keys = await crypto.getJwsKeys();
        res.send({ keys: keys });
    })

    app.use((req, res) => {
        // catch all
        res.send(404);
    })
}

async function start():Promise<void>{
    iam = new FileIAMAdapter("./dist/iamTempStorageFile");
    await iam.init();

    crypto = new SimpleCryptoAdapter("./test_keys/private.pem", "./test_keys/public.pem", ISSUER_NAME, logger);
    await crypto.init();

    if(!(iam as FileIAMAdapter).userCount()) {
        (iam as FileIAMAdapter).createUser("user", "superPass");
    }

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
