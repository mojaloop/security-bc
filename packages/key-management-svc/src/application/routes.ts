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
import express from "express";
import {ILogger} from "@mojaloop/logging-bc-public-types-lib";
import {KeyManagementAggregate} from "../domain/aggregate";
import multer from "multer";

const upload = multer({ storage: multer.memoryStorage() });

export class KeyManagementRoutes {
    private _logger: ILogger;
    private _router = express.Router();
    private _keyMgmtAgg: KeyManagementAggregate;
    private readonly _issuerName:string;

    constructor(keyMgmtAgg: KeyManagementAggregate, issuerName:string, logger: ILogger) {
        this._logger = logger.createChild(this.constructor.name);
        this._keyMgmtAgg = keyMgmtAgg;
        this._issuerName = issuerName;

        // bind routes
        this._router.post("/upload-csr", upload.single("csr"), this.uploadCSR.bind(this));
    }

    async uploadCSR(req: express.Request, res: express.Response) {
        let csrPem = "";
        if (req.file && req.file.buffer) {
            // Check if the CSR was uploaded as a file
            csrPem = req.file.buffer.toString();
        } else {
            this._logger.error("No CSR provided.");
            return res.status(400).send("No CSR provided. Please upload a CSR file.");
        }

        try {
            const signedCertPem = await this._keyMgmtAgg.signCSR(csrPem);
            return res.type("application/x-pem-file").send(signedCertPem);
        } catch (error) {
            this._logger.error("Failed to sign CSR.", error);
            return res.status(500).send("Failed to sign CSR.");
        }
    }

    get Router(): express.Router {
        return this._router;
    }

}
