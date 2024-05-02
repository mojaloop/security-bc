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
import { ILogger } from "@mojaloop/logging-bc-public-types-lib";
import { KeyManagementAggregate } from "../domain/aggregate";
import multer from "multer";
import { CallSecurityContext, ForbiddenError, IAuthorizationClient, ITokenHelper } from "@mojaloop/security-bc-public-types-lib";
import { CertKeyManagementPrivileges } from "../domain/privileges";

declare module "express-serve-static-core" {
    export interface Request {
        securityContext: null | CallSecurityContext;
    }
}


const upload = multer({ storage: multer.memoryStorage() });

export class KeyManagementRoutes {
    private _logger: ILogger;
    private _authorizationClient: IAuthorizationClient;
    private _tokenHelper: ITokenHelper;
    private _router = express.Router();
    private _keyMgmtAgg: KeyManagementAggregate;

    constructor(keyMgmtAgg: KeyManagementAggregate, tokenHelper: ITokenHelper, authorizationClient: IAuthorizationClient, logger: ILogger) {
        this._logger = logger.createChild(this.constructor.name);
        this._keyMgmtAgg = keyMgmtAgg;
        this._tokenHelper = tokenHelper;
        this._authorizationClient = authorizationClient;

        this._router.use(this._authenticationMiddleware.bind(this));
        // bind routes
        this._router.post("/certs/uploadCSR", upload.single("csr"), this.uploadCSR.bind(this));

        this._router.get("/certs/hubCAPubCert", this.getHubCAPubCert.bind(this));

        this._router.post("/certs/verify", this.verifyCert.bind(this));
    }

    async uploadCSR(req: express.Request, res: express.Response) {
        let csrPem = "";
        let client_id = "";
        if (req.file && req.file.buffer) {
            // Check if the CSR was uploaded as a file
            csrPem = req.file.buffer.toString();

        } else if (req.body && typeof req.body.csr === "string") {
            csrPem = req.body.csr;
        } else {
            this._logger.error("No CSR provided.");
            return res.status(400).send("No CSR provided. Please upload a CSR file.");
        }

        if (req.body.client_id && typeof req.body.client_id === "string") {
            client_id = req.body.client_id;
        } else {
            this._logger.error("No client_id provided.");
            return res.status(400).send("No client_id provided. Please provide a client_id.");
        }

        try {
            this._enforcePrivilege(req.securityContext!, CertKeyManagementPrivileges.SIGN_CSR);
            const signedCertPem = await this._keyMgmtAgg.signCSR(client_id, csrPem);
            return res.type("application/x-pem-file").send(signedCertPem);
        } catch (error) {
            this._logger.error("Failed to sign CSR.", (error as Error).message);
            return res.status(500).send("Failed to sign CSR.");
        }
    }

    async getHubCAPubCert(req: express.Request, res: express.Response) {
        try {
            this._enforcePrivilege(req.securityContext!, CertKeyManagementPrivileges.VIEW_HUB_PUB_CERTIFICATE);
            const hubCAPubCert = await this._keyMgmtAgg.getHubCAPubCert();
            return res.type("application/x-pem-file").send(hubCAPubCert);
        } catch (error) {
            this._logger.error("Failed to get Hub CA Public Certificate.", (error as Error).message);
            return res.status(500).send("Failed to get Hub CA Public Certificate.");
        }
    }

    async verifyCert(req: express.Request, res: express.Response) {
        if (!req.body.cert) {
            return res.status(400).send("No certificate provided.");
        }
        try {
            this._enforcePrivilege(req.securityContext!, CertKeyManagementPrivileges.VERIFY_CERTIFICATE);
            const cert = req.body.cert;
            const verified = await this._keyMgmtAgg.verifyCert(cert);
            return res.status(200).json({ verified });
        } catch (error) {
            this._logger.error("Failed to verify certificate.", (error as Error).message);
            return res.status(200).json({ verified: false });
        }
    }

    private async _authenticationMiddleware(
        req: express.Request,
        res: express.Response,
        next: express.NextFunction
    ) {
        const authorizationHeader = req.headers["authorization"];

        if (!authorizationHeader) return res.sendStatus(401);

        const bearer = authorizationHeader.trim().split(" ");
        if (bearer.length != 2) {
            return res.sendStatus(401);
        }

        const bearerToken = bearer[1];
        const callSecCtx: CallSecurityContext | null = await this._tokenHelper.getCallSecurityContextFromAccessToken(bearerToken);

        if (!callSecCtx) {
            return res.sendStatus(401);
        }

        req.securityContext = callSecCtx;
        return next();
    }

    private _enforcePrivilege(secCtx: CallSecurityContext, privilegeId: string): void {
        for (const roleId of secCtx.platformRoleIds) {
            if (this._authorizationClient.roleHasPrivilege(roleId, privilegeId)) {
                return;
            }
        }
        const error = new ForbiddenError(`Required privilege "${privilegeId}" not held by caller`);
        this._logger.isWarnEnabled() && this._logger.warn(error.message);
        throw error;
    }
    get Router(): express.Router {
        return this._router;
    }

}
