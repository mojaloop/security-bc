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
        this._router.get("/certs/csrs", this.getAllCSRRequests.bind(this));
        this._router.get("/certs/csrs/:csrId", this.getCSRFromId.bind(this));
        this._router.get("/certs/csrs/:csrIds/multi", this.getCSRRequestsFromIds.bind(this));
        this._router.post("/certs/csrs", upload.single("csr"), this.uploadCSR.bind(this));
        this._router.post("/certs/csrs/:csrId/createCertificate", this.createCertificateFromCSR.bind(this));
        this._router.delete("/certs/csrs/:csrId", this.removeCSR.bind(this));

        this._router.get("/certs/pubCerts/hubCA", this.getHubCARootCert.bind(this));
        this._router.get("/certs/pubCerts/:certIds/multi", this.getPubCerts.bind(this));
        this._router.get("/certs/pubCerts/:certId", this.getPubCert.bind(this));

        this._router.put("/certs/pubCerts/:certId/revoke", this.revokePubCert.bind(this));

        this._router.post("/certs/verify", this.verifyCert.bind(this));
    }

    async getCSRFromId(req: express.Request, res: express.Response) {
        const csrId = req.params.csrId;
        if (!csrId) {
            return res.status(400).send("No CSR ID provided.");
        }

        try {
            const csr = await this._keyMgmtAgg.getCSRFromId(req.securityContext!, csrId);
            if (!csr) {
                return res.status(404).send(null);
            }

            return res.send(csr);
        } catch (error) {
            this._logger.error("Failed to get CSR.", (error as Error).message);
            return res.status(500).send("Failed to get CSR.");
        }
    }

    async getAllCSRRequests(req: express.Request, res: express.Response) {
        try {
            const csrRequests = await this._keyMgmtAgg.getAllCSRRequests(req.securityContext!);
            return res.status(200).json(csrRequests);
        } catch (error) {
            this._logger.error("Failed to get pending CSR approvals.", (error as Error).message);
            return res.status(500).send("Failed to get pending CSR approvals.");
        }
    }

    async getCSRRequestsFromIds(req: express.Request, res: express.Response) {
        const ids = req.params.csrIds ?? null;
        const csrIds: string[] = ids == null ? [] : ids.split(",");
        if (csrIds.length === 0) {
            return res.status(400).send("No CSR IDs provided.");
        }

        try {
            const csrRequests = await this._keyMgmtAgg.getCSRRequestsFromIds(req.securityContext!, csrIds);
            return res.status(200).json(csrRequests);
        } catch (error) {
            this._logger.error("Failed to get pending CSR approvals.", (error as Error).message);
            return res.status(500).send("Failed to get pending CSR approvals.");
        }
    }

    async uploadCSR(req: express.Request, res: express.Response) {
        let csrPem = "";
        let participantId = "";
        if (req.file && req.file.buffer) {
            // Check if the CSR was uploaded as a file
            csrPem = req.file.buffer.toString();

        } else if (req.body && typeof req.body.csr === "string") {
            csrPem = req.body.csr;
        } else {
            this._logger.error("No CSR provided.");
            return res.status(400).send("No CSR provided. Please upload a CSR file.");
        }

        // participant should already been verified by participant-bc
        if (req.body.participantId && typeof req.body.participantId === "string") {
            participantId = req.body.participantId;
        } else {
            this._logger.error("No participantId provided.");
            return res.status(400).send("No participantId provided. Please provide a participantId.");
        }

        try {
            const csrRequest = await this._keyMgmtAgg.uploadCSR(req.securityContext!, participantId, csrPem);
            return res.status(200).send(csrRequest);
        } catch (error) {
            const errMessage = `${(error as Error).message}`;
            this._logger.error(errMessage);
            return res.status(500).send(errMessage);
        }
    }

    async createCertificateFromCSR(req: express.Request, res: express.Response) {
        const csrId = req.params.csrId;
        if (!csrId) {
            return res.status(400).send("No CSR ID provided.");
        }

        try {
            const pubCert = await this._keyMgmtAgg.createCertificateFromCSR(req.securityContext!, csrId);
            return res.status(200).send(pubCert);
        } catch (error) {
            this._logger.error((error as Error).message);
            return res.status(500).send((error as Error).message);
        }
    }

    async removeCSR(req: express.Request, res: express.Response) {
        const csrId = req.params.csrId;
        if (!csrId) {
            return res.status(400).send("No CSR ID provided.");
        }

        try {
            await this._keyMgmtAgg.removeCSR(req.securityContext!, csrId);
            return res.status(200).send("CSR Request is removed.");
        } catch (error) {
            this._logger.error("Failed to remove CSR Request.", (error as Error).message);
            return res.status(500).send("Failed to remove CSR Request.");
        }
    }

    async getHubCARootCert(req: express.Request, res: express.Response) {
        try {
            const hubCAPubCert = await this._keyMgmtAgg.getHubCAPubCert(req.securityContext!);
            if (!hubCAPubCert) {
                return res.status(404).send(null);
            }
            return res.send(hubCAPubCert);
        } catch (error) {
            this._logger.error("Failed to get Hub CA Public Certificate.", (error as Error).message);
            return res.status(500).send("Failed to get Hub CA Public Certificate.");
        }
    }

    async getPubCert(req: express.Request, res: express.Response) {
        const certId = req.params.certId;
        if (!certId) {
            return res.status(400).send("No certId provided.");
        }

        try {
            const cert = await this._keyMgmtAgg.getPubCert(req.securityContext!, certId);
            if (!cert) {
                return res.status(404).send(null);
            }
            return res.status(200).json(cert);
        } catch (error) {
            this._logger.error("Failed to get participant public certificate.", (error as Error).message);
            return res.status(500).send("Failed to get participant public certificate.");
        }
    }

    async getPubCerts(req: express.Request, res: express.Response) {
        const certIds = req.params.certIds ?? null;
        const certIdsList: string[] = certIds == null ? [] : certIds.split(",");
        if (certIdsList.length === 0) {
            return res.status(400).send("No participantIds provided.");
        }

        try {
            const pubCerts = await this._keyMgmtAgg.getPubCerts(req.securityContext!, certIdsList);
            return res.status(200).json(pubCerts);
        } catch (error) {
            this._logger.error("Failed to get public certificates.", (error as Error).message);
            return res.status(500).send("Failed to get public certificates.");
        }
    }

    async revokePubCert(req: express.Request, res: express.Response) {
        this._logger.debug("Revoking public certificate.");
        const certId = req.params.certId;
        const reason = req.body.reason;

        if (!certId) {
            return res.status(400).send("No certId provided.");
        }

        if (!reason) {
            return res.status(400).send("No reason provided.");
        }

        try {
            await this._keyMgmtAgg.revokePubCert(req.securityContext!, certId, reason);
            return res.status(200).send("Certificate revoked.");
        } catch (error) {
            const errMessage = `${(error as Error).message}`;
            this._logger.error(errMessage);
            return res.status(500).send(errMessage);
        }
    }

    async verifyCert(req: express.Request, res: express.Response) {
        if (!req.body.cert) {
            return res.status(400).send("No certificate provided.");
        }
        try {
            const cert = req.body.cert;
            const verified = await this._keyMgmtAgg.verifyCert(req.securityContext!, cert);
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

    get Router(): express.Router {
        return this._router;
    }

}
