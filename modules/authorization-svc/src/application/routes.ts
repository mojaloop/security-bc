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
import {
    CannotCreateDuplicateAppPrivilegesError,
    CannotCreateDuplicateRoleError,
    CannotOverrideAppPrivilegesError,
    CouldNotStoreAppPrivilegesError,
    InvalidAppPrivilegesError,
    InvalidPlatformRoleError,
    NewRoleWithPrivsUsersOrAppsError
} from "../domain/errors";
import {AllPrivilegesResp} from "../domain/types";
import {ILogger} from "@mojaloop/logging-bc-logging-client-lib";
import {AppPrivileges, PlatformRole} from "@mojaloop/security-bc-public-types-lib";
import {AuthorizationAggregate} from "../domain/authorization_agg";


export class ExpressRoutes {
    private _logger:ILogger;
    private _authorizationAggregate: AuthorizationAggregate;
    private _mainRouter = express.Router();
    private _privilegesRouter = express.Router();
    private _rolesRouter = express.Router();

    constructor(authorizationAggregate: AuthorizationAggregate, logger:ILogger) {
        this._logger = logger;
        this._authorizationAggregate = authorizationAggregate;

        // main
        this._mainRouter.post("/appbootstrap", this.postAppbootstrap.bind(this));

        // privileges
        this._privilegesRouter.get("/", this.getAllAppPrivileges.bind(this));

        // roles
        this._rolesRouter.post("/", this.postPlatformRole.bind(this));
    }

    get MainRouter():express.Router{
        return this._mainRouter;
    }
    get PrivilegesRouter():express.Router{
        return this._privilegesRouter;
    }
    get RolesRouter():express.Router{
        return this._rolesRouter;
    }

    private async postAppbootstrap(req: express.Request, res: express.Response, next: express.NextFunction){
        const data: AppPrivileges = req.body as AppPrivileges;
        this._logger.debug(data);

        await this._authorizationAggregate.processAppBootstrap(data).then(()=>{
            return res.status(200).send();
        }).catch((error: Error)=>{
            if (error instanceof InvalidAppPrivilegesError) {
                return res.status(400).json({
                    status: "error",
                    msg: "Received invalid AppPrivileges"
                });
            } else if (error instanceof CannotCreateDuplicateAppPrivilegesError) {
                return res.status(400).json({
                    status: "error",
                    msg: "Received duplicate AppPrivileges"
                });
            } else if (error instanceof CannotOverrideAppPrivilegesError) {
                return res.status(400).json({
                    status: "error",
                    msg: "Received AppPrivileges with lower version than latest"
                });
            } else if (error instanceof CouldNotStoreAppPrivilegesError) {
                return res.status(500).json({
                    status: "error",
                    msg: "Could not store appPrivileges"
                });
            }else {
                return res.status(500).json({
                    status: "error",
                    msg: "unknown error"
                });
            }
        });
    }

    private async getAllAppPrivileges(req: express.Request, res: express.Response, next: express.NextFunction){
        await this._authorizationAggregate.getAllPrivileges().then((resp:AllPrivilegesResp[])=>{
            return res.send(resp);
        }).catch(()=>{
            this._logger.error("error in getAllApprPrivileged route")
            return res.status(500).json({
                status: "error",
                msg: "unknown error"
            });
        });
    }


    // roles
    private async postPlatformRole(req: express.Request, res: express.Response, next: express.NextFunction){
        const data: PlatformRole = req.body as PlatformRole;
        this._logger.debug(data);

        await this._authorizationAggregate.createLocalRole(data).then(()=>{
            return res.status(200).send();
        }).catch((error: Error)=>{
            if (error instanceof InvalidPlatformRoleError) {
                return res.status(400).json({
                    status: "error",
                    msg: "Received invalid PlatformRole"
                });
            } else if (error instanceof NewRoleWithPrivsUsersOrAppsError) {
                return res.status(400).json({
                    status: "error",
                    msg: "New roles cannot have privileges, member users or member apps"
                });
            } else if (error instanceof CannotCreateDuplicateRoleError) {
                return res.status(400).json({
                    status: "error",
                    msg: "Received duplicate PlatformRole"
                });
            } else {
                return res.status(500).json({
                    status: "error",
                    msg: "unknown error"
                });
            }
        });
    }
}
