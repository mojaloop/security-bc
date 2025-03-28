/*****
License
--------------
Copyright © 2020-2025 Mojaloop Foundation
The Mojaloop files are made available by the Mojaloop Foundation under the Apache License, Version 2.0 (the "License") and you may not use these files except in compliance with the License. You may obtain a copy of the License at

 http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, the Mojaloop files are distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.

Contributors
--------------
This is the official list of the Mojaloop project contributors for this file.
Names of the original copyright holders (individuals or organizations)
should be listed with a '*' in the first column. People who have
contributed from an organization can be listed under the organization
that actually holds the copyright for their contributions (see the
Mojaloop Foundation for an example). Those individuals should have
their names indented and be marked with a '-'. Email address can be added
optionally within square brackets <email>.

* Mojaloop Foundation
- Name Surname <name.surname@mojaloop.io>

* Crosslake
- Pedro Sousa Barreto <pedrob@crosslaketech.com>
*****/

"use strict";

import express from "express";
import {
    BoundedContextsPrivilegesNotFoundError,
    CannotCreateDuplicateBcPrivilegesError,
    CannotCreateDuplicateRoleError,
    CannotOverrideBcPrivilegesError,
    CouldNotStoreBcPrivilegesError,
    InvalidBcPrivilegesError,
    InvalidPlatformRoleError,
    NewRoleWithPrivsUsersOrBcsError,
    PlatformRoleNotFoundError,
    PrivilegeNotFoundError
} from "../domain/errors";
import {PrivilegesByRole} from "../domain/types";
import {ILogger} from "@mojaloop/logging-bc-public-types-lib";
import {
    BoundedContextPrivileges,
    CallSecurityContext,
    ForbiddenError,
    ITokenHelper,
    MakerCheckerViolationError,
    PlatformRole,
    PrivilegeWithOwnerBcInfo,
    UnauthorizedError
} from "@mojaloop/security-bc-public-types-lib";
import {AuthorizationAggregate} from "../domain/authorization_agg";

// Extend express request to include our security fields
declare module "express-serve-static-core" {
    export interface Request {
        securityContext: null | CallSecurityContext;
    }
}

export class ExpressRoutes {
    private _logger:ILogger;
    private _tokenHelper: ITokenHelper;
    private _authorizationAggregate: AuthorizationAggregate;
    private _mainRouter = express.Router();
    private _privilegesRouter = express.Router();
    private _rolesRouter = express.Router();

    constructor(authorizationAggregate: AuthorizationAggregate, tokenHelper: ITokenHelper, logger:ILogger) {
        this._logger = logger.createChild(this.constructor.name);
        this._tokenHelper = tokenHelper;
        this._authorizationAggregate = authorizationAggregate;

        // inject authentication - all request below this require a valid token
        this._mainRouter.use(this._authenticationMiddleware.bind(this));

        // main
        this._mainRouter.post("/bootstrap", this.postBootstrap.bind(this));
        this._mainRouter.get("/appRoles", this.getAppRoles.bind(this));

        // privileges
        this._privilegesRouter.get("/", this.getAllAppPrivileges.bind(this));

        // roles
        this._rolesRouter.get("/", this.getAllPlatformRole.bind(this));
        this._rolesRouter.post("/", this.postPlatformRole.bind(this));
        this._rolesRouter.post("/:roleId/add_privileges", this.postAddPrivsToPlatformRole.bind(this));
        this._rolesRouter.post("/:roleId/remove_privileges", this.postRemovePrivsFromPlatformRole.bind(this));
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
        const callSecCtx:  CallSecurityContext | null = await this._tokenHelper.getCallSecurityContextFromAccessToken(bearerToken);

        if(!callSecCtx){
            return res.sendStatus(401);
        }

        req.securityContext = callSecCtx;
        return next();
    }

    private _handleUnauthorizedError(err: Error, res: express.Response): boolean {
        let handled = false;
        if (err instanceof UnauthorizedError) {
            this._logger.warn(err.message);
            res.status(401).json({
                status: "error",
                msg: err.message,
            });
            handled = true;
        } else if (err instanceof ForbiddenError) {
            this._logger.warn(err.message);
            res.status(403).json({
                status: "error",
                msg: err.message,
            });
            handled = true;
        }

        return handled;
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

    private async postBootstrap(req: express.Request, res: express.Response){
        const data: BoundedContextPrivileges = req.body as BoundedContextPrivileges;
        this._logger.debug(data);

        await this._authorizationAggregate.processBcBootstrap(req.securityContext!, data).then(()=>{
            return res.status(200).send();
        }).catch((error: Error)=>{
            if (this._handleUnauthorizedError(error, res)) return;

            if (error instanceof InvalidBcPrivilegesError) {
                return res.status(400).json({
                    status: "error",
                    msg: "Received invalid BoundedContextPrivileges"
                });
            } else if (error instanceof CannotCreateDuplicateBcPrivilegesError) {
                return res.status(409).json({
                    status: "error",
                    msg: "Received duplicate BoundedContextPrivileges"
                });
            } else if (error instanceof CannotOverrideBcPrivilegesError) {
                return res.status(400).json({
                    status: "error",
                    msg: "Received BoundedContextPrivileges with lower version than latest"
                });
            } else if (error instanceof CouldNotStoreBcPrivilegesError) {
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

    private async getAppRoles(req: express.Request, res: express.Response){
        const bcName = req.query["bcName"] ?? null;

        if(!bcName){
            return res.status(400).json({
                status: "error",
                msg: "invalid bcName"
            });
        }

        await this._authorizationAggregate.getBcPrivilegesByRole(
            req.securityContext!,
            bcName.toString(),
        ).then((resp:PrivilegesByRole)=>{
            return res.send(resp);
        }).catch((error: Error)=>{
            if (this._handleUnauthorizedError(error, res)) return;
            if (error instanceof BoundedContextsPrivilegesNotFoundError) {
                return res.status(404).json({
                    status: "error",
                    msg: "Application Privileges not found"
                });
            }else{
                this._logger.error("error in getAppRoles route");
                return res.status(500).json({
                    status: "error",
                    msg: "unknown error"
                });
            }
        });
        return;
    }

    private async getAllAppPrivileges(req: express.Request, res: express.Response){
        await this._authorizationAggregate.getAllPrivileges(req.securityContext!).then((resp:PrivilegeWithOwnerBcInfo[])=>{
            return res.send(resp);
        }).catch((error: Error)=>{
            if (this._handleUnauthorizedError(error, res)) return;
            this._logger.error("error in getAllAppPrivileges route");
            return res.status(500).json({
                status: "error",
                msg: "unknown error"
            });
        });
    }


    // roles
    private async getAllPlatformRole(req: express.Request, res: express.Response){
        await this._authorizationAggregate.getAllRoles(req.securityContext!).then((resp:PlatformRole[])=>{
            return res.send(resp);
        }).catch((error: Error)=>{
            if (this._handleUnauthorizedError(error, res)) return;
            this._logger.error("error in getAllPlatformRole route");
            return res.status(500).json({
                status: "error",
                msg: "unknown error"
            });
        });
    }

    private async postPlatformRole(req: express.Request, res: express.Response){
        const data: PlatformRole = req.body as PlatformRole;
        this._logger.debug(data);

        await this._authorizationAggregate.createPlatformRole(req.securityContext!, data).then((roleId:string)=>{
            return res.status(200).send({roleId: roleId});
        }).catch((error: Error)=>{
            if (this._handleUnauthorizedError(error, res)) return;
            if (error instanceof InvalidPlatformRoleError) {
                return res.status(400).json({
                    status: "error",
                    msg: "Received invalid PlatformRole"
                });
            } else if (error instanceof NewRoleWithPrivsUsersOrBcsError) {
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

    private async postAddPrivsToPlatformRole(req: express.Request, res: express.Response){
        const roleId = req.params["roleId"] ?? null;
        // body is supposed to be an array of strings
        const data: string[] = req.body as string[];
        this._logger.debug(`Add privs to role: ${roleId}, privIds: ${data}`);

        if(!roleId){
            return res.status(400).json({
                status: "error",
                msg: "invalid PlatformRole"
            });
        }

        if(!Array.isArray(data) || data.length<=0){
            return res.status(400).json({
                status: "error",
                msg: "invalid privilege id list in body"
            });
        }

        await this._authorizationAggregate.associatePrivilegesToRole(req.securityContext!, data, roleId).then(()=>{
            return res.status(200).send();
        }).catch((error: Error)=>{
            if (this._handleUnauthorizedError(error, res)) return;
            if (error instanceof PlatformRoleNotFoundError) {
                return res.status(404).json({
                    status: "error",
                    msg: "PlatformRole not found"
                });
            } else if (error instanceof PrivilegeNotFoundError) {
                return res.status(400).json({
                    status: "error",
                    msg: "Privilege not found"
                });
            } else {
                return res.status(500).json({
                    status: "error",
                    msg: "unknown error"
                });
            }
        });
        return;
    }

    private async postRemovePrivsFromPlatformRole(req: express.Request, res: express.Response){
        const roleId = req.params["roleId"] ?? null;
        // body is supposed to be an array of strings
        const data: string[] = req.body as string[];
        this._logger.debug(`Remove privs from role: ${roleId}, privIds: ${data}`);

        if(!roleId){
            return res.status(400).json({
                status: "error",
                msg: "invalid PlatformRole"
            });
        }

        if(!Array.isArray(data) || data.length<=0){
            return res.status(400).json({
                status: "error",
                msg: "invalid privilege id list in body"
            });
        }

        await this._authorizationAggregate.dissociatePrivilegesFromRole(req.securityContext!, data, roleId).then(()=>{
            return res.status(200).send();
        }).catch((error: Error)=>{
            if (this._handleUnauthorizedError((error as Error), res)) return;
            if (error instanceof PlatformRoleNotFoundError) {
                return res.status(404).json({
                    status: "error",
                    msg: "PlatformRole not found"
                });
            } else if (error instanceof PrivilegeNotFoundError) {
                return res.status(400).json({
                    status: "error",
                    msg: "Privilege not found"
                });
            } else {
                return res.status(500).json({
                    status: "error",
                    msg: "unknown error"
                });
            }
        });
        return;
    }
}
