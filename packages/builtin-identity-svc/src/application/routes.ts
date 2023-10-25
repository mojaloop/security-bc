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
import {IdentityManagementAggregate} from "../domain/identity_management_agg";
import {TokenHelper} from "@mojaloop/security-bc-client-lib";
import {
    CallSecurityContext, ForbiddenError, UserLoginResponse, LoginResponse,
    MakerCheckerViolationError,
    UnauthorizedError
} from "@mojaloop/security-bc-public-types-lib";
import {
    IBuiltinIamApplicationCreate, IBuiltinIamUser,
    IBuiltinIamUserCreate
} from "@mojaloop/security-bc-public-types-lib/dist/builtin_identity";
import {InvalidRequestError, UserNotFoundFoundError} from "../domain/errors";

// Extend express request to include our security fields
declare module "express-serve-static-core" {
    export interface Request {
        securityContext: null | CallSecurityContext;
    }
}

export class IdentifyManagementRoutes {
    private _logger: ILogger;
    private _router = express.Router();
    private _tokenHelper: TokenHelper;
    private _aggregate: IdentityManagementAggregate;

    constructor(agg: IdentityManagementAggregate, tokenHelper: TokenHelper, logger: ILogger) {
        this._logger = logger.createChild(this.constructor.name);
        this._tokenHelper = tokenHelper;
        this._aggregate = agg;

        // logins don't require authentication
        this._router.post("/login", this._handlePostLogin.bind(this));

        // inject authentication - all request below this require a valid token
        this._router.use(this._authenticationMiddleware.bind(this));

        // bind user routes
        this._router.post("/users", this._handlePostUser.bind(this));
        this._router.get("/users", this._handleGetAllUsers.bind(this));
        this._router.get("/users/:id", this._handleGetUser.bind(this));
        this._router.post("/users/:id/change_password", this._handleChangeUserPassword.bind(this));
        this._router.post("/users/:id/enable", this._handleEnableUser.bind(this));
        this._router.post("/users/:id/disable", this._handleDisableUser.bind(this));
        this._router.post("/users/:id/roles/", this._handlePostUserRole.bind(this));
        this._router.delete("/users/:id/roles/:role_id", this._handleDeleteUserRole.bind(this));
        // this._router.patch("/users/:id", this._handlePatchUser.bind(this));
        //this._router.post("/users/:id/reset_password", this._handleResetPassword.bind(this));

        // bind app routes
        this._router.post("/apps", this._handlePostApp.bind(this));
        this._router.get("/apps", this._handleGetAllApps.bind(this));
        this._router.get("/apps/:id", this._handleGetApp.bind(this));
        this._router.post("/apps/:id/change_password", this._handleChangeAppPassword.bind(this));
        this._router.post("/apps/:id/enable", this._handleEnableApp.bind(this));
        this._router.post("/apps/:id/disable", this._handleDisableApp.bind(this));
        this._router.post("/apps/:id/roles/", this._handlePostAppRole.bind(this));
        this._router.delete("/apps/:id/roles/:role_id", this._handleDeleteAppRole.bind(this));
    }

    get Router(): express.Router {
        return this._router;
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
        } else if (err instanceof MakerCheckerViolationError || err instanceof ForbiddenError) {
            this._logger.warn(err.message);
            res.status(403).json({
                status: "error",
                msg: err.message,
            });
            handled = true;
        } else if (err instanceof UserNotFoundFoundError) {
            res.status(404).json({
                status: "error",
                msg: "Not found.",
            });
            handled = true;
        }

        return handled;
    }

    private async _handlePostLogin(req: express.Request, res: express.Response){
        const grant_type = req.body.grant_type || ""; //safe default that breaks in the grant check below
        const client_id = req.body.client_id;
        const client_secret = req.body.client_secret;
        const username = req.body.username;
        const password = req.body.password;

        // should return a LoginResponse
        try {
            let loginResp:UserLoginResponse | LoginResponse | null;
            if(grant_type.toUpperCase() === "password".toUpperCase()) {
                loginResp = await this._aggregate.loginUser(username, password, client_id);
            }else if(grant_type.toUpperCase() === "client_credentials".toUpperCase()) {
                loginResp = await this._aggregate.loginApp(client_id, client_secret);
            }else {
                return res.status(401).send("Unsupported grant_type");
            }

            if(!loginResp){
               res.status(401).send();
               return;
            }

            res.send(loginResp);
            return;
        } catch (err: any) {
            if (err instanceof Error) {
                res.status(500).json({
                    status: "error",
                    msg: `Internal error`,
                });
            } else {
                this._logger.error(err);
                res.status(500).json({
                    status: "error",
                    msg: err.message,
                });
            }
            return; // lint pleaser
        }
    }

    /* User routes */

    private async _handleGetAllUsers(req: express.Request, res: express.Response){
        this._logger.debug(`Get users...`);
        const type = req.query.type as string;
        const id = req.query.id as string;
        const name = req.query.name as string;
        const stateStr = req.query.enabled as string;
        const state:boolean|undefined = stateStr!=undefined ? stateStr==="true" : undefined;

        try {
            const users = await this._aggregate.getUsers(req.securityContext!, type, id, name, state);

            if(!users || users.length<=0){
                res.status(404).send();
                return;
            }
            res.send(users);
            return;
        } catch (err: any) {
            if (this._handleUnauthorizedError(err, res)) return;

            if (err instanceof Error) {
                res.status(500).json({
                    status: "error",
                    msg: `Unable to get users. ${err.message}.`,
                });
            } else {
                this._logger.error(err);
                res.status(500).json({
                    status: "error",
                    msg: err.message,
                });
            }
        }
    }

    private async _handleGetUser(req: express.Request, res: express.Response){
        const id = req.params["id"] ?? null;
        this._logger.debug(`Get user with id: ${id}...`);

        try {
            const user = await this._aggregate.getUserById(req.securityContext!, id);

            if(!user){
                res.status(404).send();
                return;
            }

            res.send(user);
            return;
        } catch (err: any) {
            if (this._handleUnauthorizedError(err, res)) return;

            if (err instanceof Error) {
                res.status(500).json({
                    status: "error",
                    msg: `Unable get user`,
                });
            } else {
                this._logger.error(err);
                res.status(500).json({
                    status: "error",
                    msg: "Unknown", // don't leak info
                });
            }
        }
    }

    private async _handlePostUser(req: express.Request, res: express.Response){
        const userCreateData: IBuiltinIamUserCreate = req.body;
        this._logger.debug(`Creating User '${userCreateData.email}'...`);

        try {
            await this._aggregate.registerUser(req.securityContext!, userCreateData);
            this._logger.debug(`Created user with username: ${userCreateData.email}.`);
            res.send({});
        } catch (err: any) {
            if (this._handleUnauthorizedError(err, res)) return;

            if (err instanceof InvalidRequestError) {
                res.status(400).json({
                    status: "error",
                    msg: `${err.message}.`,
                });
            } else if (err instanceof Error) {
                res.status(500).json({
                    status: "error",
                    msg: `Unable to store user. ${err.message}.`,
                });
            } else {
                this._logger.error(err);
                res.status(500).json({
                    status: "error",
                    msg: err.message,
                });
            }
        }
    }

    private async _handleChangeUserPassword(req: express.Request, res: express.Response){
        // make sure we detect what changed
        const id = req.params["id"] ?? null;
        const currentPass = req.body.currentPassword;
        const newPass = req.body.newPassword;
        this._logger.debug(`User '${id}' requested password change...`);

        try {
            await this._aggregate.changeUserPassword(req.securityContext!, id, currentPass, newPass);
            this._logger.debug(`Password changed for user: ${id}.`);
            res.send({});
        } catch (err: any) {
            if (this._handleUnauthorizedError(err, res)) return;

            if (err instanceof InvalidRequestError) {
                res.status(400).json({
                    status: "error",
                    msg: `${err.message}.`,
                });
            } else if (err instanceof Error) {
                res.status(500).json({
                    status: "error",
                    msg: `Unable change user password. ${err.message}.`,
                });
            } else {
                this._logger.error(err);
                res.status(500).json({
                    status: "error",
                    msg: "Unknown", // don't leak info
                });
            }
        }
    }

    private async _handleEnableUser(req: express.Request, res: express.Response){
        // make sure we detect what changed
        const id = req.params["id"] ?? null;
        this._logger.debug(`Enable User requested for user '${id}'...`);

        try {
            await this._aggregate.enableUser(req.securityContext!, id);
            this._logger.debug(`User: ${id} enabled.`);
            res.send({});
        } catch (err: any) {
            if (this._handleUnauthorizedError(err, res)) return;

            if (err instanceof InvalidRequestError) {
                res.status(400).json({
                    status: "error",
                    msg: `${err.message}.`,
                });
            } else if (err instanceof Error) {
                res.status(500).json({
                    status: "error",
                    msg: `Unable to enable user. ${err.message}.`,
                });
            } else {
                this._logger.error(err);
                res.status(500).json({
                    status: "error",
                    msg: "Unknown", // don't leak info
                });
            }
        }
    }

    private async _handleDisableUser(req: express.Request, res: express.Response){
        // make sure we detect what changed
        const id = req.params["id"] ?? null;
        this._logger.debug(`Disable User requested for user '${id}'...`);

        try {
            await this._aggregate.disableUser(req.securityContext!, id);
            this._logger.debug(`User: ${id} disabled.`);
            res.send({});
        } catch (err: any) {
            if (this._handleUnauthorizedError(err, res)) return;

            if (err instanceof InvalidRequestError) {
                res.status(400).json({
                    status: "error",
                    msg: `${err.message}.`,
                });
            } else if (err instanceof Error) {
                res.status(500).json({
                    status: "error",
                    msg: `Unable to disable user. ${err.message}.`,
                });
            } else {
                this._logger.error(err);
                res.status(500).json({
                    status: "error",
                    msg: "Unknown", // don't leak info
                });
            }
        }
    }

    private async _handleDeleteUserRole(req: express.Request, res: express.Response){
        // make sure we detect what changed
        const id = req.params["id"] ?? null;
        const roleId = req.params["role_id"] ?? null;
        this._logger.debug(`Remove role '${roleId}' from user '${id}'...`);

        try {
            await this._aggregate.removeRoleFromUser(req.securityContext!, id, roleId);
            this._logger.debug(`Role '${roleId}' removed from user: ${id}.`);
            res.send({});
        } catch (err: any) {
            if (this._handleUnauthorizedError(err, res)) return;

            if (err instanceof InvalidRequestError) {
                res.status(400).json({
                    status: "error",
                    msg: `${err.message}.`,
                });
            } else if (err instanceof Error) {
                res.status(500).json({
                    status: "error",
                    msg: `Unable to remove user role. ${err.message}.`,
                });
            } else {
                this._logger.error(err);
                res.status(500).json({
                    status: "error",
                    msg: "Unknown", // don't leak info
                });
            }
        }
    }

    private async _handlePostUserRole(req: express.Request, res: express.Response){
        // make sure we detect what changed
        const id = req.params["id"] ?? null;

        // expects array or role ids object like: [{roleId:string}]

        if(!req.body || !req.body || !Array.isArray(req.body) || req.body.length<=0) {
            res.status(400).json({ status: "error", msg: "Invalid request"});
            return;
        }

        let rolesIds:string[];
        try{
            rolesIds = req.body.map(value => value.roleId);
        }catch(e){
            res.status(400).json({ status: "error", msg: "Invalid request"});
            return;
        }

        this._logger.debug(`Adding roles to user '${id}'...`);

        try {
            await this._aggregate.addRolesToUser(req.securityContext!, id, rolesIds);
            this._logger.debug(`Role added to user: ${id}.`);
            res.send({});
        } catch (err: any) {
            if (this._handleUnauthorizedError(err, res)) return;

            if (err instanceof InvalidRequestError) {
                res.status(400).json({
                    status: "error",
                    msg: `${err.message}.`,
                });
            } else if (err instanceof Error) {
                res.status(500).json({
                    status: "error",
                    msg: `Unable to add user role. ${err.message}.`,
                });
            } else {
                this._logger.error(err);
                res.status(500).json({
                    status: "error",
                    msg: "Unknown", // don't leak info
                });
            }
        }
    }


    /* Application routes */

    private async _handleGetAllApps(req: express.Request, res: express.Response){
        this._logger.debug(`Get apps...`);
        const clientId = req.query.clientId as string;

        const canLoginStr = req.query.canLogin as string;
        const canLogin:boolean|undefined = canLoginStr!=undefined ? canLoginStr==="true" : undefined;

        const enabledStr = req.query.enabled as string;
        const enabled:boolean|undefined = enabledStr!=undefined ? enabledStr==="true" : undefined;

        try {
            const apps = await this._aggregate.getApplications(req.securityContext!, clientId, canLogin, enabled);
            if(!apps || apps.length<=0){
                res.status(404).send();
                return;
            }

            res.send(apps);
            return;
        } catch (err: any) {
            if (this._handleUnauthorizedError(err, res)) return;

            if (err instanceof Error) {
                res.status(500).json({
                    status: "error",
                    msg: `Unable to get apps. ${err.message}.`,
                });
            } else {
                this._logger.error(err);
                res.status(500).json({
                    status: "error",
                    msg: err.message,
                });
            }
        }
    }

    private async _handleGetApp(req: express.Request, res: express.Response){
        const clientId = req.params["id"] ?? null;
        this._logger.debug(`Get app with id: ${clientId}...`);

        try {
            const app = await this._aggregate.getApplicationById(req.securityContext!, clientId);

            if(!app){
                res.status(404).send();
                return;
            }

            res.send(app);
            return;
        } catch (err: any) {
            if (this._handleUnauthorizedError(err, res)) return;

            if (err instanceof Error) {
                res.status(500).json({
                    status: "error",
                    msg: `Unable get application`,
                });
            } else {
                this._logger.error(err);
                res.status(500).json({
                    status: "error",
                    msg: "Unknown", // don't leak info
                });
            }
        }
    }

    private async _handlePostApp(req: express.Request, res: express.Response){
        const createData: IBuiltinIamApplicationCreate = req.body;
        this._logger.debug(`Creating App '${createData.clientId}'...`);

        try {
            await this._aggregate.registerApplication(req.securityContext!, createData);
            this._logger.debug(`Created app with clientId: ${createData.clientId}.`);
            res.send({});
        } catch (err: any) {
            if (this._handleUnauthorizedError(err, res)) return;

            if (err instanceof InvalidRequestError) {
                res.status(400).json({
                    status: "error",
                    msg: `${err.message}.`,
                });
            } else if (err instanceof Error) {
                res.status(500).json({
                    status: "error",
                    msg: `Unable to store app. ${err.message}.`,
                });
            } else {
                this._logger.error(err);
                res.status(500).json({
                    status: "error",
                    msg: err.message,
                });
            }
        }
    }

    private async _handleChangeAppPassword(req: express.Request, res: express.Response){
        const id = req.params["id"] ?? null;
        const currentClientSecret = req.body.currentClientSecret;
        const newClientSecret = req.body.newClientSecret;
        this._logger.debug(`App '${id}' requested client secret change...`);

        try {
            await this._aggregate.changeApplicationClientSecret(req.securityContext!, id, currentClientSecret, newClientSecret);
            this._logger.debug(`Client secret changed for app: ${id}.`);
            res.send({});
        } catch (err: any) {
            if (this._handleUnauthorizedError(err, res)) return;

            if (err instanceof InvalidRequestError) {
                res.status(400).json({
                    status: "error",
                    msg: `${err.message}.`,
                });
            } else if (err instanceof Error) {
                res.status(500).json({
                    status: "error",
                    msg: `Unable change app client secret. ${err.message}.`,
                });
            } else {
                this._logger.error(err);
                res.status(500).json({
                    status: "error",
                    msg: "Unknown", // don't leak info
                });
            }
        }
    }

    private async _handleEnableApp(req: express.Request, res: express.Response){
        // make sure we detect what changed
        const id = req.params["id"] ?? null;
        this._logger.debug(`Enable app requested for app '${id}'...`);

        try {
            await this._aggregate.enableApp(req.securityContext!, id);
            this._logger.debug(`app: ${id} enabled.`);
            res.send({});
        } catch (err: any) {
            if (this._handleUnauthorizedError(err, res)) return;

            if (err instanceof InvalidRequestError) {
                res.status(400).json({
                    status: "error",
                    msg: `${err.message}.`,
                });
            } else if (err instanceof Error) {
                res.status(500).json({
                    status: "error",
                    msg: `Unable to enable app. ${err.message}.`,
                });
            } else {
                this._logger.error(err);
                res.status(500).json({
                    status: "error",
                    msg: "Unknown", // don't leak info
                });
            }
        }
    }

    private async _handleDisableApp(req: express.Request, res: express.Response){
        // make sure we detect what changed
        const id = req.params["id"] ?? null;
        this._logger.debug(`Disable app requested for app '${id}'...`);

        try {
            await this._aggregate.disableApp(req.securityContext!, id);
            this._logger.debug(`App: ${id} disabled.`);
            res.send({});
        } catch (err: any) {
            if (this._handleUnauthorizedError(err, res)) return;

            if (err instanceof InvalidRequestError) {
                res.status(400).json({
                    status: "error",
                    msg: `${err.message}.`,
                });
            } else if (err instanceof Error) {
                res.status(500).json({
                    status: "error",
                    msg: `Unable to disable app. ${err.message}.`,
                });
            } else {
                this._logger.error(err);
                res.status(500).json({
                    status: "error",
                    msg: "Unknown", // don't leak info
                });
            }
        }
    }

    private async _handleDeleteAppRole(req: express.Request, res: express.Response){
        // make sure we detect what changed
        const id = req.params["id"] ?? null;
        const roleId = req.params["role_id"] ?? null;
        this._logger.debug(`Remove role '${roleId}' from app '${id}'...`);

        try {
            await this._aggregate.removeRoleFromApp(req.securityContext!, id, roleId);
            this._logger.debug(`Role '${roleId}' removed from app: ${id}.`);
            res.send({});
        } catch (err: any) {
            if (this._handleUnauthorizedError(err, res)) return;

            if (err instanceof InvalidRequestError) {
                res.status(400).json({
                    status: "error",
                    msg: `${err.message}.`,
                });
            } else if (err instanceof Error) {
                res.status(500).json({
                    status: "error",
                    msg: `Unable to remove app role. ${err.message}.`,
                });
            } else {
                this._logger.error(err);
                res.status(500).json({
                    status: "error",
                    msg: "Unknown", // don't leak info
                });
            }
        }
    }

    private async _handlePostAppRole(req: express.Request, res: express.Response){
        // make sure we detect what changed
        const id = req.params["id"] ?? null;

        // expects array or role ids object like: [{roleId:string}]

        if(!req.body || !req.body || !Array.isArray(req.body) || req.body.length<=0) {
            res.status(400).json({ status: "error", msg: "Invalid request"});
            return;
        }

        let rolesIds:string[];
        try{
            rolesIds = req.body.map(value => value.roleId);
        }catch(e){
            res.status(400).json({ status: "error", msg: "Invalid request"});
            return;
        }

        this._logger.debug(`Adding roles to app '${id}'...`);

        try {
            await this._aggregate.addRolesToApp(req.securityContext!, id, rolesIds);
            this._logger.debug(`Role added to app: ${id}.`);
            res.send({});
        } catch (err: any) {
            if (this._handleUnauthorizedError(err, res)) return;

            if (err instanceof InvalidRequestError) {
                res.status(400).json({
                    status: "error",
                    msg: `${err.message}.`,
                });
            } else if (err instanceof Error) {
                res.status(500).json({
                    status: "error",
                    msg: `Unable to add app role. ${err.message}.`,
                });
            } else {
                this._logger.error(err);
                res.status(500).json({
                    status: "error",
                    msg: "Unknown", // don't leak info
                });
            }
        }
    }


}
