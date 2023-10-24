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
import bcrypt from "bcrypt";
import {ILogger} from "@mojaloop/logging-bc-public-types-lib";
import {IBuiltinIdentityRepository} from "./interfaces";
import {
    IBuiltinIamApplication, IBuiltinIamApplicationCreate,
    IBuiltinIamUser,
    IBuiltinIamUserCreate,

} from "@mojaloop/security-bc-public-types-lib/dist/builtin_identity";
import {
    CallSecurityContext,
    ForbiddenError,
    UserLoginResponse, ParticipantRole, LoginResponse,
    IAuthorizationClient, UnauthorizedError, UserType
} from "@mojaloop/security-bc-public-types-lib";
import {BuiltinIdentityPrivileges} from "./privileges";
import {InvalidRequestError} from "./errors";

const BCRYPT_SALT_ROUNDS = 12;
const PASSWORD_MIN_LENGTH = 6;
const USERNAME_MIN_LENGTH = 3; // for users and apps
const DEFAULT_EXPIRY_SECS = 60*60;

export class IdentityManagementAggregate{
    private _logger:ILogger;
    private _authorizationClient: IAuthorizationClient;
    private _repo: IBuiltinIdentityRepository;

    constructor(logger: ILogger, repo: IBuiltinIdentityRepository, authorizationClient: IAuthorizationClient) {
        this._logger = logger.createChild(this.constructor.name);

        this._repo = repo;
        this._authorizationClient = authorizationClient;
    }

    async init(): Promise<void> {
        await this._repo.init();
    }

    private _enforcePrivilege(secCtx: CallSecurityContext, privName: string): void {
        for (const roleId of secCtx.platformRoleIds || []) {
            if (this._authorizationClient.roleHasPrivilege(roleId, privName)) return;
        }
        throw new ForbiddenError(`Required privilege "${privName}" not held by caller`);
    }

    private _passwordHashMatches(password:string, passwordHash:string): boolean{
        return bcrypt.compareSync(password, passwordHash);
    }

    async loginUser(username:string, password:string, client_id:string):Promise<UserLoginResponse | null>{
        if(!username || !password || !client_id){
            this._logger.warn("Invalid params on loginUser");
            return null;
        }

        const app = await this._repo.fetchApp(client_id);
        if(!app){
            this._logger.warn("Invalid client_id on loginUser");
            return null;
        }

        const user = await this._repo.fetchUser(username);
        if(!user || !user.enabled || !user.passwordHash){
            this._logger.warn("Invalid user or password hash on loginUser");
            return null;
        }

        if(!this._passwordHashMatches(password, user.passwordHash)){
            // password mismatch
            return null;
        }

        return {
            scope: null,
            userType: user.userType,
            platformRoles: user.platformRoles || [],
            participantRoles: user.participantRoles || [],
            expires_in: DEFAULT_EXPIRY_SECS
        };
    }

    async loginApp(client_id:string, client_secret:string | null):Promise<LoginResponse | null>{
        if(!client_id || !client_secret){
            this._logger.warn("Invalid params on loginApp");
            return null;
        }

        const app = await this._repo.fetchApp(client_id);
        if(!app){
            this._logger.warn("Invalid client_id on loginApp (not found)");
            return null;
        }

        if(!app.enabled  || !app.canLogin || !app.clientSecretHash){
            this._logger.warn("Disabled app, app that cannot login or invalid clientSecretHash in loginApp");
            return null;
        }

        if(!this._passwordHashMatches(client_secret, app.clientSecretHash)){
            // password mismatch
            return null;
        }

        return {
            scope: null,
            platformRoles: app.platformRoles || [],
            expires_in: DEFAULT_EXPIRY_SECS
        };
    }


    private _removeUserPrivateInfo(user: IBuiltinIamUser): IBuiltinIamUser{
        if(Object.hasOwn(user, "passwordHash")) delete user.passwordHash;

        // remove other information we don't want to send out on reads
        return user;
    }

    private _removeAppPrivateInfo(app: IBuiltinIamApplication): IBuiltinIamApplication{
        if(Object.hasOwn(app, "clientSecretHash")) delete app.clientSecretHash;

        // remove other information we don't want to send out on reads
        return app;
    }

    public async boostrapDefaultUsers(users: {id: string, userType: string, fullName: string, password: string, platformRoles: string[]}[]):Promise<void>{
        this._logger.info("Bootstrapping IdentityManagementAggregate Default users...");

        for(const user of users){
            const newUser:IBuiltinIamUser={
                enabled: true,
                userType: user.userType as UserType,
                email: user.id,
                platformRoles: user.platformRoles,
                participantRoles: [],
                fullName: user.fullName
            };

            newUser.passwordHash = bcrypt.hashSync(user.password, BCRYPT_SALT_ROUNDS);
            await this._repo.storeUser(newUser);
            this._logger.info(`\t Added user ${newUser.email}` );
        }
        this._logger.info("Bootstrapping IdentityManagementAggregate Default users complete.");
    }

    public async boostrapDefaultApps(apps: {client_id: string, client_secret: string | null, platformRoles?: string[]}[]):Promise<void>{
        this._logger.info("Bootstrapping IdentityManagementAggregate Default apps...");

        for(const app of apps){
            const newApp:IBuiltinIamApplication={
                enabled: true,
                clientId: app.client_id,
                canLogin: app.client_secret !== null,
                platformRoles: app.platformRoles || []
            };

            if(newApp.canLogin && app.client_secret){
                newApp.clientSecretHash = bcrypt.hashSync(app.client_secret, BCRYPT_SALT_ROUNDS);
            }

            await this._repo.storeApp(newApp);
            this._logger.info(`\t Added apps ${newApp.clientId}` );
        }
        this._logger.info("Bootstrapping IdentityManagementAggregate Default apps complete.");
    }

    /* User functions */

    async registerUser(secCtx: CallSecurityContext, userCreate:IBuiltinIamUserCreate):Promise<void>{
        this._enforcePrivilege(secCtx, BuiltinIdentityPrivileges.CREATE_USER);

        if(!userCreate.email || userCreate.email.length<USERNAME_MIN_LENGTH){
            const err = new InvalidRequestError("Invalid username");
            this._logger.warn("Invalid username on registerUser");
            throw err;
        }

        if(await this._repo.fetchUser(userCreate.email)){
            const err = new InvalidRequestError("Invalid username"); // don't leak details
            this._logger.warn("Invalid username on registerUser");
            throw err;
        }

        // validate
        if(!userCreate.password || userCreate.password.length<PASSWORD_MIN_LENGTH){
            const err = new InvalidRequestError("Invalid password");
            this._logger.warn("Invalid password on registerUser");
            throw err;
        }

        // TODO: validate roles against type, ex: HUB user cannot have perParticipant roles

        const newUser:IBuiltinIamUser={
            enabled: true,
            userType: userCreate.userType,
            email: userCreate.email,
            platformRoles: userCreate.platformRoles,
            participantRoles: userCreate.participantRoles,
            fullName: userCreate.fullName
        };

        newUser.passwordHash = bcrypt.hashSync(userCreate.password, BCRYPT_SALT_ROUNDS);

        await this._repo.storeUser(newUser);

        return Promise.resolve();
    }

    async getUsers(secCtx: CallSecurityContext,  type?:string, email?:string, name?:string, enabled?:boolean):Promise<IBuiltinIamUser[]>{
        this._enforcePrivilege(secCtx, BuiltinIdentityPrivileges.VIEW_ALL_USERS);

        let users: IBuiltinIamUser[];
        if(type || email || name || enabled!=undefined){
            users = await this._repo.searchUsers(type, email, name, enabled);
        }else{
            users = await this._repo.fetchAllUsers();
        }

        // make sure we remove all in
        users.every(value => this._removeUserPrivateInfo(value));

        return users;
    }

    async getUserById(secCtx: CallSecurityContext, userId:string):Promise<IBuiltinIamUser | null>{
        this._enforcePrivilege(secCtx, BuiltinIdentityPrivileges.VIEW_ALL_USERS);

        const user = await this._repo.fetchUser(userId);
        if(!user) return null;

        // make sure we remove all priv info
        return this._removeUserPrivateInfo(user);
    }

    async changeUserPassword(secCtx: CallSecurityContext, username:string, oldPassword:string, newPassword:string):Promise<void>{
        // Note: users can only change their own passwords (must be authenticated); all an "admin" can do is request a password reset
        if(secCtx.username?.toUpperCase() !== username.toUpperCase()){
            const err = new ForbiddenError("Only a user can change its password");
            this._logger.warn(err);
            throw err;
        }

        const user = await this._repo.fetchUser(username);
        if(!user || !user.enabled){
            const err = new ForbiddenError(); // don't leak details
            this._logger.warn("Invalid or disabled user on changeUserPassword");
            throw err;
        }

        if(!user.passwordHash){
            const err = new ForbiddenError(); // don't leak details
            this._logger.warn("Invalid username or password on changeUserPassword");
            throw err;
        }

        // validate
        if(!newPassword || newPassword.length<PASSWORD_MIN_LENGTH){
            const err = new InvalidRequestError("Invalid new password on changeUserPassword");
            this._logger.warn(err);
            throw err;
        }

        if(!this._passwordHashMatches(oldPassword, user.passwordHash)){
            const err = new ForbiddenError("Invalid username or password");
            this._logger.warn("Invalid username or password on changeUserPassword");
            throw err;
        }

        user.passwordHash = bcrypt.hashSync(newPassword, BCRYPT_SALT_ROUNDS);

        await this._repo.storeUser(user);

        // TODO: Audit
        // TODO: invalidate token

        return Promise.resolve();
    }

    async enableUser(secCtx: CallSecurityContext, username:string): Promise<void>{
        this._enforcePrivilege(secCtx, BuiltinIdentityPrivileges.ENABLE_USER);

        const user = await this._repo.fetchUser(username);
        if(!user){
            this._logger.warn("User not found");
            throw new InvalidRequestError("User not found");
        }

        if(user.enabled){
            this._logger.warn("User already enabled");
            throw new InvalidRequestError("User already enabled");
        }

        user.enabled = true;

        await this._repo.storeUser(user);

        return Promise.resolve();
    }

    async disableUser(secCtx: CallSecurityContext, username:string): Promise<void>{
        this._enforcePrivilege(secCtx, BuiltinIdentityPrivileges.DISABLE_USER);

        const user = await this._repo.fetchUser(username);
        if(!user){
            this._logger.warn("User not found");
            throw new InvalidRequestError("User not found");
        }

        if(!user.enabled){
            this._logger.warn("User already disabled");
            throw new InvalidRequestError("User already disabled");
        }

        user.enabled = false;

        await this._repo.storeUser(user);

        // TODO send message to void tokens (add them to block list on token helper instances)

        return Promise.resolve();

    }

    async addRolesToUser(secCtx: CallSecurityContext, username:string, roleIds:string[]):Promise<void>{
        this._enforcePrivilege(secCtx, BuiltinIdentityPrivileges.MANAGE_USER_ROLES);

        const user = await this._repo.fetchUser(username);
        if(!user){
            this._logger.info("User not found or addRoleToUser");
            throw new InvalidRequestError("User not found");
        }

        // Note, we don't know if roleIds exist nor can we validate them, it's just a string identifier

        let addedCount =0;
        roleIds.forEach(newRole =>{
            if(!user.platformRoles.includes(newRole)){
                user.platformRoles.push(newRole);
                addedCount++;
            }
        });
        if(addedCount<=0){
            this._logger.debug("User already has those roles in addRolesToUser");
            throw new InvalidRequestError("User already has those roles");
        }

        await this._repo.storeUser(user);

        return Promise.resolve();
    }

    async removeRoleFromUser(secCtx: CallSecurityContext, username:string, roleId:string):Promise<void>{
        this._enforcePrivilege(secCtx, BuiltinIdentityPrivileges.MANAGE_USER_ROLES);

        const user = await this._repo.fetchUser(username);
        if(!user){
            this._logger.info("User not found or removeRoleFromUser");
            throw new InvalidRequestError("User not found");
        }

        if(!user.platformRoles.includes(roleId)){
            this._logger.debug("User does not have role");
            throw new InvalidRequestError("User does not have that role");
        }

        user.platformRoles = user.platformRoles.filter(value => value !== roleId);

        await this._repo.storeUser(user);

        return Promise.resolve();
    }

    /* Application functions */

    async registerApplication(secCtx: CallSecurityContext, appCreate:IBuiltinIamApplicationCreate):Promise<void>{
        this._enforcePrivilege(secCtx, BuiltinIdentityPrivileges.CREATE_APP);

        if(!appCreate.clientId || appCreate.clientId.length<USERNAME_MIN_LENGTH){
            const err = new InvalidRequestError("Invalid client_id");
            this._logger.warn("Invalid client_id on registerApplication");
            throw err;
        }

        if(await this._repo.fetchApp(appCreate.clientId)){
            const err = new InvalidRequestError("Invalid client_id"); // don't leak details
            this._logger.warn("Invalid client_id on registerApplication");
            throw err;
        }

        // Applications that can't login on their own have a null secret and no roles
        // Ex: UIs or APIs that always call other services using the caller/user token
        if(appCreate.canLogin && appCreate.clientSecret!=undefined && appCreate.clientSecret!=null
            && appCreate.clientSecret.length<PASSWORD_MIN_LENGTH){
            const err = new InvalidRequestError("Invalid client secret");
            this._logger.warn("Invalid client secret on registerApplication");
            throw err;
        }

        const newApp:IBuiltinIamApplication={
            enabled: true,
            clientId: appCreate.clientId,
            platformRoles: [],
            canLogin: appCreate.canLogin,
            clientSecretHash: undefined
        };

        // Applications that can't login on their own have a null secret and no roles
        if(appCreate.canLogin && appCreate.clientSecret!=undefined && appCreate.clientSecret) {
            newApp.clientSecretHash = bcrypt.hashSync(appCreate.clientSecret, BCRYPT_SALT_ROUNDS);
            newApp.platformRoles = appCreate.platformRoles || [];
        }

        await this._repo.storeApp(newApp);

        return Promise.resolve();
    }

    async getApplications(secCtx: CallSecurityContext, clientId?:string, canLogin?:boolean, enabled?:boolean):Promise<IBuiltinIamApplication[]>{
        this._enforcePrivilege(secCtx, BuiltinIdentityPrivileges.VIEW_ALL_APPS);

        let apps: IBuiltinIamApplication[];
        if(clientId || canLogin!=undefined || enabled!=undefined){
            apps = await this._repo.searchApps(clientId, canLogin, enabled);
        }else{
            apps = await this._repo.fetchAllApps();
        }

        // make sure we remove all in
        apps.every(app => this._removeAppPrivateInfo(app));

        return apps;
    }

    async getApplicationById(secCtx: CallSecurityContext, clientId:string):Promise<IBuiltinIamApplication | null>{
        this._enforcePrivilege(secCtx, BuiltinIdentityPrivileges.VIEW_ALL_APPS);

        const app = await this._repo.fetchApp(clientId);
        if(!app) return null;

        // make sure we remove all priv info
        return this._removeAppPrivateInfo(app);
    }

    async changeApplicationClientSecret(secCtx: CallSecurityContext, clientId:string, oldClientSecret:string, newClientSecret:string ):Promise<void>{
        this._enforcePrivilege(secCtx, BuiltinIdentityPrivileges.CHANGE_APP_SECRETS);

        const app = await this._repo.fetchApp(clientId);
        if(!app || !app.enabled){
            const err = new ForbiddenError(); // don't leak details
            this._logger.warn("Invalid or disabled app on changeAppPassword");
            throw err;
        }

        if(!app.clientSecretHash){
            const err = new ForbiddenError(); // don't leak details
            this._logger.warn("Invalid clientSecretHash on changeApplicationClientSecret");
            throw err;
        }

        // validate
        if(!newClientSecret || newClientSecret.length<PASSWORD_MIN_LENGTH){
            const err = new InvalidRequestError("Invalid new Client Secret on changeAppPassword");
            this._logger.warn(err);
            throw err;
        }

        if(!this._passwordHashMatches(oldClientSecret, app.clientSecretHash)){
            const err = new ForbiddenError("Invalid client id or secret");
            this._logger.warn("Invalid old password on changeAppPassword");
            throw err;
        }

        app.clientSecretHash = bcrypt.hashSync(newClientSecret, BCRYPT_SALT_ROUNDS);

        await this._repo.storeApp(app);

        // TODO: Audit
        // TODO: invalidate token

        return Promise.resolve();
    }

    async enableApp(secCtx: CallSecurityContext, clientId:string): Promise<void>{
        this._enforcePrivilege(secCtx, BuiltinIdentityPrivileges.ENABLE_USER);

        const app = await this._repo.fetchApp(clientId);
        if(!app){
            this._logger.warn("App not found");
            throw new InvalidRequestError("App not found");
        }

        if(app.enabled){
            this._logger.warn("App already enabled");
            throw new InvalidRequestError("App already enabled");
        }

        app.enabled = true;

        await this._repo.storeApp(app);

        return Promise.resolve();
    }

    async disableApp(secCtx: CallSecurityContext, clientId:string): Promise<void>{
        this._enforcePrivilege(secCtx, BuiltinIdentityPrivileges.DISABLE_USER);

        const app = await this._repo.fetchApp(clientId);
        if(!app){
            this._logger.warn("App not found");
            throw new InvalidRequestError("App not found");
        }

        if(!app.enabled){
            this._logger.warn("App already disabled");
            throw new InvalidRequestError("App already disabled");
        }

        app.enabled = false;

        await this._repo.storeApp(app);

        // TODO send message to void tokens (add them to block list on token helper instances)

        return Promise.resolve();

    }

    async addRolesToApp(secCtx: CallSecurityContext, clientId:string, roleIds:string[]):Promise<void>{
        this._enforcePrivilege(secCtx, BuiltinIdentityPrivileges.MANAGE_USER_ROLES);

        const app = await this._repo.fetchApp(clientId);
        if(!app){
            this._logger.info("App not found or addRoleToApp");
            throw new InvalidRequestError("App not found");
        }

        // Note, we don't know if roleIds exist nor can we validate them, it's just a string identifier

        let addedCount =0;
        roleIds.forEach(newRole =>{
            if(!app.platformRoles.includes(newRole)){
                app.platformRoles.push(newRole);
                addedCount++;
            }
        });
        if(addedCount<=0){
            this._logger.debug("App already has those roles in addRolesToApp");
            throw new InvalidRequestError("App already has those roles");
        }

        await this._repo.storeApp(app);

        return Promise.resolve();
    }

    async removeRoleFromApp(secCtx: CallSecurityContext, clientId:string, roleId:string):Promise<void>{
        this._enforcePrivilege(secCtx, BuiltinIdentityPrivileges.MANAGE_USER_ROLES);

        const app = await this._repo.fetchApp(clientId);
        if(!app){
            this._logger.info("App not found or removeRoleFromApp");
            throw new InvalidRequestError("App not found");
        }

        if(!app.platformRoles.includes(roleId)){
            this._logger.debug("App does not have role");
            throw new InvalidRequestError("App does not have that role");
        }

        app.platformRoles = app.platformRoles.filter(value => value !== roleId);

        await this._repo.storeApp(app);

        return Promise.resolve();
    }

}
