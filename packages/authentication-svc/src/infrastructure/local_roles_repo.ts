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

/*
import fs from "fs";
import {readFile, writeFile} from "fs/promises";
import {watch} from "node:fs";
import {ILogger} from "@mojaloop/logging-bc-public-types-lib";
import {ILocalRoleAssociationRepo} from "../domain/interfaces";



export class LocalRolesAssociationRepo implements ILocalRoleAssociationRepo{
	private readonly _logger: ILogger;
	private readonly _filePath: string;
	private readonly _userRoles: Map<string, string[]> = new Map<string, string[]>();
	private readonly _appRoles: Map<string, string[]> = new Map<string, string[]>();
	private _watching = false;

	constructor(filePath: string, logger: ILogger) {
		this._logger = logger.createChild(this.constructor.name);
		this._filePath = filePath;

		this._logger.info(`Starting LocalRolesAssociationRepo with file path: "${this._filePath}"`);
	}

	private async _loadFromFile(): Promise<boolean> {
		this._userRoles.clear();
		this._appRoles.clear();

		let fileData: any;
		try {
			const strContents = await readFile(this._filePath, "utf8");
			if (!strContents || !strContents.length) {
				return false;
			}
			fileData = JSON.parse(strContents);
		} catch (e) {
			throw new Error("cannot read LocalRolesAssociationRepo storage file");
		}

		if (fileData.userRoles && Array.isArray(fileData.userRoles)) {
			for (const loadedRec of fileData.userRoles) {
				if (loadedRec.username && !this._userRoles.has(loadedRec.username)) {
					this._userRoles.set(loadedRec.username, loadedRec.roles);
				}
			}
		}

		if (fileData.appRoles && Array.isArray(fileData.appRoles)) {
			for (const loadedRec of fileData.appRoles) {
				if (loadedRec.client_id && !this._appRoles.has(loadedRec.client_id)) {
					this._appRoles.set(loadedRec.client_id, loadedRec.roles);
				}
			}
		}

		this._logger.info(`Successfully read file contents - userRoles: ${this._userRoles.size} and appRoles: ${this._appRoles.size}`);

		return true;
	}

	private async _saveToFile(): Promise<void> {
		try {
			const obj = {
				userRoles: Array.from(this._userRoles.values()),
				appRoles: Array.from(this._appRoles.values())
			};
			const strContents = JSON.stringify(obj, null, 4);
			await writeFile(this._filePath, strContents, "utf8");
			this._ensureIsWatching();
		} catch (e) {
			this._logger.error(e, "cannot write LocalRolesAssociationRepo storage file");
			throw new Error("cannot write LocalRolesAssociationRepo storage file");
		}
	}

	async init(): Promise<void> {
		const exists = fs.existsSync(this._filePath);

		// if not exists we skip, it will be loaded after
		if (!exists) {
			this._logger.warn("LocalRolesAssociationRepo data file does not exist, will be created at first write - filepath: " + this._filePath);
			return;
		}


		const loadSuccess = await this._loadFromFile();
		if (!loadSuccess) {
			throw new Error("Error loading LocalRolesAssociationRepo file");
		}


		this._ensureIsWatching();
	}

	private _ensureIsWatching() {
		if (this._watching) return;

		let fsWait: NodeJS.Timeout | undefined; // debounce wait
		watch(this._filePath, async (eventType, filename) => {
			if (eventType==="change") {
				if (fsWait) return;
				fsWait = setTimeout(() => {
					fsWait = undefined;
				}, 100);
				this._logger.info(`LocalRolesAssociationRepo file changed,  with file path: "${this._filePath}" - reloading...`);
				await this._loadFromFile();
			}
		});
		this._watching = true;
	}

	userRolesCount(): number {
		return this._userRoles.size;
	}

	applicationRolesCount(): number {
		return this._appRoles.size;
	}

	/!* interface methods *!/

	fetchApplicationPlatformRoles(clientId: string): Promise<string[]> {
		return Promise.resolve(this._appRoles.get(clientId) || []);
	}

	fetchUserPlatformRoles(username: string): Promise<string[]> {
		return Promise.resolve(this._userRoles.get(username) || []);
	}

	async storeApplicationRoles(clientId: string, roles: string[]): Promise<void> {
		this._appRoles.set(clientId, roles);
		await this._saveToFile();
		return Promise.resolve();
	}

	async storeUserRoles(username: string, roles: string[]): Promise<void> {
		this._userRoles.set(username, roles);
		await this._saveToFile();
		return Promise.resolve();
	}

    fetchApplicationPerParticipantRoles(clientId: string): Promise<{ participantId: string; roleId: string }[]> {
        throw new Error("Not implemented");
    }

    fetchUserPerParticipantRoles(username: string): Promise<{ participantId: string; roleId: string }[]> {
        throw new Error("Not implemented");
    }


}
*/
