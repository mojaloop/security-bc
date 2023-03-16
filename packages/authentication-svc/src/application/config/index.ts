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

import { ConfigParameterTypes } from "@mojaloop/platform-configuration-bc-public-types-lib";
import {
    ConfigurationClient,
    DefaultConfigProvider
} from "@mojaloop/platform-configuration-bc-client-lib";

if(!process.env.npm_package_version){
    throw new Error("This application must be launched by npm");
}

// configs - constants / code dependent
const BC_NAME = "security-bc";
const APP_NAME = "authentication-svc";
const APP_VERSION = process.env.npm_package_version || "0.0.0";
const CONFIGSET_VERSION = "0.0.3";

// configs - non-constants
const ENV_NAME = process.env["ENV_NAME"] || "dev";

// use default url from PLATFORM_CONFIG_BASE_SVC_URL env var
const defaultConfigProvider: DefaultConfigProvider = new DefaultConfigProvider();
const configClient = new ConfigurationClient(ENV_NAME, BC_NAME, APP_NAME, APP_VERSION, CONFIGSET_VERSION, defaultConfigProvider);

export const configKeys = {
    "ROLES_FROM_IAM_PROVIDER": "ROLES_FROM_IAM_PROVIDER"
}

/*
* Add application parameters here
* */
configClient.appConfigs.addNewParam(
        configKeys.ROLES_FROM_IAM_PROVIDER,
        ConfigParameterTypes.BOOL,
        false,
        "Enable fetching of role association from the connected IAM prodiver (instead of the builtin authorization service)"
);


export default configClient;

