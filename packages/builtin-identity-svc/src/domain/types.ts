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

export enum AuditedActionNames {
    USER_LOGIN = "USER_LOGIN",
    USER_VIEW = "USER_VIEW",
    USER_CREATE = "USER_CREATE",
    USER_ENABLE = "USER_ENABLE",
    USER_DISABLE = "USER_DISABLE",
    USER_ADD_ROLES = "USER_ADD_ROLES",
    USER_REMOVE_ROLES = "USER_REMOVE_ROLES",
    USER_CHANGE_PASSWORD = "USER_CHANGE_PASSWORD",
    USER_REQUEST_PASSWORD_RESET = "USER_REQUEST_PASSWORD_RESET",
    APP_LOGIN = "APP_LOGIN",
    APP_VIEW = "APP_VIEW",
    APP_CREATE = "APP_CREATE",
    APP_ENABLE = "APP_ENABLE",
    APP_DISABLE = "APP_DISABLE",
    APP_ADD_ROLES = "APP_ADD_ROLES",
    APP_REMOVE_ROLES = "APP_REMOVE_ROLES",
    APP_CHANGE_SECRET = "APP_CHANGE_SECRET"
}

export class User {

}
