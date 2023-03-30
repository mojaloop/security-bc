#!/bin/bash
#set -x

# The root directory of packages to publish
ROOT="./packages"
REPOSITORY_TYPE="github"
#CIRCLE_API="https://circleci.com/api"
#LASTCIBUILDFILE=".lastcibuild"

########################################################################################
## 1. Setup
########################################################################################
# load common functions
source .circleci/publish_common_functions.sh

# load commits and git change history
printHeader "Phase 1 - Setup"
loadCommits

if [[ -z "$COMMITS_SINCE_LAST_CI_BUILD" ]]; then
    echo -e "\nNo commits between last successful CI Build and this one found - exiting"
    exit 0
else
    echo -e "\nCommits between last successful CI Build and this one:\n${COMMITS_SINCE_LAST_CI_BUILD}"
fi

# detect changes
printHeader "Phase 2 - Detecting changed packages since last CI build"
detectChangedPackages

if [[ $CHANGED_PACKAGES_COUNT -le 0 ]]; then
    echo -e "\nDONE - Didn't find any changed packages, all done."
    exit 0
fi


########################################################################################
## Phase 3 - Publishing changed packages to NPM
########################################################################################
printHeader "Phase 3 - Publishing changed packages to NPM"

PUBLISHED_NPM_PACKAGES_COUNT=0

for PACKAGE in ${CHANGED_PACKAGES}; do
    echo -e "\n------------------------------------------------------------"
    echo -e "Processing package: ${PACKAGE}..."

    PACKAGE_PATH=${ROOT}/$PACKAGE
    PACKAGE_NAME=$(cat ${PACKAGE_PATH}/package.json | jq -r ".name")
    PACKAGE_CUR_VERSION=$(cat ${PACKAGE_PATH}/package.json | jq -r ".version")
    PACKAGE_IS_PRIVATE=$(cat $PACKAGE_PATH/package.json | jq -r ".private // false")

    echo -e "\tName: \t\t${PACKAGE_NAME}"
    echo -e "\tPrivate: \t${PACKAGE_IS_PRIVATE}"
    echo -e "\tCur version: \t${PACKAGE_CUR_VERSION}"

    if [[ "$PACKAGE_IS_PRIVATE" = "true" ]]; then
        echo -e "\n\tIGNORING private package"
        continue
    fi

    ## increase patch version only
    npm -w ${PACKAGE_NAME} version patch --no-git-tag-version --no-workspaces-update >/dev/null 2>&1

    PACKAGE_NEW_VERSION=$(cat ${PACKAGE_PATH}/package.json | jq -r ".version")

    echo -e "\tNew version: \t${PACKAGE_NEW_VERSION}"

    echo -e "\n\tBuilding..."
    npm -w ${PACKAGE_NAME} run build
    echo -e "\n\tBuilding completed"

    if [[ -n "$DRYRUN" ]]; then
        echo -e "\nDryrun env var found - not actually publishing to NPM"
        continue
    fi

    echo -e "Publishing..."

    echo -e "---------------- PUBLISH START ----------------------\n"
    # actual publish command
    npm -w ${PACKAGE_NAME} publish --tag=latest --access public
    PUB_SUCCESS=$?
    echo -e "\n----------------- PUBLISH END -----------------------"

    if [[ $PUB_SUCCESS -eq 0 ]]; then
        PUBLISHED_NPM_PACKAGES_COUNT=$((PUBLISHED_NPM_PACKAGES_COUNT + 1))
        TAG_NAME=${PACKAGE}_v${PACKAGE_NEW_VERSION}
        echo -e "Successfully published package."
        echo -e "Git staging '${PACKAGE_PATH}/package.json' and creating tag: '${TAG_NAME}'"
        git add ${PACKAGE_PATH}/package.json
        git tag ${TAG_NAME}
    else
        echo -e "Error publishing package: ${PACKAGE} - exiting"
        exit 1
    fi
done


#### REMOTE
exit 99


########################################################################################
## Phase 4 - Building docker images and publishing to DockerHub
########################################################################################
printHeader "Phase 4 - Building docker images and publishing to DockerHub"

PUBLISHED_DOCKERHUB_PACKAGES_COUNT=0

echo -e "Going to build and publish ${PACKAGES_TO_PUBLISH_TO_DOCKER_COUNT} package(s)..."

for PACKAGE in ${PACKAGES_TO_PUBLISH_TO_DOCKER}; do
    echo -e "\n------------------------"
    echo -e "Building and publishing package: ${PACKAGE} to DockerHub..."

    PACKAGE_PATH=${ROOT}/$PACKAGE
    IMAGE_NAME=$(node -e "const p=require('./packages/${PACKAGE_PATH}/package.json'); console.log(p.name.replace('@', ''))")

done

############################################
## Phase 5 - Pushing commits to git
############################################
printHeader "Phase 5 - Pushing commits to git"

if [[ PUBLISHED_NPM_PACKAGES_COUNT -gt 0 ]] || [[ PUBLISHED_DOCKERHUB_PACKAGES_COUNT -gt 0 ]]; then
    # store the commit ID of the current commit for future CI/C reference
    echo ${CIRCLE_SHA1} >${LASTCIBUILDFILE}
    #git --no-pager log -1 --pretty=%H > ${LASTCIBUILDFILE}
    git add ${LASTCIBUILDFILE}

    # commit the updated package.json files and LASTCIBUILDFILE
    echo -e "${PUBLISHED_NPM_PACKAGES_COUNT} package(s) were published, committing changed 'package.json' files..."
    git commit -nm "[ci skip] CI/CD auto commit for: '$(git log -1 --pretty=%B)'"

    echo -e "Pushing changes..."
    # git status
    git push -f origin $CIRCLE_BRANCH --tags

    if [[ $? -eq 0 ]]; then
        echo -e "\nDONE - ${PUBLISHED_NPM_PACKAGES_COUNT} package(s) were published and version changes pushed, all done."
    else
        echo -e "Error pushing CI/CD auto commits for version changes - exiting"
        exit 5
    fi
else
    echo -e "${PUBLISHED_NPM_PACKAGES_COUNT} Packages were found to be published, but none was successfully published, error."
    exit 9
fi
