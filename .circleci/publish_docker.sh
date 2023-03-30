#!/bin/bash
#set -x

# load common functions
source .circleci/publish_common_functions.sh

########################################################################################
## 1. Setup
########################################################################################
# load commits and git change history
printHeader "Phase 1 - Setup"
loadCommits

# detect changes
printHeader "Phase 2 - Detecting changed packages since last CI build"
detectChanges

if [[ $PACKAGES_TO_PUBLISH_TO_NPM_COUNT -le 0 ]] && [[ $PACKAGES_TO_PUBLISH_TO_DOCKER_COUNT -le 0 ]]; then
    echo -e "\nDONE - Didn't find any packages that needed publishing, all done."
    exit 0
fi

if [[ $DRYRUN ]]; then
    echo -e "\Dryrun env var found - existing"
    exit 0
fi

# remove
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
