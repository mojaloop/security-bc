#!/bin/bash
#set -x

# The root directory of packages to publish
ROOT="./packages"
REPOSITORY_TYPE="github"
# Move to circleCi file
DOCKER_BUILD_PLATFORMS=linux/amd64,linux/arm64,linux/arm/v7
DOCKER_LATEST_RELEASE_NAME=alpha-latest

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
## Phase 4 - Building docker images and publishing to DockerHub
########################################################################################
printHeader "Phase 4 - Building docker images and publishing to DockerHub"

PUBLISHED_DOCKERHUB_PACKAGES_COUNT=0

echo -e "  Docker version: $(docker --version)"
echo -e "  Logging in to dockerhub..."
echo "$DOCKER_PASS" | docker login --username $DOCKER_USER --password-stdin
echo -e "  Create docker builder, bootstrap it and use it..."
docker buildx create --name mybuilder --use --bootstrap
docker buildx ls


echo -e "\nGoing to build and publish ${PACKAGES_TO_PUBLISH_TO_DOCKER_COUNT} package(s)..."

SHORT_GIT_HASH=$(echo $CIRCLE_SHA1 | cut -c -7)

for PACKAGE in ${CHANGED_PACKAGES}; do
    echo -e "\n------------------------------------------------------------"
    echo -e "Processing package: ${PACKAGE}..."

    PACKAGE_PATH=${ROOT}/$PACKAGE
    PACKAGE_NAME=$(cat ${PACKAGE_PATH}/package.json | jq -r ".name")
    DOCKER_IMAGE_NAME=$(echo $PACKAGE_NAME | sed -e 's/@//')
    PACKAGE_CUR_VERSION=$(cat ${PACKAGE_PATH}/package.json | jq -r ".version")
    PACKAGE_PUBLISH_FLAG=$(cat $PACKAGE_PATH/package.json | jq -r ".mojaloop.publish_to_dockerhub // false")


    echo -e "\tName: \t\t${PACKAGE_NAME}"
    echo -e "\tCur version: \t${PACKAGE_CUR_VERSION}"
    echo -e "\tPublish flag: \t${PACKAGE_PUBLISH_FLAG}"

    if [[ ! "$PACKAGE_PUBLISH_FLAG" = "true" ]]; then
        echo -e "\n\tIGNORING package without 'mojaloop.publish_to_dockerhub' flag set to 'true' in package.json"
        continue
    fi

    ## increase patch version only
    npm -w ${PACKAGE_NAME} version patch --no-git-tag-version --no-workspaces-update >/dev/null 2>&1

    PACKAGE_NEW_VERSION=$(cat ${PACKAGE_PATH}/package.json | jq -r ".version")
    DOCKER_TAG_VERSION=${DOCKER_IMAGE_NAME}:${PACKAGE_NEW_VERSION}
    DOCKER_TAG_SHORT_GIT_HASH=${DOCKER_IMAGE_NAME}:${SHORT_GIT_HASH}
    DOCKER_TAG_LATEST_RELEASE=${DOCKER_IMAGE_NAME}:${DOCKER_LATEST_RELEASE_NAME}

    echo -e "\tNew version: \t${PACKAGE_NEW_VERSION}"
    echo -e "\tVersion Tag: \t${DOCKER_TAG_VERSION}"
    echo -e "\tCommit Tag: \t${DOCKER_TAG_SHORT_GIT_HASH}"
    echo -e "\tRelease Tag: \t${DOCKER_TAG_LATEST_RELEASE}"


    if [[ -n "$DRYRUN" ]]; then
        echo -e "\nDryrun env var found - not actually publishing to NPM"
        continue
    fi

    echo -e "\n\tBuilding and publishing docker image..."

    echo -e "---------------- DOCKER BUILD AND PUBLISH START ----------------------\n"

#    docker buildx build --platform ${DOCKER_BUILD_PLATFORMS} --cache-from=${DOCKER_TAG_LATEST_RELEASE} \
    docker buildx build --platform ${DOCKER_BUILD_PLATFORMS} --push --cache-from=${DOCKER_TAG_LATEST_RELEASE} \
        -f ${PACKAGE_PATH}/Dockerfile \
        -t ${DOCKER_TAG_VERSION} -t ${DOCKER_TAG_SHORT_GIT_HASH} -t ${DOCKER_TAG_LATEST_RELEASE} \
        .
    BUILD_AND_PUB_SUCCESS=$?
    echo -e "\n---------------- DOCKER BUILD AND PUBLISH END ----------------------"

    if [[ BUILD_AND_PUB_SUCCESS -eq 0 ]]; then
        PUBLISHED_DOCKERHUB_PACKAGES_COUNT=$((PUBLISHED_DOCKERHUB_PACKAGES_COUNT + 1))
        TAG_NAME=${PACKAGE}_v${PACKAGE_NEW_VERSION}
        echo -e "Successfully published docker image."
        echo -e "Git staging '${PACKAGE_PATH}/package.json, committing and tagging with: '${TAG_NAME}'"
        git add ${PACKAGE_PATH}/package.json
        git commit -nm "[ci skip] CI/CD auto commit for '${PACKAGE_NAME}' Docker Build and Publish - parent commit: '${CIRCLE_SHA1}'"
        git tag ${TAG_NAME}
    else
        echo -e "Error publishing package: ${PACKAGE} - exiting"
        exit 1
    fi
done

############################################
## Phase 4 - Pushing commits to git
############################################
printHeader "Phase 4 - Pushing commits to git"

if [[ PUBLISHED_NPM_PACKAGES_COUNT -eq 0 ]]; then
    echo -e "No Packages were published, nothing to push to git"
    exit 9
fi

echo -e "Pushing changes..."
# git status
git push -f origin $CIRCLE_BRANCH --tags

if [[ $? -eq 0 ]]; then
    echo -e "\nDONE - ${PUBLISHED_NPM_PACKAGES_COUNT} package(s) were published and version changes pushed, all done."
else
    echo -e "Error pushing CI/CD auto commits for version changes - exiting"
    exit 5
fi
