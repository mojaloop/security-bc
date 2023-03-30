#!/bin/bash
set -a # Enable allexport

########################################################################################
## Shared functions
########################################################################################

function printHeader() {
    echo -e "\n****************************************"
    echo -e "${1}"
    echo -e "****************************************"
}

#
# publishes COMMITS_SINCE_LAST_CI_BUILD and LAST_CI_BUILD_COMMIT
#
function loadCommits(){
    if [[ -z "${CIRCLE_SHA1}" ]]; then
        echo -e "\e[93mEnvironment variable CIRCLE_SHA1 is not set. Exiting.\e[0m"
        exit 1
    fi

    if [[ -z "${CIRCLE_TOKEN}" ]]; then
        echo -e "\e[93mEnvironment variable CIRCLE_TOKEN is not set. Exiting.\e[0m"
        exit 1
    fi

    if [[ -z "${CIRCLE_PROJECT_REPONAME}" ]]; then
        echo -e "\e[93mEnvironment variable CIRCLE_PROJECT_REPONAME is not set. Exiting.\e[0m"
        exit 1
    fi

    if [[ -z "${CIRCLE_PROJECT_USERNAME}" ]]; then
        echo -e "\e[93mEnvironment variable CIRCLE_PROJECT_USERNAME is not set. Exiting.\e[0m"
        exit 1
    fi

    echo -e "Provided CI Build commit hash: \t\t${CIRCLE_SHA1}"
    echo -e "Provided CI Build username: \t\t${CIRCLE_PROJECT_USERNAME}"
    echo -e "Provided project repository name: \t${CIRCLE_PROJECT_REPONAME}"

    echo -e "\nFetching last successful build from CircleCI API...."
    LAST_CI_BUILD_COMMIT=$(curl -s --header "Authorization: Basic $CIRCLE_TOKEN" https://circleci.com/api/v1.1/project/github/$CIRCLE_PROJECT_USERNAME/$CIRCLE_PROJECT_REPONAME\?filter\=completed\&limit\=1 | jq -r '.[0]["vcs_revision"]')
    echo -e "\nLast successful CI Build commit hash: \t${LAST_CI_BUILD_COMMIT}"

    if [[ -z "${LAST_CI_BUILD_COMMIT}" ]]; then
        COMMITS_SINCE_LAST_CI_BUILD=$(git --no-pager log ${CIRCLE_SHA1} --pretty=format:%H)
    else
        COMMITS_SINCE_LAST_CI_BUILD=$(git --no-pager log ${LAST_CI_BUILD_COMMIT}..${CIRCLE_SHA1} --pretty=format:%H)
    fi
}

# packages require a package.json in the package directory
function detectChangedPackages(){
    PACKAGES=$(ls -l "${ROOT}" | grep ^d | awk '{print $9}')
    echo -e "Found these packages in this repository:"
    for PACKAGE in $PACKAGES; do
        echo -e " - ${PACKAGE}"
    done

    CHANGED_PACKAGES=""
    CHANGED_PACKAGES_COUNT=0

    #for PACKAGE in "${PACKAGES[@]}"; do
    for PACKAGE in $PACKAGES; do
        PACKAGE_PATH=${ROOT}/$PACKAGE
        PACKAGE_LAST_CHANGE_COMMIT_SHA=$(git --no-pager log -1 --format=format:%H --full-diff $PACKAGE_PATH)

        echo -e "\nChecking package: '${PACKAGE}' on path: ${PACKAGE_PATH}"

        if [[ ! -s "$PACKAGE_PATH/package.json" ]]; then
            echo -e "\tPackage does not have a package.json file - ignoring"
            continue
        fi

        echo -e "\tPackage last change commit: ${PACKAGE_LAST_CHANGE_COMMIT_SHA}"

        if [[ -z "$PACKAGE_LAST_CHANGE_COMMIT_SHA" ]] || [[ $COMMITS_SINCE_LAST_CI_BUILD == *"$PACKAGE_LAST_CHANGE_COMMIT_SHA"* ]]; then
            CHANGED_PACKAGES+="$PACKAGE "
            CHANGED_PACKAGES_COUNT=$((CHANGED_PACKAGES_COUNT + 1))
            echo -e "\tPackage changed since last CI build and has a package.json file - ADDING TO THE LIST of changed packages"
        else
            echo -e "\tPackage not changed since last CI build - IGNORING"
        fi
    done

}


function OLD_detectChanges(){
    PACKAGES=$(ls -l "${ROOT}" | grep ^d | awk '{print $9}')
    echo -e "Found these packages in this repository:"
    for PACKAGE in $PACKAGES; do
        echo -e " - ${PACKAGE}"
    done

    PACKAGES_TO_PUBLISH_TO_NPM=""
    PACKAGES_TO_PUBLISH_TO_NPM_COUNT=0
    PACKAGES_TO_PUBLISH_TO_DOCKER=""
    PACKAGES_TO_PUBLISH_TO_DOCKER_COUNT=0

    #for PACKAGE in "${PACKAGES[@]}"; do
    for PACKAGE in $PACKAGES; do
        PACKAGE_PATH=${ROOT}/$PACKAGE
        PACKAGE_LAST_CHANGE_COMMIT_SHA=$(git --no-pager log -1 --format=format:%H --full-diff $PACKAGE_PATH)
        PACKAGE_IS_PRIVATE=$(cat $PACKAGE_PATH/package.json | jq -r ".private // false")
        PACKAGE_IS_DOCKERIMAGE=$(cat $PACKAGE_PATH/package.json | jq -r ".mojaloop.publish_to_dockerhub // false")

        echo -e "\nChecking package: '${PACKAGE}' on path: ${PACKAGE_PATH}"

        if [[ ! -s "$PACKAGE_PATH/package.json" ]]; then
            echo -e "\tPackage does not have a package.json file - ignoring"
            continue
        fi

        echo -e "\tPackage last change commit: ${PACKAGE_LAST_CHANGE_COMMIT_SHA} - is private: ${PACKAGE_IS_PRIVATE} - mojaloop.publish_to_dockerhub key: ${PACKAGE_IS_DOCKERIMAGE}"

        if [[ -z "$PACKAGE_LAST_CHANGE_COMMIT_SHA" ]] || [[ $COMMITS_SINCE_LAST_CI_BUILD == *"$PACKAGE_LAST_CHANGE_COMMIT_SHA"* ]]; then
            if [[ "$PACKAGE_IS_DOCKERIMAGE" = "true" ]]; then
                PACKAGES_TO_PUBLISH_TO_DOCKER+="$PACKAGE "
                PACKAGES_TO_PUBLISH_TO_DOCKER_COUNT=$((PACKAGES_TO_PUBLISH_TO_DOCKER_COUNT + 1))
                echo -e "\tPackage changed since last CI build and has Docker Build flag in package.json - adding to the list or docker packages"
            fi
            if [[ "$PACKAGE_IS_PRIVATE" = "false" ]]; then
                PACKAGES_TO_PUBLISH_TO_NPM+="$PACKAGE "
                PACKAGES_TO_PUBLISH_TO_NPM_COUNT=$((PACKAGES_TO_PUBLISH_TO_NPM_COUNT + 1))
                echo -e "\tPackage changed since last CI build and is not market as private in package.json - adding to the list of npm packages"
            fi
        else
            echo -e "\tPackage not changed since last CI build - ignoring"
        fi
    done

}
