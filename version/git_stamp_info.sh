#!/bin/bash

# Check if there is uncommitted exist
# The if condition will be TRUE if 'git status -s' return empty string
# which means git has no uncommitted change
if [[ -z $(git status -s) ]]; then
    echo "STABLE_GIT_DIRTY FALSE"
else
    echo "STABLE_GIT_DIRTY TRUE"
fi

# Get the full commit hash of the latest commit
GIT_COMMIT=$(git rev-parse HEAD)
# Check if the latest commit has tags
GIT_TAG=$(git tag --contains $GIT_COMMIT)
# The if condition will be TRUE if tag info is empty
# which means this is not a release version, thus a short commit sha
# will be added after the version number
if [[ -z $GIT_TAG ]]; then
    echo "STABLE_GIT_TAG $(git tag | grep -E '^v[0-9]' | sort -V | tail -1)"
    echo "STABLE_GIT_COMMIT $(git rev-parse --short HEAD)"
else
    echo "STABLE_GIT_TAG $GIT_TAG"
    echo "STABLE_GIT_COMMIT EMPTY"
fi
