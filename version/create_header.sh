#!/bin/bash

# Key words of the git info in the bazel stamped file
STAMP_INFO_KEYS=('STABLE_GIT_DIRTY' 'STABLE_GIT_COMMIT' 'STABLE_GIT_TAG')

# Git info table
declare -A GIT_INFO_MAP
GIT_INFO_CNT=${#STAMP_INFO_KEYS[@]}
GIT_INFO_VALID=true

# Parse git info from bazel stamped info
while read -r STAMP_INFO; do
    # End the search if invalid info detected
    if [[ "$GIT_INFO_VALID" == "false" || "$GIT_INFO_CNT" -eq 0 ]]; then
        break
    fi
    # At each line of the bazel stamped info check if it's git info
    for KEY in "${STAMP_INFO_KEYS[@]}"; do
        if [[ "$STAMP_INFO" == *"$KEY"* ]]; then
            # Split the line of git info into key-value pair
            read -ra INFO_ARR <<< "$STAMP_INFO"
            GIT_INFO=${INFO_ARR[1]}
            # Check the validity of the git info
            if [[ -z $GIT_INFO ]]; then
                GIT_INFO_VALID=false
            else
                GIT_INFO_MAP[$KEY]=$GIT_INFO
            fi
            # If find a matched git info goto next loop
            let "GIT_INFO_CNT-=1"
            break
        fi
    done
done < bazel-out/stable-status.txt

# Initialize target replacement info
SRC_VER_INFO="SRC_VER_INFO"
DST_VER_INFO="VERSION_ERROR"

# Check the validity of stamped git info
if [[ "$GIT_INFO_VALID" == "true" && "$GIT_INFO_CNT" -eq 0 ]]; then
    # Use the git tag version as the main version number
    DST_VER_INFO=${GIT_INFO_MAP[${STAMP_INFO_KEYS[2]}]}

    # Check if current version is a release version or not
    if [[ "${GIT_INFO_MAP[${STAMP_INFO_KEYS[1]}]}" != "EMPTY" ]]; then
        DST_VER_INFO+="-${GIT_INFO_MAP[${STAMP_INFO_KEYS[1]}]}"
    fi

    # Check if git has uncommitted change
    if [[ "${GIT_INFO_MAP[${STAMP_INFO_KEYS[0]}]}" == "TRUE" ]]; then
        DST_VER_INFO+="-dirty"
    fi
fi

# Write the final verison info to header file
echo "version info: $DST_VER_INFO"
sed "s/$SRC_VER_INFO/$DST_VER_INFO/" $1 > $2
