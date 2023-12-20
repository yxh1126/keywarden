#!/bin/bash

# This bash tool will iterately loop through all the .h or .cc files for cpplint
# For .cpplintignore files, recommend to add files seperately.
# Yet regex like ./math/geometry/poly* is supported

if [ -e "/usr/bin/python2" ]; then
  PYTHON="python2"
else
  PYTHON="python"
fi

find . -type f -name "*.h" -or -name "*.cc" -or -name "*.cpp"\
| grep -v $(printf -- "-f %s " $(find . -name \*.cpplintignore)) \
| xargs $PYTHON tools/cpplint.py --counting=detailed --quiet
# --root=.
