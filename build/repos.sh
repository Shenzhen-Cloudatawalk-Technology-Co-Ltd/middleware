#!/bin/sh
#
# Script which defines variables which specify the repositories
# and branches to check out extra sources from.
# This script should not be called directly but should
# be included in other scripts.
#


if [ "$USE_NEW_LAYOUT" ]; then
SRCS_MANIFEST="${AVATAR_ROOT}/objs/repo-manifest"
else
SRCS_MANIFEST="${AVATAR_ROOT}/${EXTRA_SRC}/FreeBSD/repo-manifest"
fi

if is_truenas ; then
    # Additional repos to checkout for build
    ADDL_REPOS="$ADDL_REPOS ZFSD TRUENAS_COMPONENTS"

    : ${GIT_ZFSD_REPO=git@gitserver.ixsystems.com:/git/repos/truenas-build/git-repo/zfsd.git}
    : ${GIT_ZFSD_CHECKOUT_PATH="${AVATAR_ROOT}/${EXTRA_SRC}/nas_source/zfsd"}
    : ${GIT_TRUENAS_COMPONENTS_REPO=git@gitserver.ixsystems.com:/git/repos/truenas-build/truenas.git}
    : ${GIT_TRUENAS_COMPONENTS_CHECKOUT_PATH="${AVATAR_ROOT}/${EXTRA_SRC}/nas_source/truenas-components"}

    export NAS_PORTS_DIRECT=1

fi

if [ "${GIT_LOCATION}" = "EXTERNAL" ] ; then
    : ${GIT_FREEBSD_REPO=https://github.com/trueos/trueos}
    : ${GIT_PORTS_REPO=https://github.com/freenas/ports.git}
fi

: ${GIT_FREEBSD_BRANCH=freebsd10}
: ${GIT_FREEBSD_REPO=git@gitserver.ixsystems.com:/git/repos/freenas-build/trueos.git}
: ${GIT_FREEBSD_CHECKOUT_PATH="${AVATAR_ROOT}/${EXTRA_SRC}/FreeBSD/src"}

: ${GIT_PORTS_BRANCH=freenas/9-stable}
: ${GIT_PORTS_REPO=git@gitserver.ixsystems.com:/git/repos/freenas-build/ports.git}
: ${GIT_PORTS_CHECKOUT_PATH="${AVATAR_ROOT}/${EXTRA_SRC}/FreeBSD/ports"}

: ${REPOS="FREEBSD PORTS ${ADDL_REPOS}"}
