#!/bin/sh
DIR="${1}"
FILE="${2}"
ZONE="${3}"
SERIAL="${4}"
git -C "${DIR}" add ${FILE}
git -C "${DIR}" commit ${FILE} -m "zone ${ZONE} with serial ${SERIAL}"
