#!/bin/sh
DIR="${1}"
FILE="${2}"
ZONE="${3}"
SERIAL="${4}"
TARGET=$(dirname ${FILE})/latest
mv ${FILE} ${TARGET}
FILE=${TARGET}
git -C "${DIR}" add ${FILE}
git -C "${DIR}" commit ${FILE} -m "zone ${ZONE} with serial ${SERIAL}"
