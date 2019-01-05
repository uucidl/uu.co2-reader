#!/usr/bin/env bash
HERE="$(dirname "${0}")"

(O="${HERE}"/co2
 cc "${HERE}"/src/co2_unit.c -g -o "${O}" -I"${HERE}"/deps/hidapi/hidapi \
    "${HERE}"/deps/hidapi/mac/hid.c \
    -std=c11 \
    -DAPPLE -framework IOKit -framework CoreFoundation \
    && printf "PROGRAM\t%s\n" "${O}") || exit 1

