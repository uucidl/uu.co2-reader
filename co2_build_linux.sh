#!/usr/bin/env bash
HERE="$(dirname "${0}")"

CC=${CC:-cc}
(O="${HERE}"/co2
 "${CC}" "${HERE}"/src/co2_unit.c -g -o "${O}" -I"${HERE}"/deps/hidapi/hidapi \
    "${HERE}"/deps/hidapi/linux/hid.c \
    -DLINUX_FREEBSD -DHIDAPI=hidraw \
    && printf "PROGRAM\t%s\n" "${O}") || exit 1

exit 0
