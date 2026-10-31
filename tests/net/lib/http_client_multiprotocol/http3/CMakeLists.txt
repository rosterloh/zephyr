# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.28.0)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(http_client_multiprotocol_http3)

target_sources(app PRIVATE src/main.c src/qpack.c ../http2/src/common.c)
target_include_directories(app PRIVATE ../http2/src ${ZEPHYR_BASE}/tests/net/lib/quic/certs
  ${ZEPHYR_BASE}/subsys/net/lib/http/headers)

set(gen_dir ${ZEPHYR_BINARY_DIR}/include/generated/)

foreach(inc_file ca.crt server.crt server.key client.crt client.key)
  generate_inc_file_for_target(app ${ZEPHYR_BASE}/tests/net/lib/quic/certs/${inc_file}
    ${gen_dir}/${inc_file}.inc)
endforeach()

zephyr_linker_sources(SECTIONS sections-rom.ld)
zephyr_iterable_section(NAME http_resource_desc_test_http_service KVMA RAM_REGION GROUP RODATA_REGION)
