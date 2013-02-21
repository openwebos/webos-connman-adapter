# @@@LICENSE
#
# Copyright (c) 2012 Hewlett-Packard Development Company, L.P.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# LICENSE@@@

#
# webos-connman-adapter/CMakeLists.txt
#


cmake_minimum_required(VERSION 2.8.7)

project(webos-connman-adapter C)

include(webOS/webOS)
webos_modules_init(1 0 0 QUALIFIER RC4)
webos_component(1 0 0)

set(WIFI_IFACE_NAME "wlan0" CACHE STRING "WiFi interface name")
set(WIRED_IFACE_NAME "eth0" CACHE STRING "Wired interface name")

find_program(GDBUS_CODEGEN_EXECUTABLE NAMES gdbus-codegen DOC "gdbus-codegen executable")
if(NOT GDBUS_CODEGEN_EXECUTABLE)
	message(FATAL_ERROR "Executable gdbus-codegen not found")
endif()

include(FindPkgConfig)

pkg_check_modules(GLIB2 REQUIRED glib-2.0)
include_directories(${GLIB2_INCLUDE_DIRS})
webos_add_compiler_flags(ALL ${GLIB2_CFLAGS_OTHER})

pkg_check_modules(LUNASERVICE2 REQUIRED luna-service2)
include_directories(${LUNASERVICE2_INCLUDE_DIRS})
webos_add_compiler_flags(ALL ${LUNASERVICE2_CFLAGS_OTHER})

pkg_check_modules(GIO-UNIX REQUIRED gio-unix-2.0)
include_directories(${GIO-UNIX_INCLUDE_DIRS})
webos_add_compiler_flags(ALL ${GIO-UNIX_CFLAGS_OTHER})

pkg_check_modules(PBNJSON_C REQUIRED pbnjson_c)
include_directories(${PBNJSON_C_INCLUDE_DIRS})
webos_add_compiler_flags(ALL ${PBNJSON_C_CFLAGS_OTHER})

pkg_check_modules(OPENSSL REQUIRED openssl)
include_directories(${OPENSSL_INCLUDE_DIRS})
webos_add_compiler_flags(ALL ${OPENSSL_CFLAGS_OTHER})

pkg_check_modules(LUNAPREFS REQUIRED luna-prefs)
include_directories(${LUNAPREFS_INCLUDE_DIRS})
webos_add_compiler_flags(ALL ${LUNAPREFS_CFLAGS_OTHER})

pkg_check_modules(PMLOG REQUIRED PmLogLib)
include_directories(${PMLOG_INCLUDE_DIRS})
webos_add_compiler_flags(ALL ${PMLOG_CFLAGS_OTHER})

webos_add_compiler_flags(ALL -Wall -g)

webos_add_linker_options(ALL --no-undefined)

set(GDBUS_IF_DIR ${WEBOS_BINARY_CONFIGURED_DIR}/src)

file (MAKE_DIRECTORY ${GDBUS_IF_DIR})

execute_process(COMMAND ${GDBUS_CODEGEN_EXECUTABLE} --c-namespace ConnmanInterface --generate-c-code 
			${GDBUS_IF_DIR}/connman-interface --interface-prefix net.connman. 
			${CMAKE_CURRENT_SOURCE_DIR}/files/xml/connman.xml
	                RESULT_VARIABLE codegen_failed)
if(codegen_failed)
		message(FATAL_ERROR "Error in generating code for connman interface using gdbus-codegen")
endif()

include_directories(src ${GDBUS_IF_DIR})
webos_configure_header_files(src)

file(GLOB SOURCE_FILES src/*.c ${GDBUS_IF_DIR}/connman-interface.c)

add_executable(webos-connman-adapter ${SOURCE_FILES})
target_link_libraries(webos-connman-adapter
                        ${GLIB2_LDFLAGS}
                        ${LUNASERVICE2_LDFLAGS}
                        ${GIO-UNIX_LDFLAGS}
                        ${PBNJSON_C_LDFLAGS}
                        ${OPENSSL_LDFLAGS}
                        ${LUNAPREFS_LDFLAGS}
                        ${PMLOG_LDFLAGS}
                        rt
                        pthread)

webos_build_daemon()
webos_build_system_bus_files()

webos_config_build_doxygen(doc Doxyfile)

# Install connman configuration file to set priorities between wired and wifi interfaces
install(FILES files/conf/main.conf DESTINATION ${WEBOS_INSTALL_SYSCONFDIR}/connman)
