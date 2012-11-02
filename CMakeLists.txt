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
# pmwifiservice/CMakeLists.txt
#


cmake_minimum_required(VERSION 2.8.7)

project(webos-connman-adapter C)

include(webOS/webOS)
webos_modules_init(1 0 0 QUALIFIER RC4)
webos_component(1 0 0)

find_program(GDBUS_CODEGEN_EXECUTABLE NAMES gdbus-codegen DOC "gdbus-codegen executable")
if(NOT GDBUS_CODEGEN_EXECUTABLE)
	message(FATAL_ERROR "Executable gdbus-codegen not found")
endif(GDBUS_CODEGEN_EXECUTABLE)

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

pkg_check_modules(CJSON REQUIRED cjson)
include_directories(${CJSON_INCLUDE_DIRS})
webos_add_compiler_flags(ALL ${CJSON_CFLAGS_OTHER})

webos_add_compiler_flags(ALL -Wall)

webos_add_linker_options(ALL --no-undefined)

include_directories(src)

execute_process(COMMAND ${GDBUS_CODEGEN_EXECUTABLE} --c-namespace ConnmanInterface --generate-c-code 
			${CMAKE_CURRENT_SOURCE_DIR}/src/connman-interface --interface-prefix net.connman. 
			${CMAKE_CURRENT_SOURCE_DIR}/files/xml/connman.xml
	                RESULT_VARIABLE codegen_failed)
if(codegen_failed)
		message(FATAL_ERROR "Error in generating code for connman interface using gdbus-codegen")
endif()

file(GLOB SOURCE_FILES src/*.c)

add_executable(webos-connman-adapter ${SOURCE_FILES})
target_link_libraries(webos-connman-adapter
                        ${GLIB2_LDFLAGS}
                        ${LUNASERVICE2_LDFLAGS}
                        ${GIO-UNIX_LDFLAGS}
			${CJSON_LDFLAGS}
                        rt
                        pthread)

webos_build_daemon()
webos_build_system_bus_files()
