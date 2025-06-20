##
# SPDX-License-Identifier: BSD-3-Clause
#
# https://opensource.org/license/bsd-3-clause
#
# Copyright (C) 2021 Kang Lin <kl222@126.com>
#
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
# 3. Neither the name of the project nor the names of its contributors
#    may be used to endorse or promote products derived from this software
#    without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.
##

project(turnjwt)

# Find required packages
find_package(OpenSSL REQUIRED COMPONENTS Crypto SSL)
find_package(PkgConfig REQUIRED)

# Check for optional JWT dependencies
pkg_check_modules(LIBJWT libjwt)
pkg_check_modules(JANSSON jansson)
pkg_check_modules(CJSON libcjson)

set(SOURCE_FILES
    rs256.c
)

set(HEADER_FILES
    rs256.h
    jwt_integration.h
)

# Prepare JWT-related libraries and definitions
set(JWT_LIBS OpenSSL::SSL OpenSSL::Crypto)
set(JWT_DEFINED)
set(JWT_INCLUDE_DIRS)

if(LIBJWT_FOUND)
    list(APPEND JWT_LIBS ${LIBJWT_LDFLAGS})
    list(APPEND JWT_INCLUDE_DIRS ${LIBJWT_INCLUDE_DIRS})
    list(APPEND JWT_DEFINED HAVE_LIBJWT)
else()
    list(APPEND JWT_DEFINED TURN_NO_LIBJWT)
    message(WARNING "libjwt not found. JWT functionality will be limited.")
endif()

if(JANSSON_FOUND)
    list(APPEND JWT_LIBS ${JANSSON_LDFLAGS})
    list(APPEND JWT_INCLUDE_DIRS ${JANSSON_INCLUDE_DIRS})
    list(APPEND JWT_DEFINED HAVE_JANSSON)
else()
    list(APPEND JWT_DEFINED TURN_NO_JANSSON)
    message(WARNING "jansson not found. JSON functionality will be limited.")
endif()

if(CJSON_FOUND)
    list(APPEND JWT_LIBS ${CJSON_LDFLAGS})
    list(APPEND JWT_INCLUDE_DIRS ${CJSON_INCLUDE_DIRS})
    list(APPEND JWT_DEFINED HAVE_CJSON)
else()
    list(APPEND JWT_DEFINED TURN_NO_CJSON)
    message(WARNING "libcjson not found. JSON functionality will be limited.")
endif()

message("JWT_LIBS: ${JWT_LIBS}")
message("JWT_DEFINED: ${JWT_DEFINED}")

# Create static library
add_library(${PROJECT_NAME} STATIC ${SOURCE_FILES} ${HEADER_FILES})

# Public interface - what other libraries link against
target_link_libraries(${PROJECT_NAME} PUBLIC ${JWT_LIBS})
target_compile_definitions(${PROJECT_NAME} PUBLIC ${JWT_DEFINED})

# Include directories
target_include_directories(${PROJECT_NAME} PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}/turn/jwt>
    ${JWT_INCLUDE_DIRS}
)

# Private include directories (internal dependencies)
target_include_directories(${PROJECT_NAME} PRIVATE
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/src/apps/common
)

# Set target properties following coturn conventions
set_target_properties(${PROJECT_NAME} PROPERTIES
    LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
    ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib
    PUBLIC_HEADER "${HEADER_FILES}"
    VERSION ${VERSION}
)

# Install configuration
INSTALL(TARGETS ${PROJECT_NAME}
    EXPORT ${PROJECT_NAME}Config
    RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
        COMPONENT Runtime
    LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
        COMPONENT Runtime
    ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
        COMPONENT Development
    PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/turn/jwt
        COMPONENT Development
    INCLUDES DESTINATION
        ${CMAKE_INSTALL_INCLUDEDIR}/turn
        ${CMAKE_INSTALL_INCLUDEDIR}/turn/jwt
        COMPONENT Development
)

# Export for build tree
export(TARGETS ${PROJECT_NAME}
    NAMESPACE coturn::
    APPEND FILE ${CMAKE_BINARY_DIR}/${PROJECT_NAME}Config.cmake
)

# Install cmake configure files
install(EXPORT ${PROJECT_NAME}Config
    NAMESPACE coturn::
    DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/coturn"
        COMPONENT Development
)

# Install cmake version configure file
if(DEFINED VERSION)
    write_basic_package_version_file(
        "${CMAKE_BINARY_DIR}/${PROJECT_NAME}ConfigVersion.cmake"
        VERSION ${VERSION}
        COMPATIBILITY AnyNewerVersion)
    install(FILES "${CMAKE_BINARY_DIR}/${PROJECT_NAME}ConfigVersion.cmake"
        DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/coturn"
            COMPONENT Development)
endif()
