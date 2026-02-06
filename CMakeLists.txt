cmake_minimum_required(VERSION 3.10)
project(QuickLog)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Compiler flags
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra")
set(CMAKE_CXX_FLAGS_RELEASE "-O2")
set(CMAKE_CXX_FLAGS_DEBUG "-g")

# Source files
set(SOURCES
        main.cpp
)

# Create executable
add_executable(quickLog ${SOURCES})

# macOS specific settings
if(APPLE)
    # No additional libraries needed for basic BSD sockets on macOS
    message(STATUS "Building for macOS")
endif()

# Install target (optional)
install(TARGETS quickLog DESTINATION /usr/local/bin)

# Custom targets for convenience
add_custom_target(run
        COMMAND quickLog
        DEPENDS quickLog
        WORKING_DIRECTORY ${CMAKE_PROJECT_DIR}
        COMMENT "Running QuickLog..."
)

# Uninstall target
add_custom_target(uninstall
        COMMAND rm -f /usr/local/bin/quicklog
        COMMENT "Uninstalling QuickLog from /usr/local/bin"
)

# Print build type
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "C++ Compiler: ${CMAKE_CXX_COMPILER}")
message(STATUS "C++ Standard: ${CMAKE_CXX_STANDARD}")