cmake_minimum_required(VERSION 3.16)
project(PacketAnalyzer VERSION 1.0)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Header files location
include_directories(${CMAKE_SOURCE_DIR}/include)

# Common utility sources
set(COMMON_SOURCES
    src/pcap_reader.cpp
    src/packet_parser.cpp
    src/types.cpp
    src/sni_extractor.cpp
    src/connection_tracker.cpp
    src/rule_manager.cpp
)

# Standard analyzer executable (Improved CLI)
add_executable(packet_analyzer src/main.cpp ${COMMON_SOURCES})

# Multi-threaded DPI engine executable (Reference architecture)
set(DPI_ENGINE_SOURCES
    src/main_dpi.cpp
    src/dpi_engine.cpp
    src/load_balancer.cpp
    src/fast_path.cpp
    ${COMMON_SOURCES}
)

add_executable(dpi_engine ${DPI_ENGINE_SOURCES})
target_link_libraries(dpi_engine PRIVATE -pthread)

# Single-file simple multi-threaded version
add_executable(dpi_mt src/dpi_mt.cpp ${COMMON_SOURCES})
target_link_libraries(dpi_mt PRIVATE -pthread)

# Simplified working version
add_executable(dpi_working src/main_working.cpp ${COMMON_SOURCES})

# Unit Tests Executable
add_executable(unit_tests src/unit_tests.cpp ${COMMON_SOURCES})

if(APPLE)
    # Add any macOS-specific settings here
endif()
