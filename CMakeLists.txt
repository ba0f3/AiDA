cmake_minimum_required(VERSION 3.10)
project(aida)

add_subdirectory(libs)
add_subdirectory(src)

# aida
if(DEFINED ENV{IDASDK})
    set(IDA_SDK_INCLUDE_DIR "$ENV{IDASDK}/include")
    if(EXISTS ${IDA_SDK_INCLUDE_DIR})
        add_executable(aida ${AIDA_SRCS})
        target_include_directories(aida PUBLIC src ${IDA_SDK_INCLUDE_DIR})
        target_link_libraries(aida httplib nlohmann_json)
    else()
        message(FATAL_ERROR "IDASDK environment variable is set but the include directory does not exist: ${IDA_SDK_INCLUDE_DIR}")
    endif()
else()
    message(FATAL_ERROR "IDASDK environment variable is not set. Please set it to your IDA SDK path.")
endif()
