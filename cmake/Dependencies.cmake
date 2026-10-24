# Prefer system packages, fall back to FetchContent for what is missing.
include(FetchContent)

# CMake 4 dropped compatibility with projects declaring cmake_minimum_required < 3.5.
set(CMAKE_POLICY_VERSION_MINIMUM 3.5)

find_package(spdlog REQUIRED)
find_package(SQLite3 REQUIRED)
find_package(CURL REQUIRED)

find_package(yaml-cpp QUIET)
if(NOT yaml-cpp_FOUND)
  FetchContent_Declare(yaml-cpp
    GIT_REPOSITORY https://github.com/jbeder/yaml-cpp.git
    GIT_TAG 0.8.0)
  set(YAML_CPP_BUILD_TESTS OFF CACHE BOOL "" FORCE)
  set(YAML_CPP_BUILD_TOOLS OFF CACHE BOOL "" FORCE)
  FetchContent_MakeAvailable(yaml-cpp)
  if(NOT TARGET yaml-cpp::yaml-cpp)
    add_library(yaml-cpp::yaml-cpp ALIAS yaml-cpp)
  endif()
endif()

find_package(nlohmann_json 3.9 QUIET)
if(NOT nlohmann_json_FOUND)
  FetchContent_Declare(nlohmann_json
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE
    URL https://github.com/nlohmann/json/releases/download/v3.11.3/json.tar.xz)
  FetchContent_MakeAvailable(nlohmann_json)
endif()

if(AGENT_BUILD_TESTS)
  find_package(Catch2 2 QUIET)
  if(NOT Catch2_FOUND)
    FetchContent_Declare(Catch2
      GIT_REPOSITORY https://github.com/catchorg/Catch2.git
      GIT_TAG v2.13.10)
    FetchContent_MakeAvailable(Catch2)
  endif()
endif()
