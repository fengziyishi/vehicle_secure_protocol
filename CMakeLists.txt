cmake_minimum_required(VERSION 3.10)
project(VehicleSecureProtocol LANGUAGES CXX)

# 设置C++标准
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# 配置调试符号
set(CMAKE_BUILD_TYPE Debug)

# 设置输出目录
set(EXECUTABLE_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/bin)
set(LIBRARY_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/lib)

# 查找依赖库
find_package(Boost 1.66 REQUIRED COMPONENTS system)
find_package(OpenSSL REQUIRED)

# 国密算法库配置（示例路径，需根据实际安装路径修改）
set(GMSSL_ROOT "/opt/gmssl" CACHE PATH "GmSSL安装路径")
find_library(GMSSL_LIB gmssl
    PATHS ${GMSSL_ROOT}/lib
    REQUIRED
)
find_path(GMSSL_INCLUDE_DIR gmssl/sm2.h
    PATHS ${GMSSL_ROOT}/include
    REQUIRED
)

# 包含目录
include_directories(
    ${PROJECT_SOURCE_DIR}/include
    ${Boost_INCLUDE_DIRS}
    ${OPENSSL_INCLUDE_DIR}
    ${GMSSL_INCLUDE_DIR}
)

# 收集源文件
file(GLOB_RECURSE CRYPTO_SOURCES
    "src/crypto/*.cpp"
)

file(GLOB_RECURSE NETWORK_SOURCES
    "src/network/*.cpp"
)

# 构建RSU服务端可执行文件
add_executable(rsu_main
    src/rsu/rsu_main.cpp
    ${CRYPTO_SOURCES}
    ${NETWORK_SOURCES}
    src/utils/logger.cpp
)

target_link_libraries(rsu_main
    PRIVATE 
    Boost::system
    OpenSSL::SSL
    OpenSSL::Crypto
    ${GMSSL_LIB}
)

# 构建车辆客户端可执行文件
add_executable(vehicle_main
    src/vehicle/vehicle_main.cpp
    ${CRYPTO_SOURCES}
    ${NETWORK_SOURCES}
)

target_link_libraries(vehicle_main
    PRIVATE 
    Boost::system
    OpenSSL::SSL
    OpenSSL::Crypto
    ${GMSSL_LIB}
)

# 安装规则（可选）
install(TARGETS rsu_main vehicle_main
    RUNTIME DESTINATION bin
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
)

