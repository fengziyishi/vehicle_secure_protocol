cmake_minimum_required(VERSION 3.25)
cmake_policy(SET CMP0167 NEW)  # Boost策略
cmake_policy(SET CMP0144 NEW)  # ROOT变量策略

project(VehicleSecurityProtocol)

# 设置C++标准
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 手动依赖路径配置
set(GMSSL_ROOT "C:/gmssl")
set(GMSSL_INCLUDE_DIRS "${GMSSL_ROOT}/include")
set(GMSSL_LIBRARIES "${GMSSL_ROOT}/lib/libgmssl.a")

set(Boost_ROOT "C:/boost_1_87_0")

# Windows配置
if(WIN32)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -static-libgcc -static-libstdc++")
    set(SYSTEM_LIBS ws2_32)
    
    set(THREADS_PREFER_PTHREAD_FLAG ON)
    find_package(Threads REQUIRED)
    list(APPEND SYSTEM_LIBS Threads::Threads)
endif()

# 现代Boost查找方式
find_package(Boost 
    REQUIRED 
    COMPONENTS system 
    CONFIG
    NO_CMAKE_PACKAGE_REGISTRY
    PATHS "${Boost_ROOT}"
    NO_DEFAULT_PATH
)

# 诊断输出
message(STATUS "GMSSL Path: ${GMSSL_ROOT}")
message(STATUS "Boost Version: ${Boost_VERSION}")

include_directories(
    ${PROJECT_SOURCE_DIR}/include
    ${GMSSL_INCLUDE_DIRS}
    ${Boost_INCLUDE_DIR}
)

# 公共源码
set(COMMON_SOURCES
    src/crypto/sm2_wrapper.cpp
    src/crypto/sm3_wrapper.cpp
    src/crypto/sm4_wrapper.cpp
    src/network/secure_socket.cpp
)

add_executable(vehicle_main
    src/vehicle/vehicle_main.cpp
    ${COMMON_SOURCES}
)
target_link_libraries(vehicle_main
    ${GMSSL_LIBRARIES}
    Boost::system
    ${SYSTEM_LIBS}
)
