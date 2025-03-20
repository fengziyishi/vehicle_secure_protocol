#include "network/secure_socket.h"
#include "utils/logger.h"
#include <boost/asio.hpp>
#include <thread>
#include <functional>

using namespace boost::asio;

void simulate_sensor_data(SecureSocket::Ptr socket) {
    while(true) {
        try {
            // 模拟传感器数据
            std::vector<uint8_t> data = { /* 实际数据 */ };
            
            // 发送加密数据
            socket->async_send(data, [](bool success) {
                if(!success) LOG_WARN << "Data send failed";
            });

            std::this_thread::sleep_for(std::chrono::seconds(1));
        } catch(const std::exception& e) {
            LOG_ERROR << "Sensor thread error: " << e.what();
            break;
        }
    }
}

int main() {
    Logger::init("vehicle.log", Logger::Level::Debug);
    io::io_context io;

    try {
        // 连接RSU
        auto socket = std::make_shared<SecureSocket>(io, SecureSocket::Mode::V2I);
        socket->async_connect("192.168.1.100", 5000, [&](bool success) {
            if(success) {
                LOG_INFO << "Connected to RSU, starting data transmission";
                
                // 启动传感器线程
                std::thread(simulate_sensor_data, socket).detach();

                using ReceiveHandler = std::function<void(std::vector<uint8_t>, bool)>;
                auto receive_handler = std::make_shared<ReceiveHandler>();

                // 接收消息循环
                *receive_handler = [socket, receive_handler](std::vector<uint8_t> data, bool valid) {
                    if (valid) {
                        LOG_INFO << "Received RSU message, size: " << data.size();
                        // 处理接收数据...
                    } else {
                        LOG_WARN << "Received invalid message";
                    }
                    socket->async_receive(*receive_handler); // 持续接收
                };
                // 首次启动接收
                socket->async_receive(*receive_handler);
            } else {
                LOG_ERROR << "Failed to connect RSU";
                io.stop();
            }
        });

        io.run();
    } catch(const std::exception& e) {
        LOG_ERROR << "Main error: " << e.what();
        return 1;
    }
    return 0;
}
