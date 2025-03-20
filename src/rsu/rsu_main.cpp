#include "network/secure_socket.h"
#include "utils/logger.h"
#include <boost/asio.hpp>
#include <unordered_map>

namespace sys = boost::system; // 简化命名空间别名
using boost::asio::ip::tcp;

using namespace boost::asio;

class RSUServer {
public:
    RSUServer(io::io_context& io, uint16_t port)
        : acceptor_(io, ip::tcp::endpoint(ip::tcp::v4(), port)) {
        start_accept();
    }

private:
    void start_accept() {
        auto socket = std::make_shared<SecureSocket>(acceptor_.get_executor().context(), 
                                                    SecureSocket::Mode::V2I);
        acceptor_.async_accept(socket->socket(), 
            [this, socket](sys::error_code ec) {
                if(!ec) {
                    LOG_INFO << "New vehicle connected: " 
                            << socket->socket().remote_endpoint();
                    
                    handle_connection(socket);
                } else {
                    LOG_ERROR << "Accept error: " << ec.message();
                }
                start_accept();
            });
    }

    void handle_connection(SecureSocket::Ptr socket) {
        socket->async_connect("", 0, [this, socket](bool success) { // 空参数表示服务端模式
            if(!success) {
                LOG_WARN << "Vehicle handshake failed";
                return;
            }

            // 注册车辆
            std::string vehicle_id = "VEH_" + std::to_string(rand());
            registered_vehicles_[vehicle_id] = socket;

            // 接收车辆数据
            socket->async_receive([this, vehicle_id](std::vector<uint8_t> data, bool valid) {
                if(valid) {
                    LOG_DEBUG << "Received data from " << vehicle_id 
                            << ", size: " << data.size();
                    // 处理数据并广播...
                } else {
                    LOG_WARN << "Invalid data from " << vehicle_id;
                }
            });

            // 定时发送路况信息
            send_traffic_updates(socket);
        });
    }

    void send_traffic_updates(SecureSocket::Ptr socket) {
        auto timer = std::make_shared<steady_timer>(acceptor_.get_executor());
        timer->expires_after(std::chrono::seconds(30));
        
        timer->async_wait([this, socket, timer](sys::error_code ec) {
            if(ec) return;

            std::vector<uint8_t> traffic_data = {/* 生成路况数据 */};
            socket->async_send(traffic_data, [](bool success){
                if(!success) LOG_WARN << "Traffic update send failed";
            });

            send_traffic_updates(socket); // 循环发送
        });
    }

    ip::tcp::acceptor acceptor_;
    std::unordered_map<std::string, SecureSocket::Ptr> registered_vehicles_;
};

int main() {
    Logger::init("rsu.log", Logger::Level::Info);
    io::io_context io;

    try {
        RSUServer server(io, 5000);
        LOG_INFO << "RSU server started on port 5000";
        io.run();
    } catch(const std::exception& e) {
        LOG_ERROR << "RSU fatal error: " << e.what();
        return 1;
    }
    return 0;
}
