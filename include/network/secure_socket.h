#pragma once
#include <C:/boost/include/boost-1_87/boost/asio.hpp>
#include <vector>
#include <memory>
#include <boost/asio/ip/tcp.hpp>
#include "crypto/sm2_wrapper.h"
#include "crypto/sm4_wrapper.h"
#include "crypto/sm3_wrapper.h"

namespace io = boost::asio;

class SecureSocket : public std::enable_shared_from_this<SecureSocket> {
public:
    enum class Mode { V2V, V2I };
    using Ptr = std::shared_ptr<SecureSocket>;
    SecureSocket(boost::asio::io_context& io, Mode mode);
    boost::asio::ip::tcp::socket& socket() { return socket_; } // 允许外部访问socket
    
    // 连接模式枚举
    enum class Mode {
        V2V,    // 车车直连
        V2I     // 车路通信
    };

    // 构造函数（传入io_context和运行模式）
    SecureSocket(io::io_context& io, Mode mode);
    
    io::ip::tcp::socket& socket() { return socket_; }
    // 异步连接（带回调函数）
    void async_connect(const std::string& ip, uint16_t port, 
                      std::function<void(bool)> callback);

    // 异步发送加密数据
    void async_send(const std::vector<uint8_t>& data,
                   std::function<void(bool)> callback);

    // 异步接收数据（自动解密）
    void async_receive(std::function<void(std::vector<uint8_t>, bool)> callback);

    // 获取对端证书信息
    std::string get_peer_cert() const { return peer_cert_; }

private:
    boost::asio::ip::tcp::socket socket_; // 底层socket对象
    // 初始化握手协议（SM2双向认证）
    void perform_handshake(std::function<void(bool)> callback);

    // 生成会话密钥
    void generate_session_key();

    // 加密数据（SM4-CTR + SM3-HMAC）
    std::vector<uint8_t> encrypt_data(const std::vector<uint8_t>& plaintext);

    // 解密验证数据
    std::pair<std::vector<uint8_t>, bool> 
    decrypt_data(const std::vector<uint8_t>& ciphertext);

    // 成员变量
    io::ip::tcp::socket socket_;
    Mode mode_;
    std::vector<uint8_t> session_key_;
    std::vector<uint8_t> iv_;
    std::string peer_cert_;
    std::vector<uint8_t> local_priv_key_;
    std::vector<uint8_t> local_pub_key_;
};
