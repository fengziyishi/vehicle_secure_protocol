#include "network/secure_socket.h"
#include "crypto/sm2_wrapper.h"
#include "crypto/sm4_wrapper.h"
#include "crypto/sm3_wrapper.h"
#include "utils/logger.h"
#include <boost/asio.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ip/address.hpp>  
#include <boost/endian/conversion.hpp>

using namespace boost::asio;
using namespace boost::system;

SecureSocket::SecureSocket(io::io_context& io, Mode mode)
    : socket_(io.get_executor()),  
      mode_(mode) {
    SM2Wrapper::generate_key_pair(local_pub_key_, local_priv_key_);
}

void SecureSocket::async_connect(const std::string& ip, uint16_t port,
                                std::function<void(bool)> callback) {
    ip::tcp::endpoint ep(ip::make_address(ip), port);
    socket_.async_connect(ep, [this, callback](const error_code& ec) {
        if(ec) {
            LOG_ERROR << "Connect failed: " << ec.message();
            callback(false);
            return;
        }
        LOG_DEBUG << "TCP connected, starting handshake...";
        perform_handshake(callback);
    });
}

void SecureSocket::perform_handshake(std::function<void(bool)> callback) {
    // 1. 交换公钥证书和签名
    auto self = shared_from_this();
    
    // 1.1 生成本地公钥的签名
    std::vector<uint8_t> local_pub_key_signature;
    if (!SM2Wrapper::sign(local_priv_key_, local_pub_key_, local_pub_key_signature)) {
        LOG_ERROR << "Sign local public key failed";
        callback(false);
        return;
    }

    // 1.2 发送本地公钥和签名
    std::vector<uint8_t> handshake_data;
    handshake_data.insert(handshake_data.end(), local_pub_key_.begin(), local_pub_key_.end());
    handshake_data.insert(handshake_data.end(), local_pub_key_signature.begin(), local_pub_key_signature.end());

    async_write(socket_, buffer(handshake_data), [this, self, callback](error_code ec, size_t) {
        if(ec) {
            LOG_ERROR << "Send public key and signature failed: " << ec.message();
            callback(false);
            return;
        }

        // 接收对方公钥和签名
        auto peer_handshake_data = std::make_shared<std::vector<uint8_t>>(SM2Wrapper::PUBLIC_KEY_SIZE + SM2Wrapper::SIGNATURE_SIZE);
        async_read(socket_, buffer(*peer_handshake_data), [this, self, peer_handshake_data, callback](error_code ec, size_t) {
            if(ec) {
                LOG_ERROR << "Receive public key and signature failed: " << ec.message();
                callback(false);
                return;
            }

            // 1.3 验证对方签名
            std::vector<uint8_t> peer_pub_key(peer_handshake_data->begin(), peer_handshake_data->begin() + SM2Wrapper::PUBLIC_KEY_SIZE);
            std::vector<uint8_t> peer_pub_key_signature(peer_handshake_data->begin() + SM2Wrapper::PUBLIC_KEY_SIZE, peer_handshake_data->end());

            if (!SM2Wrapper::verify(peer_pub_key, peer_pub_key, peer_pub_key_signature)) {
                LOG_ERROR << "Verify peer public key signature failed";
                callback(false);
                return;
            }

            // 2. 密钥协商
            if(!SM2Wrapper::ecdh(local_priv_key_, peer_pub_key, session_key_)) {
                LOG_ERROR << "ECDH key exchange failed";
                callback(false);
                return;
            }

            // 3. 初始化向量生成
            iv_.resize(SM4Cipher::IV_SIZE);
            std::generate(iv_.begin(), iv_.end(), [](){ return rand() % 256; });

            // 4. 验证握手完成
            LOG_INFO << "Handshake completed. Session key established";
            callback(true);
        });
    });
}

void SecureSocket::async_send(const std::vector<uint8_t>& data,
                            std::function<void(bool)> callback) {
    auto self = shared_from_this();
    io::post(socket_.get_executor(), [this, self, data, callback]() {
        try {
            auto encrypted = encrypt_data(data);
            uint32_t len = encrypted.size();
            boost::endian::native_to_big_inplace(len);

            // 发送长度头+加密数据
            std::vector<io::const_buffer> buffers;
            buffers.push_back(io::buffer(&len, sizeof(len)));
            buffers.push_back(io::buffer(encrypted));

            async_write(socket_, buffers, [callback](error_code ec, size_t) {
                callback(!ec);
            });
        } catch(const std::exception& e) {
            LOG_ERROR << "Encrypt failed: " << e.what();
            callback(false);
        }
    });
}

void SecureSocket::async_receive(std::function<void(std::vector<uint8_t>, bool)> callback) {
    auto self = shared_from_this();
    
    // 读取长度头
    auto len_buf = std::make_shared<uint32_t>(0);
    async_read(socket_, buffer(len_buf.get(), sizeof(uint32_t)),
        [this, self, len_buf, callback](error_code ec, size_t) {
            if(ec) {
                LOG_ERROR << "Read length header failed: " << ec.message();
                callback({}, false);
                return;
            }

            boost::endian::big_to_native_inplace(*len_buf);
            if(*len_buf > 10*1024*1024) { // 限制10MB
                LOG_ERROR << "Invalid data size: " << *len_buf;
                callback({}, false);
                return;
            }

            // 读取加密数据
            auto data_buf = std::make_shared<std::vector<uint8_t>>(*len_buf);
            async_read(socket_, buffer(*data_buf), 
                [this, self, data_buf, callback](error_code ec, size_t) {
                    if(ec) {
                        LOG_ERROR << "Read data failed: " << ec.message();
                        callback({}, false);
                        return;
                    }

                    try {
                        auto [plaintext, valid] = decrypt_data(*data_buf);
                        callback(plaintext, valid);
                    } catch(const std::exception& e) {
                        LOG_ERROR << "Decrypt failed: " << e.what();
                        callback({}, false);
                    }
                });
        });
}

std::vector<uint8_t> SecureSocket::encrypt_data(const std::vector<uint8_t>& plaintext) {
    // HMAC计算
    std::vector<uint8_t> hmac;
    SM3Hasher::hash(plaintext, hmac);

    // 加密数据
    std::vector<uint8_t> ciphertext;
    SM4Cipher::ctr_crypt(session_key_, iv_, plaintext, ciphertext);

    // 构造数据包：HMAC + 密文
    std::vector<uint8_t> packet;
    packet.reserve(hmac.size() + ciphertext.size());
    packet.insert(packet.end(), hmac.begin(), hmac.end());
    packet.insert(packet.end(), ciphertext.begin(), ciphertext.end());
    return packet;
}

std::pair<std::vector<uint8_t>, bool> 
SecureSocket::decrypt_data(const std::vector<uint8_t>& packet) {
    if(packet.size() < SM3Hasher::DIGEST_SIZE) {
        throw std::runtime_error("Invalid packet size");
    }

    // 分离HMAC和密文
    auto hmac_received = std::vector<uint8_t>(
        packet.begin(), packet.begin() + SM3Hasher::DIGEST_SIZE);
    auto ciphertext = std::vector<uint8_t>(
        packet.begin() + SM3Hasher::DIGEST_SIZE, packet.end());

    // 解密数据
    std::vector<uint8_t> plaintext;
    SM4Cipher::ctr_crypt(session_key_, iv_, ciphertext, plaintext);

    // 验证HMAC
    std::vector<uint8_t> hmac_calculated;
    SM3Hasher::hash(plaintext, hmac_calculated);

    bool valid = (hmac_calculated == hmac_received);
    return {plaintext, valid};
}
