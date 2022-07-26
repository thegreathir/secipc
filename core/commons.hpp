#ifndef COMMONS_H_
#define COMMONS_H_

#include <cstdint>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <vector>

#include <boost/interprocess/ipc/message_queue.hpp>

namespace secipc
{

constexpr char CERT_FILE[] = "cert.pem";
constexpr char KEY_FILE[] = "key.pem";

constexpr std::size_t MAX_MESSAGE_SIZE = 1024;

constexpr std::size_t MAX_MESSAGE_NUMBER = 64;

constexpr char MESSAGE_QUEUE_NAME1[] = "ipc_ssl_message_queue1";
constexpr char MESSAGE_QUEUE_NAME2[] = "ipc_ssl_message_queue2";

struct SslContext {
    SslContext(bool server);
    ~SslContext();

    SslContext(const SslContext& other) = delete;
    SslContext(SslContext&& other) = default;
    SslContext& operator=(const SslContext& other) = delete;
    SslContext& operator=(SslContext&& other) = default;

    static void throw_ssl_error();

    SSL_CTX* ctx;
    SSL* ssl;
    BIO* internal_bio;
    BIO* external_bio;

    char buffer[MAX_MESSAGE_SIZE];
};

class Ipc {
public:
    struct ClientTag{};
    struct ServerTag{};
    Ipc(ClientTag);
    Ipc(ServerTag);

    ~Ipc();

    Ipc(const Ipc& other) = default;
    Ipc(Ipc&& other) = default;
    Ipc& operator=(const Ipc& other) = default;
    Ipc& operator=(Ipc&& other) = default;

    void send(const char* buffer, std::size_t size);
    std::size_t receive(char* buffer);
private:
    boost::interprocess::message_queue send_message_queue;
    boost::interprocess::message_queue receive_message_queue;
};

class SecureIpc {
public:
    struct ClientTag{};
    struct ServerTag{};
    using ByteArray = std::vector<uint8_t>;

    SecureIpc(ClientTag);
    SecureIpc(ServerTag);

    void handshake();
    void send(const uint8_t* byte_array, std::size_t byte_array_size);
    ByteArray receive();
private:
    SslContext ctx;
    Ipc ipc;
};

}

#endif
