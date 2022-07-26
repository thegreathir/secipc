#include "commons.hpp"

void secipc::SslContext::throw_ssl_error() {
    auto error_code = ERR_get_error();
    auto error_message = ERR_error_string(error_code, nullptr);
    throw std::runtime_error(error_message);
}

secipc::SslContext::SslContext(bool client) {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();


    const SSL_METHOD* method;
    if (client)
        method = TLS_client_method();
    else
        method = TLS_server_method();

    ctx = SSL_CTX_new(method);
    if (!ctx)
        throw_ssl_error();

    const long flags = SSL_EXT_TLS1_3_ONLY;
    SSL_CTX_set_options(ctx, flags);

    SSL_CTX_set_ecdh_auto(ctx, 1);

    if (SSL_CTX_use_certificate_file(ctx, CERT_FILE, SSL_FILETYPE_PEM) <= 0)
        throw_ssl_error();

    if (SSL_CTX_use_PrivateKey_file(ctx, KEY_FILE, SSL_FILETYPE_PEM) <= 0)
        throw_ssl_error();

    ssl = SSL_new(ctx);

    BIO_new_bio_pair(&internal_bio, 0, &external_bio, 0);
    SSL_set_bio(ssl, internal_bio, internal_bio);

    SSL_set_bio(ssl, internal_bio, internal_bio);

    if (client)
        SSL_set_connect_state(ssl);
    else
        SSL_set_accept_state(ssl);
}

secipc::SslContext::~SslContext()
{
    SSL_CTX_free(ctx);
    BIO_free(external_bio);
    EVP_cleanup();
}

secipc::Ipc::Ipc(ClientTag)
: send_message_queue(
    boost::interprocess::open_only,
    MESSAGE_QUEUE_NAME2)
, receive_message_queue(
    boost::interprocess::open_only,
    MESSAGE_QUEUE_NAME1)
{}

secipc::Ipc::Ipc(ServerTag)
: send_message_queue(
    boost::interprocess::create_only,
    MESSAGE_QUEUE_NAME1,
    MAX_MESSAGE_NUMBER,
    MAX_MESSAGE_SIZE)
, receive_message_queue(
    boost::interprocess::create_only,
    MESSAGE_QUEUE_NAME2,
    MAX_MESSAGE_NUMBER,
    MAX_MESSAGE_SIZE)
{}

secipc::Ipc::~Ipc()
{
    boost::interprocess::message_queue::remove(MESSAGE_QUEUE_NAME1);
    boost::interprocess::message_queue::remove(MESSAGE_QUEUE_NAME2);
}

void secipc::Ipc::send(const char* buffer, std::size_t size)
{
    send_message_queue.send(buffer, size, 0);
}

std::size_t secipc::Ipc::receive(char* buffer)
{
    unsigned int priority;
    std::size_t size;
    receive_message_queue.receive(buffer, MAX_MESSAGE_SIZE, size, priority);
    return size;

}

secipc::SecureIpc::SecureIpc(ClientTag)
: ctx(false)
, ipc(Ipc::ClientTag())
{

}

secipc::SecureIpc::SecureIpc(ServerTag)
: ctx(true)
, ipc(Ipc::ServerTag())
{

}

void secipc::SecureIpc::handshake() {
    while (!SSL_is_init_finished(ctx.ssl)) {
        SSL_do_handshake(ctx.ssl);

        const int bytes_to_write = BIO_read(ctx.external_bio, ctx.buffer, secipc::MAX_MESSAGE_SIZE);
        if (bytes_to_write > 0)
            ipc.send(ctx.buffer, bytes_to_write);
        else {
            const int received_bytes = ipc.receive(ctx.buffer);
            if (received_bytes > 0)
                BIO_write(ctx.external_bio, ctx.buffer, received_bytes);
        }
    }
}

void secipc::SecureIpc::send(const uint8_t* byte_array, std::size_t byte_array_size) {
    SSL_write(ctx.ssl, byte_array, byte_array_size);
    while(true) {

        int bytes_to_write = BIO_read(ctx.external_bio, ctx.buffer, secipc::MAX_MESSAGE_SIZE);

        if (bytes_to_write > 0)
            ipc.send(ctx.buffer, bytes_to_write);
        else
            break;
    }
}

auto secipc::SecureIpc::receive() -> ByteArray {
    int received_decrypted_bytes = 0;
    do {
        const int received_bytes = ipc.receive(ctx.buffer);
        if (received_bytes > 0)
            BIO_write(ctx.external_bio, ctx.buffer, received_bytes);

        received_decrypted_bytes = SSL_read(ctx.ssl, ctx.buffer, secipc::MAX_MESSAGE_SIZE);

    } while (received_decrypted_bytes <= 0);

    ByteArray result;
    std::copy_n(ctx.buffer, received_decrypted_bytes, std::back_inserter(result));
    return result;
}