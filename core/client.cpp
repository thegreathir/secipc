#include <iostream>
#include "commons.hpp"

int main() {
    secipc::SecureIpc client{secipc::SecureIpc::ClientTag()};

    client.handshake();
    std::cout << "Enter message: ";
    std::string message;
    std::cin >> message;

    client.send(reinterpret_cast<const uint8_t*>(message.c_str()), message.size());
    auto data = client.receive();
    std::cout << std::string(
        reinterpret_cast<const char*>(data.data()), data.size()
    ) << std::endl;
}