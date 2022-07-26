#include <iostream>
#include "commons.hpp"

int main()
{
    secipc::SecureIpc server{secipc::SecureIpc::ServerTag()};

    server.handshake();
    auto data = server.receive();
    server.send(data.data(), data.size());
}