#include <iostream>
#include <thread>

#include <kissnet.hpp>

void loopBackUDP(const std::string &rSendAddress, const std::string &rRecvAddress) {
    //Socket used to send, the "endpoint" is the destination of the data
    Kissnet::UDPSocket lASocket(Kissnet::Endpoint(rSendAddress, 6666));

    //Socket used to receive, the "endpoint" is where to listen to data
    Kissnet::UDPSocket lBSocket(Kissnet::Endpoint(rRecvAddress, 6666));
    lBSocket.bind();

    //Byte Buffer
    Kissnet::Buffer<16> lBuff;

    //Build data to send (flat array of bytes
    for (unsigned char i = 0; i < 16; i++) {
        lBuff[i] = std::byte{i};
    }

    //Send data
    lASocket.send(lBuff.data(), 16);

    //We do know, for the sake of the example, that there are 16 bytes to get lFrom the network
    Kissnet::Buffer<16> lRecvBuff;

    //Actually print bytes_available
    std::cout << "avaliable in UDP socket : " << lBSocket.bytes_available() << " bytes" << std::endl;

    //You receive in the same way
    auto[lReceivedBytes, lStatus] = lBSocket.recv(lRecvBuff);
    const auto lFrom = lBSocket.getRecvEndpoint();

    //Print the data
    std::cout << "Received: ";

    for (unsigned char i = 0; i < 16; i++) {
        std::cout << std::hex << std::to_integer<int>(lRecvBuff[i]) << std::dec << ' ';
    }

    //Print who send the data
    std::cout << "From: " << lFrom.address() << ' ' << lFrom.port() << std::endl;
}

int main() {
    loopBackUDP("127.0.0.1", "0.0.0.0");
    loopBackUDP("::1", "::");

    //So long, and thanks for all the fish
    return EXIT_SUCCESS;
}
