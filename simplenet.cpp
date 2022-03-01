//
// Created by Anders Cedronius on 2022-02-22.
//

// UDP Example

#include <iostream>
#include "kissnet.hpp"

int main() {

    //Define a Buffer. The size should not exceed max UDP payload
    const int BUFFER_SIZE = 300;

    std::cout << "Hello simple net." << std::endl;
#ifdef OPENSSL_VERSION_NUMBER
    std::cout << "OpenSSL is available" << std::endl;
#endif
    //Create a sender Buffer of BUFFER_SIZE bytes
    Kissnet::Buffer<BUFFER_SIZE> lSendBuff;
    //Create a recieve Buffer of BUFFER_SIZE bytes
    Kissnet::Buffer<BUFFER_SIZE> lRecvBuff;
    //Generate a vector of data (Value 0 -> 127)
    for (uint64_t x = 0; x<lSendBuff.size(); x++) lSendBuff[x]=(std::byte)x;

    //Create a UDP socket for the listener/server
    Kissnet::UDPSocket lUDPSocketListen(Kissnet::Endpoint("127.0.0.1", 1234));
    //Bind it to the host IP defined and wait for data
    lUDPSocketListen.bind();

    //Create a UDP socket for the sender
    Kissnet::UDPSocket lUDPSocketSend(Kissnet::Endpoint("127.0.0.1", 1234));
    //Send the bytes in the Buffer
    lUDPSocketSend.send(lSendBuff.data(), lSendBuff.size());

    //Get the bytes from the listen socket
    auto[lReceivedBytes, lStatus] = lUDPSocketListen.recv(lRecvBuff);
    if (!lReceivedBytes || lStatus != Kissnet::SocketStatus::VALID) {
        std::cout << "There was a error reading the data." << std::endl;
        return EXIT_FAILURE;
    }

    //Did we get the correct amount
    if (lReceivedBytes != BUFFER_SIZE) {
        std::cout << "Got data but it's wrong size." << std::endl;
        return EXIT_FAILURE;
    }

    //Is the vector intact
    for (uint64_t x = 0; x<lRecvBuff.size(); x++) {
        if ((uint8_t)lRecvBuff[x] != (uint8_t)x) {
            std::cout << "Data not as expected." << std::endl;
            return EXIT_FAILURE;
        }
    }

    //The sockets will garbage collect themselves when going out of scope
    //But it's also OK to explicitly close them when done.
    lUDPSocketSend.close();
    lUDPSocketListen.close();

    std::cout << "Got all data and it was correct payload, All good!" << std::endl;
    return EXIT_SUCCESS;
}
