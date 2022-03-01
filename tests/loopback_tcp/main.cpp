#include <iostream>
#include <thread>
#include <chrono>

#include <kissnet.hpp>

void loopBackTCP(const std::string &rListenAddress, const std::string &rConnectAddress, const int lPort) {
    std::thread([&] {
        Kissnet::TCPSocket lListener(Kissnet::Endpoint(rListenAddress, lPort));
        lListener.setNonBlocking();
        lListener.bind();
        lListener.listen();

        std::string lHelloGoodbye = "Hello hello, I don't know why you say goodbye, I say hello!";
        for (size_t i = 0; i < 50; ++i) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            if (auto lSocket = lListener.accept(); lSocket.is_valid()) {
                std::cout << "Accepted connect" << std::endl;
                lSocket.send(reinterpret_cast<const std::byte *>(lHelloGoodbye.c_str()), lHelloGoodbye.size());
            } else {
                std::cout << "No connections to accept..." << std::endl;
            }
        }
        lListener.close();
    }).detach();

    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    Kissnet::TCPSocket lAsocket(Kissnet::Endpoint(rConnectAddress, lPort));
    lAsocket.connect();

    //Receive data into a Buffer
    Kissnet::Buffer<4096> lBuffer;

    //Get the data, and the lengh of data
    const auto[lData, lStatus] = lAsocket.recv(lBuffer);
    lAsocket.close();

    //To print it as a good old C string, add a null terminator
    if (lData < lBuffer.size()) {
        lBuffer[lData] = std::byte{'\0'};
    }

    //Print the raw data as text into the terminal (should display html/css code here)
    std::cout << reinterpret_cast<const char *>(lBuffer.data()) << std::endl;
}

int main() {
    // Increment mPort number to avoid bind failure on TIME-WAIT connections
    loopBackTCP("0.0.0.0", "127.0.0.1", 6666);
    loopBackTCP("::", "::1", 6667);

    return EXIT_SUCCESS;
}
