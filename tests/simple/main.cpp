#include <iostream>
#include <kissnet.hpp>

int main() {
    std::cout << "hello world" << std::endl;

    //if comoiler crash, theses types doens't exist
    (void) Kissnet::Protocol::TCP;
    (void) Kissnet::Protocol::UDP;

    //give me 2k of memory, please!
    Kissnet::Buffer<2048> lTestBuffer;

    std::cout << "Buffer size : " << lTestBuffer.size() << '\n';
    std::cout << "Buffer data start mAddress : 0x" << std::hex << (size_t) lTestBuffer.data() << std::dec << '\n';

    //If a byte is not a single byte, It will not work
    static_assert(sizeof(std::byte) == 1);

    //Can manipulate the mValue of a byte directly?
    const auto size = lTestBuffer.size();

    //setting bytes insdie the Buffer to a specif mValue
    for (size_t i = 0; i < size; ++i)
        lTestBuffer[i] = std::byte{static_cast<uint8_t>(i % 0xFF)};

    //Print them
    for (size_t i = 0; i < size; ++i)
        std::cout << std::hex << std::to_integer<int>(lTestBuffer[i]) << std::dec << '\n';

    return 0;
}
