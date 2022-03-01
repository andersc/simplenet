#include <iostream>
#include <kissnet.hpp>

int main() {
    {
        Kissnet::Endpoint lByStringPort("www.google.com", 80);
        if (lByStringPort.empty()) {
            std::cout << "endpoint empty is empty" << std::endl;
            return 1;
        } else {
            std::cout << "endpoint empty is NOT empty" << std::endl;
        }
        std::cout << lByStringPort.address() << std::endl;
        std::cout << lByStringPort.port() << std::endl;
    }

    {
        Kissnet::Endpoint lByString("www.google.com:80");
        if (lByString.empty()) {
            std::cout << "endpoint empty is empty" << std::endl;
            return 1;
        } else {
            std::cout << "endpoint empty is NOT empty" << std::endl;
        }
        std::cout << lByString.address() << std::endl;
        std::cout << lByString.port() << std::endl;
    }

    {
        bool lShouldFail = false;
        try {
            lShouldFail = false;
            Kissnet::Endpoint lByFalseString("www.google.com:xxxx");
        } catch (const std::runtime_error& e) {
            std::cout << "Should say invalid port (0) -> " << e.what() << std::endl;
            lShouldFail = true;
        }
        if (!lShouldFail) {
            return EXIT_FAILURE;
        }

        try {
            lShouldFail = false;
            Kissnet::Endpoint lByFalseString("www.google.com", 0);
        } catch (const std::runtime_error& e) {
            std::cout << "Should say invalid port (0) -> " << e.what() << std::endl;
            lShouldFail = true;
        }
        if (!lShouldFail) {
            return EXIT_FAILURE;
        }

        try {
            lShouldFail = false;
            Kissnet::Endpoint lByFalseString("www.google.com");
        } catch (const std::runtime_error& e) {
            std::cout << "Should say is not address:port -> " << e.what() << std::endl;
            lShouldFail = true;
        }
        if (!lShouldFail) {
            return EXIT_FAILURE;
        }

        try {
            lShouldFail = false;
            Kissnet::Endpoint lByFalseString("www.google.com:");
        } catch (const std::runtime_error& e) {
            std::cout << "Should say last character is : -> " << e.what() << std::endl;
            lShouldFail = true;
        }
        if (!lShouldFail) {
            return EXIT_FAILURE;
        }
    }

    return 0;
}
