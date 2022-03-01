#include <iostream>
#include <kissnet.hpp>

int main() {
    Kissnet::Error::lAbortOnFatalError = false;
    Kissnet::Error::handle("test what code would be called on Error when built without exception\n");
    Kissnet::Error::pCallback = [](const std::string &str, void *ctx) {
        std::cerr << "this is the pCallback : ";
        std::cerr << str;
        (void) ctx;
    };
    Kissnet::Error::handle("test our custom pCallback");
    return 0;
}
