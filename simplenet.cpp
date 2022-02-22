//
// Created by Anders Cedronius on 2022-02-22.
//

#include <iostream>
#include "kissnet.hpp"

int main() {
    std::cout << "Hello simple net." << std::endl;
    auto endpoint = kissnet::Endpoint("127.0.0.1", 1234);
    return 0;
}
