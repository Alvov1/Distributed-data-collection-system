#include <iostream>
#include <string>
#include "Client.h"

int main(int argc, const char **argv) {
    setlocale(LC_ALL, "Russian");
    std::string IP;
    std::string Port;

    if (argc < 3) {
        std::cout << "Enter IPv4 address. " << std::endl;
        std::getline(std::cin, IP);
        std::cout << "Enter Port. " << std::endl;
        std::getline(std::cin, Port);
    } else {
        IP = std::string(argv[1]);
        Port = std::string(argv[2]);
    }

    Client client(IP, Port);
    client.start();
    return 0;
}
