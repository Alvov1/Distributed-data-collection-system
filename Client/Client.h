#ifndef CLIENT_CLIENT_H
#define CLIENT_CLIENT_H

#define WIN32_LEAN_AND_MEAN
#include <iostream>
#include <fstream>
#include <string>
#include <windows.h>
#include <winsock2.h>
#include <wincrypt.h>
#include <ws2tcpip.h> // Директива линковщику: использовать библиотеку сокетов
#pragma comment(lib, "ws2_32.lib")
#pragma warning(disable : 4996)

class Client {
    std::string IP;
    std::string Port;

    int sock = 0;
    sockaddr_in addr{};

    HCRYPTPROV descCSP;
    HCRYPTKEY descKey;
    HCRYPTKEY descKeyImpl;
    HCRYPTKEY hPublicKey;
    HCRYPTKEY hPrivateKey;

    static const auto receivingSize = 3072;
    char receivingBuffer[receivingSize] = {0};

    void tryConnect(unsigned attemptsCount = 10);

    static int init() {
        // Для Windows следует вызвать WSAStartup перед началом использования сокетов
        WSADATA wsa_data;
        return (0 == WSAStartup(MAKEWORD(2, 2), &wsa_data));
    }
    static void deinit() {
        // Для Windows следует вызвать WSACleanup в конце работы
        WSACleanup();
    }
    void s_close() const {
        closesocket(sock);
    }
    static void Error() {
        std::cerr << "Error: " << GetLastError() << std::endl;
    }

    int createCryptedConnection();
    static void help();
    int callCommand();
    int makeRequest(const std::string& message);

public:
    Client(const std::string& IP = "127.0.0.1", const std::string& Port = "9000");
    void start();
    ~Client();
};
#endif //CLIENT_CLIENT_H
