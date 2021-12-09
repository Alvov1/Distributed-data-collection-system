#include "Client.h"
void Client::tryConnect(unsigned attemptsCount) {
    for(auto i = 0; i < attemptsCount; ++i)
        if(connect(sock, (sockaddr *) &addr, sizeof(addr)) == 0)
            return;
        else
            Sleep(100);
    throw std::runtime_error("Unable to tryConnect to the server. ");
}
int Client::createCryptedConnection() {
    if(!CryptAcquireContext(&descCSP, nullptr, MS_ENHANCED_PROV, PROV_RSA_FULL, 0) &&
       !CryptAcquireContext(&descCSP, nullptr, MS_ENHANCED_PROV, PROV_RSA_FULL, CRYPT_NEWKEYSET))
        Error();

    /* Генерируем пару ключей. */
    if(CryptGenKey(descCSP, AT_KEYEXCHANGE, CRYPT_EXPORTABLE, &descKey) == 0)
        Error();
    if(!CryptGetUserKey(descCSP, AT_KEYEXCHANGE, &hPublicKey))
        Error();
    if(!CryptGetUserKey(descCSP, AT_KEYEXCHANGE, &hPrivateKey))
        Error();

    char expBuffer[256] = {0};
    DWORD len = 256;
    if(!CryptExportKey(hPublicKey, 0, PUBLICKEYBLOB,
                       NULL, (BYTE*) expBuffer, &len))
        Error();

    /* Посылаем публичный ключ серверу. */
    auto tLen = 255;
    for(; tLen >= 0 && expBuffer[tLen] == 0; --tLen);
    expBuffer[tLen + 1] = static_cast<char>(tLen + 1);

    if(send(sock, expBuffer, tLen + 2, 0) < 0)
        throw std::runtime_error("Error with sending: " + std::to_string(WSAGetLastError()));

    /* Получаем ответ от сервера. */
    char recvBuffer[256] = {0};
    if(recv(sock, recvBuffer, 256, 0) < 0)
        throw std::runtime_error("Error in receiving: " + std::to_string(WSAGetLastError()));

    /* Дешифруем полученное сообщение через приватный ключ. */
    tLen = 255;
    for(; tLen >= 0 && recvBuffer[tLen] == 0; --tLen);
    const auto sym = static_cast<unsigned char>(recvBuffer[tLen]);
    recvBuffer[tLen] = 0;
    if(!CryptImportKey(descCSP, (BYTE*) recvBuffer, sym, hPrivateKey, 0, &descKeyImpl))
        Error();

    return sock;
}
Client::Client(const std::string &IP, const std::string &Port) {
    init();

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if(sock < 0)
        throw std::runtime_error("Unable to create socket: " + std::to_string(WSAGetLastError()));

    addr.sin_family = AF_INET;
    addr.sin_port = htons(std::stoi(Port));
    addr.sin_addr.s_addr = inet_addr(IP.c_str());

    tryConnect();
    std::cout << "Connected successfully on IPv4 " << IP << " and port " << Port << "." << std::endl;

    sock = createCryptedConnection();
    std::cout << "Encrypted connection created." << std::endl;
}
int Client::makeRequest(const std::string& message) {
    char data[500] = {0};
    memset(receivingBuffer, 0, receivingSize);

    strcpy(data, message.c_str());
    unsigned dataLen = strlen(data);
    if(!CryptEncrypt(descKeyImpl, 0, TRUE, 0, (BYTE*) data, (DWORD*) &dataLen, 500))
        Error();

    if(send(sock, data, dataLen, 0) < 0)
        throw std::runtime_error("Data sending was not successful: " + std::to_string(WSAGetLastError()));

    if(recv(sock, receivingBuffer, receivingSize, 0) < 0)
        throw std::runtime_error("Data receiving was not successful: " + std::to_string(WSAGetLastError()));

    auto len = receivingSize - 1;
    for(; len >= 0 && receivingBuffer[len] == 0; --len);

    dataLen = len + 1;
    if(dataLen > 0 && !CryptDecrypt(descKeyImpl, NULL, TRUE, NULL, (BYTE*) receivingBuffer, (DWORD*)&dataLen))
        Error();
    return 0;
}
void Client::help(){
    static const char indent = '\t';
    std::cout << "Available options: " << std::endl;
    std::cout << indent << "1. Operating system info. " << std::endl;
    std::cout << indent << "2. Current time. " << std::endl;
    std::cout << indent << "3. Time since the launch of the system. " << std::endl;
    std::cout << indent << "4. Info about memory used. " << std::endl;
    std::cout << indent << "5. Info about connected disks. " << std::endl;
    std::cout << indent << "6. Available space on local disks. " << std::endl;
    std::cout << indent << "7. Permissions for file/directory/register key. " << std::endl;
    std::cout << indent << "8. Info about the owner of file/directory/register key. " << std::endl;
    std::cout << indent << "9. Exit. " << std::endl;
}
int Client::callCommand() {
    static std::string str;
    std::getline(std::cin, str);

    try {
        unsigned choice = std::stoi(str) % 9;
        if(choice > 6) {
            static std::string type = "\t1. File.\n\t2. Directory.\n\t3. Register key.\n";
            std::cout << type;

            std::string typeNumStr;
            std::getline(std::cin, typeNumStr);
            unsigned typeNum = (std::stoi(typeNumStr) - 1) % 3;

            std::string filename;
            std::cout << "Enter the name of the file/directory/register key." << std::endl;
            std::getline(std::cin, filename);

            makeRequest(std::to_string(choice) + std::to_string(typeNum) + filename);
        } else makeRequest(std::to_string(choice));

        if(choice == 0) return 1;
        std::cout << receivingBuffer << std::endl;
    }
    catch (std::invalid_argument& except) {
        std::cout << "Please enter a proper value. " << std::endl;
    }
    return 0;
}
void Client::start() {
    while(true) {
        help();
        if(callCommand() == 1)
            break;
    }
}
Client::~Client() {
    s_close();
    deinit();
}





