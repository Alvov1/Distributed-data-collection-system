#include <winsock2.h>
#include <windows.h>
#include <mswsock.h>
#include <aclapi.h>
#include <cstdio>
#include <iostream>
#include <string>
#include <Sddl.h>

#pragma comment (lib, "ws2_32.lib" )
#pragma comment (lib, "mswsock.lib")
#pragma warning (disable: 4996)
#define MAX_CLIENTS (100)
#define WIN32_LEAN_AND_MEAN

const unsigned receivingBufferSize = 512;
const unsigned sendingBufferSize = 3072;

struct clientInfo {
    int socket;
    CHAR receivingBuffer[receivingBufferSize]; // Буфер приема
    CHAR sendingBuffer[sendingBufferSize]; // Буфер отправки

    unsigned int receiveDataLength; // Принято данных
    unsigned int sendDataLength; // Данных в буфере отправки
    unsigned int sz_send; // Данных отправлено

    // Структуры OVERLAPPED для уведомлений о завершении
    OVERLAPPED overlap_recv;
    OVERLAPPED overlap_send;
    OVERLAPPED overlap_cancel;
    DWORD flags_recv; // Флаги для WSARecv
};
// Прослушивающий сокет и все сокеты подключения хранятся
// в массиве структур (вместе с overlapped и буферами)
struct clientInfo Clients[1 + MAX_CLIENTS];
int acceptedSocket;
HANDLE ioPort;
HCRYPTPROV descCSP = 0;
HCRYPTKEY descKey = 0;
HCRYPTKEY descKeyOpen = 0;

/* ------------------------------------------------------------------------------ */
int isStringReceived(DWORD idx, int *len) {
    for (DWORD i = 0; i < Clients[idx].receiveDataLength; i++)
        if (Clients[idx].receivingBuffer[i] == '\n') {
            *len = (int) (i + 1);
            return 1;
        }

    if (Clients[idx].receiveDataLength == sizeof(Clients[idx].receivingBuffer)) {
        *len = sizeof(Clients[idx].receivingBuffer);
        return 1;
    }
    return 1;
}
std::string ipToString(unsigned ip) {
    return {std::to_string((ip >> 24) & 0xff) + "." + std::to_string((ip >> 16) & 0xff) +
            "." + std::to_string((ip >> 8) & 0xff) + "." + std::to_string((ip) & 0xff)};
}
// Функция стартует операцию чтения из сокета
void schedule_read(DWORD idx) {
    WSABUF buf;
    buf.buf = Clients[idx].receivingBuffer + Clients[idx].receiveDataLength;
    buf.len = sizeof(Clients[idx].receivingBuffer) - Clients[idx].receiveDataLength;
    memset(&Clients[idx].overlap_recv, 0, sizeof(OVERLAPPED));
    Clients[idx].flags_recv = 0;
    WSARecv(Clients[idx].socket, &buf, 1, nullptr, &Clients[idx].flags_recv, &Clients[idx].overlap_recv, nullptr);
}
// Функция стартует операцию отправки подготовленных данных в сокет
void schedule_write(DWORD idx) {
    WSABUF buf;
    buf.buf = Clients[idx].sendingBuffer + Clients[idx].sz_send;
    buf.len = Clients[idx].sendDataLength - Clients[idx].sz_send;
    memset(&Clients[idx].overlap_send, 0, sizeof(OVERLAPPED));
    WSASend(Clients[idx].socket, &buf, 1, nullptr, 0, &Clients[idx].overlap_send, nullptr);
}
// Функция добавляет новое принятое подключение клиента
void add_accepted_connection() {
    for (auto index = 0; index < sizeof(Clients) / sizeof(Clients[0]); index++) {
        if (Clients[index].socket == 0) {
            sockaddr_in* local_addr = nullptr;
            sockaddr_in* remote_addr = nullptr;

            int local_addr_sz, remote_addr_sz;
            GetAcceptExSockaddrs(
                    Clients[0].receivingBuffer,
                    Clients[0].receiveDataLength,
                    sizeof(sockaddr_in) + 16,
                    sizeof(sockaddr_in) + 16,
                    (sockaddr **) &local_addr,
                    &local_addr_sz,
                    (sockaddr **) &remote_addr,
                    &remote_addr_sz);

            unsigned int ip = 0;
            if (remote_addr)
                ip = ntohl(remote_addr->sin_addr.s_addr);

            std::cout << "Client " << index << " connected: " << ipToString(ip) << std::endl;

            Clients[index].socket = acceptedSocket;

            // Связь сокета с портом IOCP, в качестве key используется индекс массива
            if (CreateIoCompletionPort((HANDLE) Clients[index].socket, ioPort, index, 0) == nullptr) {
                std::cout << "CreateIoCompletionPort error: " << GetLastError() << std::endl;
                return;
            }
            // Ожидание данных от сокета
            schedule_read(index);
            return;
        }
    }
    // Место не найдено => нет ресурсов для принятия соединения
    closesocket(acceptedSocket);
    acceptedSocket = 0;
}
// Функция стартует операцию приема соединения
void schedule_accept() {
    // Создание сокета для принятия подключения (AcceptEx не создает сокетов)
    acceptedSocket = WSASocket(AF_INET, SOCK_STREAM, 0, nullptr, 0, WSA_FLAG_OVERLAPPED);
    memset(&Clients[0].overlap_recv, 0, sizeof(OVERLAPPED));
    // Принятие подключения.
    // Как только операция будет завершена - порт завершения пришлет уведомление.
    // Размеры буферов должны быть на 16 байт больше размера адреса согласно документации разработчика ОС
    AcceptEx(
            Clients[0].socket,
            acceptedSocket,
            Clients[0].receivingBuffer,
            0,
            sizeof(sockaddr_in) + 16,
            sizeof(sockaddr_in) + 16,
            nullptr,
            &Clients[0].overlap_recv);
}
/* ------------------------------------------------------------------------------ */
void Error() {
    std::cerr << "Error: " << GetLastError() << std::endl;
}

void getAndSetSystem(char *buffer) {
    OSVERSIONINFOEX osVersion;
    ZeroMemory(&osVersion, sizeof(OSVERSIONINFOEX));

    osVersion.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
    GetVersionEx((LPOSVERSIONINFOA) &osVersion);

    switch(osVersion.dwMajorVersion) {
        case 4:
            switch(osVersion.dwMinorVersion) {
                case 0:
                    strcpy(buffer, "Windows 95\n\0");
                    break;
                case 10:
                    strcpy(buffer, "Windows 98\n\0");
                    break;
                case 90:
                    strcpy(buffer, "WindowsMe\n\0");
                    break;
                default:
                    strcpy(buffer, "Unknown OS\n\0");
                    break;
            }
            break;
        case 5:
            switch(osVersion.dwMinorVersion) {
                case 0:
                    strcpy(buffer, "Windows 2000\n\0");
                    break;
                case 1:
                    strcpy(buffer, "Windows XP\n\0");
                    break;
                case 2:
                    strcpy(buffer, "Windows 2003\n\0");
                    break;
                default:
                    strcpy(buffer, "Unknown OS\n\0");
                    break;
            }
            break;
        case 6:
            switch(osVersion.dwMinorVersion) {
                case 0:
                    strcpy(buffer, "Windows Vista\n\0");
                    break;
                case 1:
                    strcpy(buffer, "Windows 7\n\0");
                    break;
                case 2:
                    strcpy(buffer, "Windows 10\n\0");
                    break;
                case 3:
                    strcpy(buffer, "Unknown OS\n\0");
                    break;
            }
            break;
        default:
            strcpy(buffer, "Unknown OS\n\0");
            break;
    }
}
void getAndSetCurrentTime(char *buffer) {
    SYSTEMTIME sysTime;
    GetSystemTime(&sysTime);

    auto pos = 0;
    if (sysTime.wDay < 10) {
        buffer[pos++] = '0';
        buffer[pos++] = '0' + sysTime.wDay;
    } else {
        strncpy(buffer + pos, std::to_string(sysTime.wDay).c_str(), 2);
        pos += 2;
    }
    buffer[pos++] = '.';

    if (sysTime.wMonth < 10) {
        buffer[pos++] = '0';
        buffer[pos++] = '0' + sysTime.wMonth;
    } else {
        strncpy(buffer + pos, std::to_string(sysTime.wMonth).c_str(), 2);
        pos += 2;
    }
    buffer[pos++] = '.';

    strncpy(buffer + pos, std::to_string(sysTime.wYear).c_str(), 4);
    pos += 4;
    buffer[pos++] = ' ';

    if (sysTime.wHour < 10) {
        buffer[pos++] = '0';
        buffer[pos++] = '0' + sysTime.wHour;
    } else {
        strncpy(buffer + pos, std::to_string(sysTime.wHour).c_str(), 2);
        pos += 2;
    }
    buffer[pos++] = ':';

    if (sysTime.wMinute < 10) {
        buffer[pos++] = '0';
        buffer[pos++] = '0' + sysTime.wMinute;
    } else {
        strncpy(buffer + pos, std::to_string(sysTime.wMinute).c_str(), 2);
        pos += 2;
    }
    buffer[pos++] = ':';

    if (sysTime.wSecond < 10) {
        buffer[pos++] = '0';
        buffer[pos++] = '0' + sysTime.wSecond;
    } else {
        strncpy(buffer + pos, std::to_string(sysTime.wSecond).c_str(), 2);
        pos += 2;
    }
    buffer[pos++] = '\n';
    buffer[pos] = 0;
}
void getAndSetTimeSinceLaunch(char *buffer) {
    auto time = GetTickCount();
    auto hours = time / (1000 * 60 * 60);
    auto minutes = time / (1000 * 60) - hours * 60;
    auto seconds = time - hours * 24 * 60 - minutes * 60;

    auto pos = 0;
    if (hours < 10) {
        buffer[pos++] = '0';
        buffer[pos++] = '0' + hours;
    } else {
        strncpy(buffer + pos, std::to_string(hours).c_str(), 2);
        pos += 2;
    }
    buffer[pos++] = ':';
    if (minutes < 10) {
        buffer[pos++] = '0';
        buffer[pos++] = '0' + minutes;
    } else {
        strncpy(buffer + pos, std::to_string(minutes).c_str(), 2);
        pos += 2;
    }
    buffer[pos++] = ':';
    if (seconds < 10) {
        buffer[pos++] = '0';
        buffer[pos++] = '0' + seconds;
    } else {
        strncpy(buffer + pos, std::to_string(seconds).c_str(), 2);
        pos += 2;
    }
    buffer[pos++] = '\n';
    buffer[pos] = 0;
}
void getAndSetMemoryInfo(char *buffer) {
    MEMORYSTATUS status;
    GlobalMemoryStatus(&status);
    std::string text =
            std::to_string(status.dwTotalPhys) +
            " bytes in total, " +
            std::to_string(status.dwAvailPhys) +
            " bytes occupied. " +
            std::to_string(status.dwMemoryLoad) +
            "% load.\n" +
            "Maximum available for programs - " +
            std::to_string(status.dwTotalPageFile) +
            ". Not occupied - " +
            std::to_string(status.dwAvailPageFile) +
            ".\n" +
            "Maximum available virtual - " +
            std::to_string(status.dwTotalVirtual) +
            ". Not occupied - " +
            std::to_string(status.dwTotalVirtual) +
            ".";
    strcpy(buffer, text.c_str());
    buffer[text.size()] = '\n';
    buffer[text.size() + 1] = 0;
}
void getAndSetDisksInfo(char *buffer) {
    static const auto mostAvailableDisks = 26;
    char disks[mostAvailableDisks][3] = {0};
    DWORD drives = GetLogicalDrives();
    auto pos = 0;
    for (int i = 0, count = 0; i < 26; i++)
        if (((drives >> i) & 0x00000001) == 1) {
            disks[count][0] = static_cast<char>(static_cast<int>('A') + i);
            disks[count][1] = ':';
            std::string text = std::string(1, *disks[count]) + ": ";

            switch (GetDriveTypeA(disks[count])) {
                case 0:
                    text += std::string("Unknown.\n");
                    break;
                case 1:
                    text += std::string("Root path is invalid.\n");
                    break;
                case 2:
                    text += std::string("Removable.\n");
                    break;
                case 3:
                    text += std::string("Fixed.\n");
                    break;
                case 4:
                    text += std::string("Network.\n");
                    break;
                case 5:
                    text += std::string("CD-ROM.\n");
                    break;
                case 6:
                    text += std::string("RAM.\n");
                    break;
                default:
                    break;
            }
            strcpy(buffer + pos, text.c_str());
            pos += strlen(text.c_str());
            count++;
        }

}
void getAndSetAvailableDiskSpace(char *buffer) {
    static const auto mostAvailableDisks = 26;
    char disks[mostAvailableDisks][3] = {0};
    DWORD drives = GetLogicalDrives();
    auto pos = 0;
    for (auto i = 0, count = 0; i < 26; i++)
        if (((drives >> i) & 0x00000001) == 1) {
            disks[count][0] = static_cast<char>(static_cast<int>('A') + i);
            disks[count][1] = ':';
            if (GetDriveTypeA(disks[count]) == DRIVE_FIXED || GetDriveTypeA(disks[count]) == DRIVE_REMOVABLE) {
                __int64 lpFreeBytesAvailable, lpTotalNumberOfBytes, lpTotalNumberOfFreeBytes;
                GetDiskFreeSpaceEx(
                        disks[count],
                        (PULARGE_INTEGER) &lpFreeBytesAvailable,
                        (PULARGE_INTEGER) &lpTotalNumberOfBytes,
                        (PULARGE_INTEGER) &lpTotalNumberOfFreeBytes
                );
                strcpy(buffer + pos, "Disk ");
                pos += 5;
                buffer[pos++] = disks[count][0];
                buffer[pos++] = ':';
                buffer[pos++] = ' ';
                strcpy(buffer + pos, std::to_string(lpTotalNumberOfFreeBytes).c_str());
                pos += std::to_string(lpTotalNumberOfFreeBytes).size();
                buffer[pos++] = '\n';
            }
            count++;
        }
    buffer[pos] = 0;
}
enum objectType {
    File,
    Directory,
    RegisterKey
};
void getAndSetAccessRights(const std::string &filename, enum objectType type, char *buffer) {
    static const std::string pathError = "Error. Unable to find the file.";
    PACL dACL;
    ACL_SIZE_INFORMATION aclSize;
    PSECURITY_DESCRIPTOR pSD;
    ACCESS_ALLOWED_ACE *pACE;

    char objectType;
    if (type == RegisterKey) objectType = SE_REGISTRY_KEY;
    if (type == File) objectType = SE_FILE_OBJECT;
    if (type == Directory) objectType = SE_FILE_OBJECT;


    if (GetNamedSecurityInfoA(
            filename.c_str(),
            (SE_OBJECT_TYPE) objectType,
            DACL_SECURITY_INFORMATION,
            nullptr,
            nullptr,
            &dACL,
            nullptr,
            &pSD) != ERROR_SUCCESS) {
        strcpy(buffer, pathError.c_str());
        return;
    }

    GetAclInformation(dACL, &aclSize, sizeof(aclSize), AclSizeInformation);

    const auto size = 256;
    char user[size] = {0};
    char domain[size] = {0};

    std::string result;

    for (auto i = 0; i < aclSize.AceCount; ++i) {
        memset(user, 0, size);
        memset(domain, 0, size);

        GetAce(dACL, i, (PVOID *) &pACE);
        PSID pSID = (PSID) (&(pACE->SidStart));

        DWORD dUserSize = sizeof(user);
        DWORD dDomainSize = sizeof(domain);
        SID_NAME_USE sidName;
        LPSTR sSID = nullptr;

        if (LookupAccountSidA(
                nullptr,
                pSID,
                user,
                &dUserSize,
                domain,
                &dDomainSize,
                &sidName)) {

            ConvertSidToStringSidA(pSID, &sSID);
            result += std::string("# Account: ") + domain + " | " + user + ".\n" + "Sid: " + sSID + ".\n" + "Ace objectType: ";

            switch (pACE->Header.AceType) {
                case ACCESS_DENIED_ACE_TYPE:
                    result += "access denied.\n";
                    break;
                case ACCESS_ALLOWED_ACE_TYPE:
                    result += "access allowed.\n";
                    break;
                default:
                    result += "audit.\n";
            }

            std::string mask = "Access mask: ";
            for (auto j = 0; j < 32; ++j)
                mask += static_cast<char>('0' + pACE->Mask / (1 << (31 - j)) % 2);
            result += mask + ".\nGeneric rights:\n";

            if (((ACCESS_ALLOWED_ACE *) pACE)->Mask & 1) result += "\tGeneric read.\n";
            if (((ACCESS_ALLOWED_ACE *) pACE)->Mask & 2) result += "\tGeneric write.\n";
            if (((ACCESS_ALLOWED_ACE *) pACE)->Mask & 4) result += "\tGeneric execute.\n";
            if (((ACCESS_ALLOWED_ACE *) pACE)->Mask & GENERIC_ALL) result += "\tGeneric all.\n";

            result += "Standart rights:\n";

            if ((pACE->Mask & SYNCHRONIZE) == SYNCHRONIZE) result += "\tSynchronise.\n";
            if ((pACE->Mask & WRITE_OWNER) == WRITE_OWNER) result += "\tWrite owner.\n";
            if ((pACE->Mask & WRITE_DAC) == WRITE_DAC) result += "\tWrite DAC.\n";
        }

        if ((pACE->Mask & READ_CONTROL) == READ_CONTROL) result += "\tRead control.\n";
        if ((pACE->Mask & DELETE) == DELETE) result += "\tDelete.\n";

        if (type == Directory) {
            result += "Additional rights for directory:\n";
            if ((pACE->Mask & FILE_LIST_DIRECTORY) == FILE_LIST_DIRECTORY) result += "\tFILE_LIST_DIRECTORY\n";
            if ((pACE->Mask & FILE_ADD_FILE) == FILE_ADD_FILE) result += "\tFILE_ADD_FILE\n";
            if ((pACE->Mask & FILE_ADD_SUBDIRECTORY) == FILE_ADD_SUBDIRECTORY) result += "\tFILE_ADD_SUBDIRECTORY\n";
            if ((pACE->Mask & FILE_READ_EA) == FILE_READ_EA) result += "\tFILE_READ_EA\n";
            if ((pACE->Mask & FILE_WRITE_EA) == FILE_WRITE_EA) result += "\tFILE_WRITE_EA\n";
            if ((pACE->Mask & FILE_TRAVERSE) == FILE_TRAVERSE) result += "\tFILE_TRAVERSE\n";
            if ((pACE->Mask & FILE_DELETE_CHILD) == FILE_DELETE_CHILD) result += "\tFILE_DELETE_CHILD\n";
            if ((pACE->Mask & FILE_READ_ATTRIBUTES) == FILE_READ_ATTRIBUTES) result += "\tFILE_READ_ATTRIBUTES\n";
            if ((pACE->Mask & FILE_WRITE_ATTRIBUTES) == FILE_WRITE_ATTRIBUTES) result += "\tFILE_WRITE_ATTRIBUTES\n";
        }

        if (type == File) {
            result += "Additional rights for file:\n";
            if ((pACE->Mask & FILE_READ_DATA) == FILE_READ_DATA) result += "\tFILE_READ_DATA\n";
            if ((pACE->Mask & FILE_WRITE_DATA) == FILE_WRITE_DATA) result += "\tFILE_WRITE_DATA\n";
            if ((pACE->Mask & FILE_APPEND_DATA) == FILE_APPEND_DATA) result += "\tFILE_APPEND_DATA\n";
            if ((pACE->Mask & FILE_READ_EA) == FILE_READ_EA) result += "\tFILE_READ_EA\n";
            if ((pACE->Mask & FILE_WRITE_EA) == FILE_WRITE_EA) result += "\tFILE_WRITE_EA\n";
            if ((pACE->Mask & FILE_EXECUTE) == FILE_EXECUTE) result += "\tFILE_EXECUTE\n";
            if ((pACE->Mask & FILE_READ_ATTRIBUTES) == FILE_READ_ATTRIBUTES) result += "\tFILE_READ_ATTRIBUTES\n";
            if ((pACE->Mask & FILE_WRITE_ATTRIBUTES) == FILE_WRITE_ATTRIBUTES) result += "\tFILE_WRITE_ATTRIBUTES\n";
        }

        if (type == RegisterKey) {
            result += "Register key permissions:\n";
            if ((pACE->Mask & KEY_CREATE_SUB_KEY) == KEY_CREATE_SUB_KEY) result += "\tKEY_CREATE_SUB_KEY\n ";
            if ((pACE->Mask & KEY_ENUMERATE_SUB_KEYS) == KEY_ENUMERATE_SUB_KEYS)
                result += "\tKEY_ENUMERATE_SUB_KEYS\n ";
            if ((pACE->Mask & KEY_NOTIFY) == KEY_NOTIFY) result += "\tKEY_NOTIFY\n ";
            if ((pACE->Mask & KEY_QUERY_VALUE) == KEY_QUERY_VALUE) result += "\tKEY_QUERY_VALUE\n ";
            if ((pACE->Mask & KEY_SET_VALUE) == KEY_SET_VALUE) result += "\tKEY_SET_VALUE\n ";
        }
        result += '\n';
    }
    strcpy(buffer, result.c_str());
}
void getAndSetOwner(const std::string &filename, enum objectType type, char *buffer) {
    DWORD dwRes = 0;
    PSID ownerSID;
    PSECURITY_DESCRIPTOR pSD;

    if (type == File)
        dwRes = GetNamedSecurityInfoA(filename.c_str(), SE_FILE_OBJECT,
                                      OWNER_SECURITY_INFORMATION, &ownerSID, nullptr, nullptr, nullptr, &pSD);
    else
        dwRes = GetNamedSecurityInfoA(filename.c_str(), SE_REGISTRY_KEY,
                                      OWNER_SECURITY_INFORMATION, &ownerSID, nullptr, nullptr, nullptr, &pSD);

    if (dwRes != ERROR_SUCCESS) {
        std::cerr << "Error in receiving owner's information" << std::endl;
        LocalFree(pSD);
    }

    char szOwnerName[1024] = {0};
    char szDomainName[1024] = {0};
    DWORD dwUsetNameLength = sizeof(szOwnerName);
    DWORD dwDomainNameLength = sizeof(szDomainName);
    SID_NAME_USE sidUse;

    dwRes = LookupAccountSidA(nullptr, ownerSID, szOwnerName,
                              &dwUsetNameLength, szDomainName, &dwDomainNameLength, &sidUse);

    if (dwRes == 0)
        std::cerr << "Error in receiving owner's information" << std::endl;

    std::string result = "Owner: " + std::string(szOwnerName) + ". Domain: " + std::string(szDomainName) + ".\n";
    strcpy(buffer, result.c_str());
}
void exitClient(unsigned clientNumber) {
    descCSP = 0;
    descKey = 0;
    descKeyOpen = 0;
    memset(Clients[clientNumber].sendingBuffer, 0, sendingBufferSize);
    CancelIo((HANDLE) Clients[clientNumber].socket);
    PostQueuedCompletionStatus(ioPort, 0, clientNumber, &Clients[clientNumber].overlap_cancel);
}

void createCryptedConnection(int clientNumber){
    if (!CryptAcquireContext(&descCSP, nullptr, MS_ENHANCED_PROV, PROV_RSA_FULL, NULL)
        && !CryptAcquireContext(&descCSP, nullptr, MS_ENHANCED_PROV, PROV_RSA_FULL, CRYPT_NEWKEYSET))
        Error();

    /* Создаем сеансовый ключ. */
    if (CryptGenKey(descCSP, CALG_RC4, (CRYPT_EXPORTABLE | CRYPT_ENCRYPT | CRYPT_DECRYPT), &descKey) == 0)
        Error();

    /* Шифруем полученные от клиента данные. */
    auto tLen = 255;
    for (; tLen >= 0 && Clients[clientNumber].receivingBuffer[tLen] == 0; --tLen);
    unsigned int len = (unsigned char) Clients[clientNumber].receivingBuffer[tLen];
    Clients[clientNumber].receivingBuffer[tLen] = 0;

    if (!CryptImportKey(
            descCSP, (BYTE *) Clients[clientNumber].receivingBuffer,
            len, 0, 0, &descKeyOpen))
        Error();

    /* Помещаем шифрованное сообщение в буффер отправки. */
    DWORD lenExp = 256;
    if (!CryptExportKey(
            descKey, descKeyOpen, SIMPLEBLOB, NULL,
            (BYTE *) Clients[clientNumber].sendingBuffer, &lenExp))
        Error();

    Clients[clientNumber].sendingBuffer[lenExp] = lenExp;
    Clients[clientNumber].sendDataLength = lenExp + 1;
    std::cout << "Created encrypted connection for client " << clientNumber << "." << std::endl;
}

void Search(DWORD index) {
    char* rBuffer = Clients[index].receivingBuffer;
    char* sBuffer = Clients[index].sendingBuffer;
    if (descCSP != 0 && descKey != 0 && descKeyOpen != 0 &&
        !CryptDecrypt(
                descKey,
                NULL,
                true,
                NULL,
                (BYTE *) rBuffer,
                (DWORD *) &(Clients[index].receiveDataLength)))
        Error();


    const char firstSym = *rBuffer;
    std::string filename = (firstSym < '7') ? "" : std::string(rBuffer).substr(2);
    enum objectType type = (firstSym < '7') ? File : objectType((rBuffer[1] - '0') % 3);

    static const std::string indent = "   - ";
    switch (firstSym) {
        case '0':
            std::cout << indent << "Client " << index << " disconnected. " << std::endl;
            exitClient(index);
            return;
        case '1':
            std::cout << indent << "Client " << index << " requested information about the system." << std::endl;
            getAndSetSystem(sBuffer);
            break;
        case '2':
            std::cout << indent << "Client " << index << " requested current time. " << std::endl;
            getAndSetCurrentTime(sBuffer);
            break;
        case '3':
            std::cout << indent << "Client " << index << " requested time since launch. " << std::endl;
            getAndSetTimeSinceLaunch(sBuffer);
            break;
        case '4':
            std::cout << indent << "Client " << index << " requested info about the memory. " << std::endl;
            getAndSetMemoryInfo(sBuffer);
            break;
        case '5':
            std::cout << indent << "Client " << index << " requested info about the disks. " << std::endl;
            getAndSetDisksInfo(sBuffer);
            break;
        case '6':
            std::cout << indent << "Client " << index << " requested available space on the disks. " << std::endl;
            getAndSetAvailableDiskSpace(sBuffer);
            break;
        case '7':
            std::cout << indent << "Client " << index << " requested access rights. " << std::endl;
            getAndSetAccessRights(filename, type, sBuffer);
            break;
        case '8':
            std::cout << indent << "Client " << index << " requested information about owner. " << std::endl;
            getAndSetOwner(filename, type, sBuffer);
            break;
        default:
            createCryptedConnection(index);
            return;
    }

    DWORD count = strlen(sBuffer);
    if (!CryptEncrypt(
            descKey, NULL, true, NULL,
            (BYTE *) sBuffer, (DWORD *) &count, sendingBufferSize))
        Error();
    Clients[index].sendDataLength = count;
}

void Server() {
    WSADATA wasData;
    if (WSAStartup(MAKEWORD(2, 2), &wasData) == 0)
        std::cout << "WSAStartup - all right" << std::endl;
    else
        std::cout << "WSAStartup - error" << std::endl;

    struct sockaddr_in addr{};
    SOCKET s = WSASocket(AF_INET, SOCK_STREAM, 0, nullptr, 0, WSA_FLAG_OVERLAPPED);

    ioPort = CreateIoCompletionPort(INVALID_HANDLE_VALUE, nullptr, 0, 0);
    if (ioPort == nullptr)
        throw std::runtime_error("CreateIoCompletionPort error: " + std::to_string(GetLastError()));

    memset(Clients, 0, sizeof(Clients));
    memset(&addr, 0, sizeof(addr));

    addr.sin_family = AF_INET;
    addr.sin_port = htons(9000);

    if (bind(s, (struct sockaddr *) &addr, sizeof(addr)) < 0 || listen(s, 1) < 0)
        throw std::runtime_error("Binding or listening error");

    std::cout << "Listening: " << ntohs(addr.sin_port) << std::endl;

    // Присоединение существующего сокета s к порту io_port.
    // В качестве ключа для прослушивающего сокета используется 0
    if (nullptr == CreateIoCompletionPort((HANDLE) s, ioPort, 0, 0))
        throw std::runtime_error("CreateIoCompletionPort error: " + std::to_string(GetLastError()));

    Clients[0].socket = static_cast<int>(s);

    schedule_accept();

    while (true) {
        DWORD transferred;
        ULONG_PTR key;
        OVERLAPPED *lp_overlap;

        BOOL b = GetQueuedCompletionStatus(ioPort, &transferred, &key, &lp_overlap, 1000);
        if (b) {
            // Поступило уведомление о завершении операции
            if (key == 0) {// ключ 0 - для прослушивающего сокета
                Clients[0].receiveDataLength += transferred;
                // Принятие подключения и начало принятия следующего
                add_accepted_connection();
                schedule_accept();
            } else {
                // Иначе поступило событие по завершению операции от клиента.
                // Ключ key - индекс в массиве Clients
                if (&Clients[key].overlap_recv == lp_overlap) {
                    int len;
                    // Данные приняты:
                    if (transferred == 0) {
                        // Соединение разорвано
                        CancelIo((HANDLE) Clients[key].socket);
                        PostQueuedCompletionStatus(ioPort, 0, key,
                                                   &Clients[key].overlap_cancel);
                        continue;
                    }
                    Clients[key].receiveDataLength += transferred;
                    if (isStringReceived(key, &len)) {
                        // Если строка полностью пришла, то сформировать ответ и начать его отправлять

                        Search(key);

                        Clients[key].sz_send = 0;
                        memset(Clients[key].receivingBuffer, 0, receivingBufferSize);

                        schedule_write(key);
                    } else
                        schedule_read(key); // Иначе - ждем данные дальше

                } else if (&Clients[key].overlap_send == lp_overlap) {
                    // Данные отправлены
                    Clients[key].sz_send += transferred;
                    if (Clients[key].sz_send < Clients[key].sendDataLength && transferred > 0) {
                        // Если данные отправлены не полностью - продолжить отправлять
                        schedule_write(key);
                    } else {
                        // Данные отправлены полностью, прервать все коммуникации,
                        // добавить в порт событие на завершение работы

                        Clients[key].receiveDataLength = 0;
                        memset(Clients[key].sendingBuffer, 0, sendingBufferSize);
                        schedule_read(key);

                    }
                } else if (&Clients[key].overlap_cancel == lp_overlap) {
                    // Все коммуникации завершены, сокет может быть закрыт
                    closesocket(Clients[key].socket);
                    memset(&Clients[key], 0, sizeof(Clients[key]));
                    std::cout << "Connection " << key << " closed" << std::endl;
                }
            }
        } else {
            // Ни одной операции не было завершено в течение заданного времени, программа может
            // выполнить какие-либо другие действия
            // ...
        }
    }
}

int main() {
    Server();
    return 0;
}