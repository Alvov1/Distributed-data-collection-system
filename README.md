# Distributed-data-collection-system-
A distributed system for collecting information about a computer, consisting of a server and a client, interacting via sockets.

The servers are running continuously and are constantly waiting for incoming connections. Clients are launched only when some information is required from the servers. The following parameters can be requested from the server:

- Server operation type (Windows family);
- Current time in OS;
- Time since OS startup;
- Information about the used memory;
- Information about local drives;
- Free space on local drives;
- Access rights to file / directory / registry key;
- The owner of the file / directory / registry key;

All information transmitted between client and server is encrypted using Windows CryptoAPI. Asynchronous RSA1 is used for key exchange, and synchronous RC4 is used afterwards for data transmission. 

Serving clients on the server is implemented using Windows I/O completion ports.

Windows MSVC compiler only.  
