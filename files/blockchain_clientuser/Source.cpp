#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdlib.h>
#include <stdio.h>
#include <thread>
#include <iostream>
#include <string>
#include <map>
#include <vector>

#pragma comment (lib, "Ws2_32.lib")

#define DEFAULT_BUFLEN 512
#define DEFAULT_PORT "43012"

bool isServerOnline;

void HandleIncomingData(std::string data) {
	int pos = data.find(';');
	data = data.substr(0, pos);
	if (data == "Confirmed") {
		std::cout << "абырвалг";
	}
}

DWORD WINAPI SessionWithServer(LPVOID data) { 

	SOCKET ConnectSocket = (SOCKET)data;
	// Process the client.

	int iSendResult;
	int iResult;
	char recvbuf[DEFAULT_BUFLEN];
	int recvbuflen = DEFAULT_BUFLEN;
	std::string receivedData;

	std::string s = "User;";
	char const *sendbuf = s.c_str();

	std::cout << "Sending out data: " << sendbuf << std::endl;

	iSendResult = send(ConnectSocket, sendbuf, (int)strlen(sendbuf), 0);
	if (iSendResult == SOCKET_ERROR) {
		printf("send failed with error: %d\n", WSAGetLastError());
		closesocket(ConnectSocket);
	}

	// Receiving all kinds of data
	do {
		iResult = recv(ConnectSocket, recvbuf, recvbuflen, 0);
		if (iResult > 0) {
			printf("Bytes received: %d\n", iResult);
			std::cout << "Data received: " << recvbuf << std::endl;
			HandleIncomingData(std::string(recvbuf));
		}
		else if (iResult == 0)
			printf("Connection closing...\n");
		else {
			printf("recv failed with error: %d\n", WSAGetLastError());
			closesocket(ConnectSocket);
		}

	} while (iResult > 0);

	// shutdown the connection since we're done
	iResult = shutdown(ConnectSocket, SD_SEND);
	if (iResult == SOCKET_ERROR) {
		printf("shutdown failed with error: %d\n", WSAGetLastError());
		closesocket(ConnectSocket);
		//WSACleanup();
	}

	// cleanup
	closesocket(ConnectSocket);
	//WSACleanup();

	std::cout << "Server disconnected, shutting down\n";
	isServerOnline = false;
	return 0;

}

SOCKET ConnectToServer(char* address) {
	WSADATA wsaData;
	SOCKET ConnectSocket = INVALID_SOCKET;
	struct addrinfo *result = NULL,
		*ptr = NULL,
		hints;
	int iResult;

	// Initialize Winsock
	iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (iResult != 0) {
		printf("WSAStartup failed with error: %d\n", iResult);
		return INVALID_SOCKET;
	}

	ZeroMemory(&hints, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	// Resolve the server address and port
	iResult = getaddrinfo(address, DEFAULT_PORT, &hints, &result);
	if (iResult != 0) {
		printf("getaddrinfo failed with error: %d\n", iResult);
		WSACleanup();
		return INVALID_SOCKET;
	}

	// Attempt to connect to an address until one succeeds
	for (ptr = result; ptr != NULL; ptr = ptr->ai_next) {

		// Create a SOCKET for connecting to server
		ConnectSocket = socket(ptr->ai_family, ptr->ai_socktype,
			ptr->ai_protocol);
		if (ConnectSocket == INVALID_SOCKET) {
			printf("socket failed with error: %ld\n", WSAGetLastError());
			WSACleanup();
			return INVALID_SOCKET;
		}

		// Connect to server.
		iResult = connect(ConnectSocket, ptr->ai_addr, (int)ptr->ai_addrlen);
		if (iResult == SOCKET_ERROR) {
			closesocket(ConnectSocket);
			ConnectSocket = INVALID_SOCKET;
			continue;
		}
		break;
	}

	freeaddrinfo(result);

	if (ConnectSocket == INVALID_SOCKET) {
		printf("Unable to connect to server!\n");
		WSACleanup();
		return INVALID_SOCKET;
	}

	return ConnectSocket;

}

int main(int argc, char **argv) {

	// Validate the parameters
	if (argc != 2) {
		printf("usage: %s server-name\n", argv[0]);
		return 1;
	}

	std::cout << "Connecting to server..." << std::endl;

	SOCKET ConnectSocket = ConnectToServer(argv[1]);

	if (ConnectSocket == INVALID_SOCKET) {
		std::cout << "Connection failed, restart the program while making sure server is running\n";
		return 1;
	}

	isServerOnline = true;

	DWORD dwThreadId;

	CreateThread(NULL, 0, SessionWithServer, (LPVOID)ConnectSocket, 0, &dwThreadId);

	int iSendResult;

	while (isServerOnline) {
		std::string s;
		std::cin >> s;

		s = "Transactions:" + s + ";";
		char const *sendbuf = s.c_str();

		std::cout << "Sending out data: " << sendbuf << std::endl;

		iSendResult = send(ConnectSocket, sendbuf, (int)strlen(sendbuf), 0);
		if (iSendResult == SOCKET_ERROR) {
			printf("send failed with error: %d\n", WSAGetLastError());
			closesocket(ConnectSocket);
		}

	}

	// Here goes mining and other stuff


}