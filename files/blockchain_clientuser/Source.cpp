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
#include "dsa.h"
#include "osrng.h"
#include "sha.h"
#include "hex.h"

#pragma comment (lib, "Ws2_32.lib")

#define DEFAULT_BUFLEN 1024
#define DEFAULT_PORT "43012"
using namespace CryptoPP;
AutoSeededRandomPool rng;
bool isServerOnline = true;
std::map<std::string, std::string> UserToPassword;
std::map<std::string, DSA::PrivateKey> UserToPrivateKey;
// обработка идущих данных
void HandleIncomingData(std::string data) {
	int pos = data.find(';');
	if (pos < 0) {
		printf("Received data in wrong format");
		return;
	}
	size_t start = data.find(':');
	if (start < 0) {
		printf("Received data in wrong format");
		return;
	}
	std::string type = data.substr(0, start);
	data = data.substr(start + 1, pos - start - 1);
	if (type == "RegisterConfirmation") {
		if (data.substr(0, 4) == "True") {
			data = data.substr(5);
			start = data.find("|");
			std::string username = data.substr(0, start);
			std::string publicKey = data.substr(start + 1);
			std::cout << "User: " + username + " was successfully registered!\nHis public key is:\n" + publicKey + "\n";
		}
		else {
			printf("User registration rejected: username already used\n");
		}
		return;
	}
	else if (type == "Confirmation") {
		if (data=="True") {
			printf("Received confirmation for transaction used;\n");
		}
		else {
			printf("Sent transaction was rejected;\n");
		}
		return;
	}
	else {
		printf("Received data in wrong format");
		return;
	}
}
// класс для транзакций
class Transaction {
public:
	int number;
	std::string data;
};
// еще одна штука для связи
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

SOCKET ConnectSocket;
// подключение к серверу
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
// шифрующая функция
std::string SHA256Hash(std::string input) {
	CryptoPP::byte digest[CryptoPP::SHA256::DIGESTSIZE];
	CryptoPP::SHA256 hash;
	hash.CalculateDigest(digest, (const CryptoPP::byte*)input.c_str(), input.length());
	CryptoPP::HexEncoder encoder;
	std::string output;
	encoder.Attach(new CryptoPP::StringSink(output));
	encoder.Put(digest, sizeof(digest));
	encoder.MessageEnd();
	return output;
}
// перевод строки в шестнадцатиричное число-строку
std::string string_to_hex(const std::string& input)
{
	static const char* const lut = "0123456789ABCDEF";
	size_t len = input.length();

	std::string output;
	output.reserve(2 * len);
	for (size_t i = 0; i < len; ++i)
	{
		const unsigned char c = input[i];
		output.push_back(lut[c >> 4]);
		output.push_back(lut[c & 15]);
	}
	return output;
}
// здесь вводятся данные для регистрации юзера
void SendRegistrationData(std::string username, std::string password){
	std::string s = "Register:" + username + '|' + password + ';';
	int iSendResult;
	char const *sendbuf = s.c_str();
	std::cout << "Sending out data: " << sendbuf << std::endl;
	iSendResult = send(ConnectSocket, sendbuf, (int)strlen(sendbuf), 0);

	if (iSendResult == SOCKET_ERROR) {
		printf("send failed with error: %d\n", WSAGetLastError());
		closesocket(ConnectSocket);
	}
}
// это функция для регистрации юзера
void HandleUserRegister() {
	std::string username, password;
	std::cout << "Enter a username:\n";
	std::cin >> username;
	std::cout << "Enter a password:\n";
	std::cin >> password;
	password = SHA256Hash(password);
	SendRegistrationData(username, password);	
}
// это функция для отправки транзакции
void HandleTransactionSend() {
	int iSendResult;
	std::string s, username, password, signature;
	username = "";
	int numberOfSignatures;
	std::cout << "Enter a transaction to send:\n";
	std::cin >> s;
	std::cout << "Enter number of signatures to attach:\n";
	std::cin >> numberOfSignatures;
	std::string userdata = "";
	for (int i = 0; i < max(numberOfSignatures, 0); ++i) {
		std::cout << "Enter username of the " << (i + 1) << "signature:\n";
		std::cin >> username;
		std::cout << "Enter password of the user" << username << " :\n";
		std::cin >> password;
		userdata += username + '!' + SHA256Hash(password) + '!';
	}
	s = "Transactions:" + s +"!"+ userdata+ ";";
	char const *sendbuf = s.c_str();
	std::cout << "Sending out data: " << sendbuf << std::endl;
	iSendResult = send(ConnectSocket, sendbuf, (int)strlen(sendbuf), 0);
	if (iSendResult == SOCKET_ERROR) {
		printf("send failed with error: %d\n", WSAGetLastError());
		closesocket(ConnectSocket);
	}
}

int main(int argc, char **argv) {
	// Validate the parameters
	if (argc != 2) {
		printf("usage: %s server-name\n", argv[0]);
		return 1;
	}
	std::cout << "Connecting to server..." << std::endl;
	ConnectSocket = ConnectToServer(argv[1]);
	if (ConnectSocket == INVALID_SOCKET) {
		std::cout << "Connection failed, restart the program while making sure server is running\n";
		return 1;
	}
	isServerOnline = true;
	DWORD dwThreadId;
	CreateThread(NULL, 0, SessionWithServer, (LPVOID)ConnectSocket, 0, &dwThreadId);
	while (isServerOnline) {
		std::string input;
		std::cout << "Choose an action (1 - send transaction, 2 - register user):\n";
		std::cin >> input;
		if (input == "1") {
			HandleTransactionSend();
		}
		else if (input == "2") {
			HandleUserRegister();
		}
		else {
			std::cout << "Wrong option!\n";
		}

	}
	// Here goes mining and other stuff
}