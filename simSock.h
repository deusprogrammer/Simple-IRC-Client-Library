#include <winsock2.h>
#include <ws2tcpip.h>
#include <sys/types.h>
#include <sys/stat.h>

#pragma comment(lib, "Ws2_32.lib")
//#pragma comment(lib, "libeay32.lib")

#define DEFAULT_HOST	"127.0.0.1"
#define DEFAULT_PORT	"1234"
#define DEFAULT_BUFLEN	512
#define PACKET_SIZE		1024

#define SUCCESS					0
#define CREATE_FILE_FAILED		1
#define AUTHENTICATION_FAILED	2
#define OPEN_FILE_FAILED		3
#define INVALID_FILE_HEADER		4

#define UDP 0
#define TCP 1

struct FileHeader {
	int sizeInBytes;
	char fileName[1024];
};

struct AuthenticatedFileHeader {
	unsigned char mac[20];
	int sizeInBytes;
	char fileName[1024];
};

struct AuthenticatedPacket {
	unsigned char mac[20];
	char data[PACKET_SIZE];
};

int InitializeWS();
int CleanupWS();

int OpenClientSocket(OUT SOCKET *pSock, IN char *hostname, IN char *port, IN DWORD type);
int OpenServerSocket(OUT SOCKET *pSock, IN char *port, IN DWORD type);
void CloseSocket(SOCKET sock);

SOCKET AcceptConnection(IN SOCKET sock);

bool CreateAuthenticatedFileHeader(IN CHAR* key, IN CHAR* filePath, IN CHAR* fileName, OUT AuthenticatedFileHeader* hmach);
bool CreateAuthenticatedPacket(IN CHAR* data, OUT AuthenticatedPacket* packet, IN CHAR* key);

int RecvFromSocket(IN SOCKET sock, OUT LPVOID data, IN int len, OUT sockaddr* out);
int RecvFromSocket(IN SOCKET sock, OUT LPVOID data, OUT sockaddr* out);
int SendToSocket(IN SOCKET sock, IN LPVOID data, IN int len, IN sockaddr* in);
int SendToSocket(IN SOCKET sock, IN LPVOID data, IN sockaddr* in);
int WriteSocket(IN SOCKET sock, IN LPVOID data, IN int buf_sz);
int WriteSocket(IN SOCKET sock, IN LPVOID data);
int ReadSocket(IN SOCKET sock, OUT LPVOID data, IN int buf_sz);
int ReadLineSocket(IN SOCKET sock, OUT LPVOID data, IN int buf_sz);
int WriteAuthenticatedSocket(IN SOCKET sock, IN LPVOID data, IN int buf_sz, IN CHAR* key);
int ReadAuthenticatedSocket(IN SOCKET sock, OUT LPVOID data, IN int buf_sz, IN CHAR* key);

bool WriteFileToSocket(IN SOCKET sock, IN CHAR* filePath, IN CHAR* fileName);
bool ReadFileFromSocket(IN SOCKET sock, IN CHAR* filePath, OUT CHAR* fileName);
//int WriteAuthenticatedFileToSocket(IN SOCKET sock, IN CHAR* filePath, IN CHAR* fileName, IN CHAR* key);
//int ReadAuthenticatedFileFromSocket(IN SOCKET sock, IN CHAR *filePath, IN CHAR* key);

int InitializeWS() {
	WSAData wsaData;

	int iResult;

	// Initialize Winsock
	iResult = WSAStartup(MAKEWORD(2,2), &wsaData);
	if (iResult != 0) {
		printf("WSAStartup failed: %d\n", iResult);
		return -1;
	}

	return 0;
}

int CleanupWS() {
	WSACleanup();

	return 0;
}

int OpenClientSocket(OUT SOCKET *pSock, IN char *hostname, IN char *port, IN DWORD type) {
	struct addrinfo *result = NULL,
                *ptr = NULL,
                hints;

	int iResult;

	ZeroMemory( &hints, sizeof(hints) );
	hints.ai_family = AF_UNSPEC;
	if(type==TCP) {
		hints.ai_socktype = SOCK_STREAM;
		hints.ai_protocol = IPPROTO_TCP;
	}
	else if(type==UDP) {
		hints.ai_socktype = SOCK_DGRAM;
		hints.ai_protocol = IPPROTO_UDP;
	}

	// Resolve the server address and port
	iResult = getaddrinfo(hostname, port, &hints, &result);
	if (iResult != 0) {
		printf("Unable to resolve host: %s (%d)\n", hostname, WSAGetLastError());
	    //WSACleanup();
		return -1;
	}

	*pSock = INVALID_SOCKET;

	// Attempt to connect to the first address returned by
	// the call to getaddrinfo
	ptr=result;

	// Create a SOCKET for connecting to server
	*pSock = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);

	if (*pSock == INVALID_SOCKET) {
		printf("Error creating socket: %ld\n", WSAGetLastError());
		freeaddrinfo(result);
		//WSACleanup();
		return -1;
	}

	// Connect to server.
	iResult = connect(*pSock, ptr->ai_addr, (int)ptr->ai_addrlen);
	if (iResult == SOCKET_ERROR) {
		closesocket(*pSock);
		*pSock = INVALID_SOCKET;
	}

	freeaddrinfo(result);

	if (*pSock == INVALID_SOCKET) {
		printf("Unable to connect to server: (%d)!\n", WSAGetLastError());
		//WSACleanup();
		return -1;
	}

	return 0;
}

int OpenServerSocket(OUT SOCKET *pSock, IN char *port, IN DWORD type) {
	int iResult;

	struct addrinfo *result = NULL, *ptr = NULL, hints;

	ZeroMemory(&hints, sizeof (hints));
	hints.ai_family = AF_INET;
	hints.ai_flags = AI_PASSIVE;

	if(type==TCP) {
		hints.ai_socktype = SOCK_STREAM;
		hints.ai_protocol = IPPROTO_TCP;
	}
	else if(type==UDP) {
		hints.ai_socktype = SOCK_DGRAM;
		hints.ai_protocol = IPPROTO_UDP;
	}

	// Resolve the local address and port to be used by the server
	iResult = getaddrinfo(NULL, port, &hints, &result);
	if (iResult != 0) {
		printf("getaddrinfo failed: %d\n", iResult);
		//WSACleanup();
		return -1;
	}

	*pSock = INVALID_SOCKET;

	// Create a SOCKET for the server to listen for client connections
	*pSock = socket(result->ai_family, result->ai_socktype, result->ai_protocol);

	if (*pSock == INVALID_SOCKET) {
		printf("Error at socket(): %ld\n", WSAGetLastError());
		freeaddrinfo(result);
		//WSACleanup();
		return -1;
	}

	// Setup the TCP listening socket
	iResult = bind(*pSock, result->ai_addr, (int)result->ai_addrlen);
	if (iResult == SOCKET_ERROR) {
		printf("bind failed: %d\n", WSAGetLastError());
		freeaddrinfo(result);
		closesocket(*pSock);
		//WSACleanup();
		return -1;
	}

	freeaddrinfo(result);

	if(type!=UDP){
		if (listen(*pSock, SOMAXCONN ) == SOCKET_ERROR ) {
			printf( "Listen failed with error: %ld\n", WSAGetLastError() );
			closesocket(*pSock);
			//WSACleanup();
			return -1;
		}
	}

	return 0;
}

void CloseSocket(SOCKET sock) {
	closesocket(sock);
}

SOCKET AcceptConnection(IN SOCKET sock) {
	SOCKET ClientSocket = INVALID_SOCKET;

	// Accept a client socket
	ClientSocket = accept(sock, NULL, NULL);
	if (ClientSocket == INVALID_SOCKET) {
		printf("accept failed: %d\n", WSAGetLastError());
		closesocket(sock);
		//WSACleanup();
		return -1;
	}

	return ClientSocket;
}

int SendToSocket(IN SOCKET sock, IN LPVOID data, IN int len, IN sockaddr* to) {
	return sendto(sock, (char*)data, len, 0, to, sizeof(sockaddr));
}

int SendToSocket(IN SOCKET sock, IN LPVOID data, IN sockaddr* to) {
	int len = strlen((char*)data);
	return sendto(sock, (char*)data, len, 0, to, sizeof(sockaddr));
}

int RecvFromSocket(IN SOCKET sock, OUT LPVOID data, IN int len, OUT sockaddr* from) {
	int client_length = (int)sizeof(struct sockaddr_in);
	return recvfrom(sock, (char*)data, len, 0, from, &client_length);
}

int RecvFromSocket(IN SOCKET sock, OUT LPVOID data, OUT sockaddr* from) {
	int client_length = (int)sizeof(struct sockaddr_in);
	int len = strlen((char*)data);
	return recvfrom(sock, (char*)data, len, 0, from, &client_length);
}

int WriteSocket(IN SOCKET sock, IN LPVOID data, IN int buf_sz) {
	return send(sock, (char*)data, buf_sz, 0);
}

int WriteSocket(IN SOCKET sock, IN LPVOID data) {
	return send(sock, (char*)data, strlen((char*)data)+1, 0);
}

int ReadSocket(IN SOCKET sock, OUT LPVOID data, IN int buf_sz) {
	return recv(sock, (char*)data, buf_sz, 0);
}

int ReadLineSocket(IN SOCKET sock, OUT LPVOID data, IN int buf_sz) {
	int i = 0;
	int result;
	char c[1];

	do{
		result = recv(sock, c, 1, 0);
		*(((char*)data) + i) = c[0];
		i++;
	}while(c[0]!='\n' && i<buf_sz && result>0);

	if(!result>0)
		return -1;
	else
		return i;
}

/*int WriteAuthenticatedSocket(IN SOCKET sock, IN LPVOID data, IN CHAR* key) {
	AuthenticatedPacket pack;
	CreateAuthenticatedPacket((char*)data, &pack, key);
	return send(sock, (char*)&pack, sizeof(AuthenticatedPacket), 0);
}

int ReadAuthenticatedSocket(IN SOCKET sock, OUT LPVOID data, IN CHAR* key) {
	AuthenticatedPacket pack;
	int bytesRecv;
	unsigned int macLen;
	unsigned char mac[20];

	bytesRecv = recv(sock, (char*)&pack, sizeof(AuthenticatedPacket), 0);

	HMAC(EVP_sha1(), key, 64, (const unsigned char*)pack.data, PACKET_SIZE, mac, &macLen);

	for(int i=0; i<macLen; i++) {
		if(mac[i]!=pack.mac[i])
			return -1;
	}

	memcpy(data, pack.data, PACKET_SIZE);

	return bytesRecv;
}
*/

bool WriteFileToSocket(IN SOCKET sock, IN CHAR* filePath, IN CHAR* fileName) {
	CHAR buffer[1024];
	CHAR fullPath[2048];
	FileHeader fh;
	struct stat filestatus;
	
	sprintf(fullPath, "%s%s", filePath, fileName);

	FILE *fp = fopen(fullPath, "rb");
		
	if(fp==NULL) {
		fh.sizeInBytes = -1;
		WriteSocket(sock, &fh, sizeof(FileHeader));
		printf("File not found:\n\t%s\n", fullPath);
		return false;
	}

	strncpy(fh.fileName, fileName, 1024);

	stat(fullPath, &filestatus );
	fh.sizeInBytes = filestatus.st_size;
	
	printf("Reading %d bytes from %s...\n", fh.sizeInBytes, fullPath);

	WriteSocket(sock, &fh, sizeof(FileHeader));
	ReadSocket(sock, buffer, 1024);
	//puts("Writing file header!");

	while(fread(buffer, 1, 1024, fp)!=0) {
		WriteSocket(sock, buffer, 1024);
		ReadSocket(sock, buffer, 1024);
	}

	//puts("Copying file...");
	
	fclose(fp);

	return true;
}

bool ReadFileFromSocket(IN SOCKET sock, IN CHAR* filePath, OUT CHAR* fileName) {
	CHAR buffer[1024];
	FILE *fp;
	CHAR fullPath[2048];
	FileHeader fh;
	int bytesRecv = 0;
	
	ReadSocket(sock, &fh, sizeof(FileHeader));
	WriteSocket(sock, "/ack", 1024);

	if(fh.sizeInBytes==-1) {
		printf("Received error code from socket\n");
		return false;
	}

	if(fileName!=NULL)
		strcpy(fileName, fh.fileName);

	sprintf(fullPath, "%s%s", filePath, fh.fileName);

	printf("Writing %d bytes to %s...\n", fh.sizeInBytes, fullPath);

	fp = fopen(fullPath, "wb");

	if(fp==NULL) {
		printf("Failed to create file!\n");
		return false;
	}

	while(bytesRecv<fh.sizeInBytes) {
		bytesRecv += ReadSocket(sock, buffer, 1024);
		fwrite(buffer, 1, 1024, fp);
		WriteSocket(sock, "\ack", 1024);
	}

	printf("Successfully wrote file!\n");
		
	fclose(fp);

	return true;
}

/*
bool CreateAuthenticatedPacket(IN CHAR* data, OUT AuthenticatedPacket* packet, IN CHAR* key) {
	unsigned int macLen;
	memcpy(packet->data, data, PACKET_SIZE);

	HMAC(EVP_sha1(), key, 64, (const unsigned char*)data, PACKET_SIZE, packet->mac, &macLen);

	printf("MAC Len:\t%d\nMAC:\t\t", macLen);

	for(int i=0; i<macLen; i++)
		printf("%x", packet->mac[i]);

	printf("\n\n");

	return true;
}

bool CreateAuthenticatedFileHeader(IN CHAR* key, IN CHAR* filePath, IN CHAR* fileName, OUT AuthenticatedFileHeader* hmach) {
	struct stat file;
	char *buffer;
	char fullPath[2048];
	size_t macLen = 20;

	sprintf(fullPath, "%s%s", filePath, fileName);

	if(stat(fullPath, &file)==-1) {
		hmach->sizeInBytes = -1;
		return false;
	}

	strncpy(hmach->fileName, fileName, 1024);

	hmach->sizeInBytes = file.st_size;

	buffer = new char[hmach->sizeInBytes*2];

	FILE *fp = fopen(fullPath, "rb");

	fread(buffer, 1, hmach->sizeInBytes, fp);

	HMAC(EVP_sha1(), key, 64, (const unsigned char*)buffer, hmach->sizeInBytes, hmach->mac, &macLen);

	fclose(fp);

	printf("Filename:\t%s\nSize:\t\t%d bytes\nHMAC:\t\t", hmach->fileName, hmach->sizeInBytes);

	for(int i=0; i<20; i++)
		printf("%x", hmach->mac[i]);

	printf("\n\n");

	return true;
}

int WriteAuthenticatedFileToSocket(IN SOCKET sock, IN CHAR* filePath, IN CHAR* fileName, IN CHAR* key) {
	CHAR buffer[1024];
	CHAR fullPath[2048];
	AuthenticatedFileHeader fh;
	struct stat filestatus;

	if(!CreateAuthenticatedFileHeader(key, filePath, fileName, &fh)) {
		printf("Invalid file name\n!");
		WriteSocket(sock, &fh, sizeof(AuthenticatedFileHeader));
	}
	
	sprintf(fullPath, "%s%s", filePath, fileName);

	FILE *fp = fopen(fullPath, "rb");
		
	if(fp==NULL)
		return OPEN_FILE_FAILED;
	
	printf("Reading %d bytes from %s...\n", fh.sizeInBytes, fullPath);

	WriteSocket(sock, &fh, sizeof(AuthenticatedFileHeader));
	ReadSocket(sock, buffer, 1024);

	while(fread(buffer, 1, 1024, fp)!=0) {
		WriteSocket(sock, buffer, 1024);
		ReadSocket(sock, buffer, 1024);
	}
	
	fclose(fp);

	return SUCCESS;
}

int ReadAuthenticatedFileFromSocket(IN SOCKET sock, IN CHAR *filePath, IN CHAR* key) {
	CHAR* buffer;
	CHAR* p;
	FILE* fp;
	CHAR fullPath[2048];
	AuthenticatedFileHeader fh;
	int bytesRecv = 0;
	int result = 0;

	unsigned char mac[20];
	unsigned int macLen = 20;
	
	ReadSocket(sock, &fh, sizeof(AuthenticatedFileHeader));

	printf("File Size: %d\nFile Name: %s\n", fh.sizeInBytes, fh.fileName);

	if(fh.sizeInBytes == -1) {
		printf("Invalid file header!\n");
		return INVALID_FILE_HEADER;
	}
	
	WriteSocket(sock, "/ack", 1024);

	sprintf(fullPath, "%s%s", filePath, fh.fileName);

	printf("Writing %d bytes to %s...\n", fh.sizeInBytes, fullPath);

	buffer = new char[fh.sizeInBytes*2];

	p = buffer;
	
	while(bytesRecv<fh.sizeInBytes) {
		int result = ReadSocket(sock, p, 1024);

		if(result==-1) {
			printf("ERROR: %d\n", WSAGetLastError());
			break;
		}

		bytesRecv += result;
		p = buffer + bytesRecv;
		WriteSocket(sock, "\ack", 1024);
	}

	HMAC(EVP_sha1(), key, 64, (const unsigned char*)buffer, fh.sizeInBytes, mac, &macLen);

	printf("HMAC: ");

	for(int i=0; i<20; i++) {
		printf("%x", mac[i]);
	}

	printf("\n");

	printf("HMAC: ");

	for(int i=0; i<20; i++) {
		printf("%x", fh.mac[i]);
	}

	printf("\n");

	for(int i=0; i<20; i++) {
		if(mac[i] != fh.mac[i]) {
			printf("Authentication failed!\n\n");
			return AUTHENTICATION_FAILED;
		}
	}

	printf("Authentication successful!\n\n");

	fp = fopen(fullPath, "wb");

	if(fp==NULL) {
		printf("Failed to create file!\n");
		return CREATE_FILE_FAILED;
	}

	fwrite(buffer, 1, fh.sizeInBytes, fp);

	printf("Successfully wrote file!\n");
		
	fclose(fp);

	return SUCCESS;
}
*/