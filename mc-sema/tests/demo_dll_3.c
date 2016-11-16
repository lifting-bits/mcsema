#undef UNICODE

#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdlib.h>
#include <stdio.h>

#pragma comment (lib, "Ws2_32.lib")

#define DEFAULT_BUFLEN 512
#define DEFAULT_PORT "1337"


BOOL APIENTRY _DllMainCRTStartup( HANDLE hModule, 
                       DWORD  ul_reason_for_call, 
                       LPVOID lpReserved
                     )
{
    return TRUE;
}

__declspec(dllexport) int WINAPI ServerThread(LPVOID *ptr) {
    SOCKET ListenSocket = INVALID_SOCKET;
    SOCKET ClientSocket = INVALID_SOCKET;

    struct addrinfo *result = NULL;
    struct addrinfo hints;

    int iSendResult;
    int iResult;
    char recvbuf[DEFAULT_BUFLEN];
    int recvbuflen = DEFAULT_BUFLEN;

    //ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_PASSIVE;

    printf("Listening on port: %s\n", DEFAULT_PORT);

    // Resolve the server address and port
    iResult = getaddrinfo(NULL, DEFAULT_PORT, &hints, &result);
    if ( iResult != 0 ) {
        WSACleanup();
        return 1;
    }

    // Create a SOCKET for connecting to server
    ListenSocket = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    if (ListenSocket == INVALID_SOCKET) {
        freeaddrinfo(result);
        WSACleanup();
        return 1;
    }

    // Setup the TCP listening socket
    iResult = bind( ListenSocket, result->ai_addr, (int)result->ai_addrlen);
    if (iResult == SOCKET_ERROR) {
        freeaddrinfo(result);
        closesocket(ListenSocket);
        WSACleanup();
        return 1;
    }

    freeaddrinfo(result);

    iResult = listen(ListenSocket, SOMAXCONN);
    if (iResult == SOCKET_ERROR) {
        closesocket(ListenSocket);
        WSACleanup();
        return 1;
    }

    // Accept a client socket
    ClientSocket = accept(ListenSocket, NULL, NULL);
    if (ClientSocket == INVALID_SOCKET) {
        closesocket(ListenSocket);
        WSACleanup();
        return 1;
    }

    // No longer need server socket
    closesocket(ListenSocket);

    // Receive until the peer shuts down the connection
    do {

        iResult = recv(ClientSocket, recvbuf, recvbuflen, 0);
        if (iResult > 0) {

            // Echo the buffer back to the sender
            iSendResult = send( ClientSocket, recvbuf, iResult, 0 );
            if (iSendResult == SOCKET_ERROR) {
                closesocket(ClientSocket);
                WSACleanup();
                return 1;
            }
        }
	else if(iResult == 0) {
	    break;
	}
        else  {
            closesocket(ClientSocket);
            WSACleanup();
            return 1;
        }

    } while (iResult > 0);

    // shutdown the connection since we're done
    iResult = shutdown(ClientSocket, SD_SEND);
    if (iResult == SOCKET_ERROR) {
        closesocket(ClientSocket);
        WSACleanup();
        return 1;
    }

    // cleanup
    closesocket(ClientSocket);
    WSACleanup();

    return 0;

}

extern int WINAPI printString(const char *s, int d0, const char *s2, int d1);
extern int WINAPI printInt(int i, const char *s0, int d0, const char *s1);

__declspec(dllexport) HANDLE StartServer()
{

    WSADATA wsd;
    int result;
    DWORD tid;
    HANDLE hThread;

    result = WSAStartup(MAKEWORD(2,2), &wsd);
    if(result != 0) {
        return NULL;
    }

    hThread = CreateThread(NULL,
                 0,
                 ServerThread,
                 NULL,
                 0,
                 &tid); 
    
    if(hThread != NULL) {
        return hThread;
    }

    //int data0;
    //char data1[4];
    //int data2;
    //char data3[4];
    //int data4;
    //char data5[4];
    //int data6;

    //
    //if(GetTickCount() > 0) {
    //    data0 = 0x11111111;
    //    data1[0] = 'a';
    //    data1[1] = 'a';
    //    data1[2] = 'a';
    //    data1[3] = '\0';
    //    data2 = 0x22222222;
    //    data3[0] = 'b';
    //    data3[1] = 'b';
    //    data3[2] = 'b';
    //    data3[3] = '\0';
    //    data4 = 0x33333333;
    //    data5[0] = 'c';
    //    data5[1] = 'c';
    //    data5[2] = 'c';
    //    data5[3] = '\0';
    //    data6 = 0x44444444;
    //    printInt(data0, data1, 0x0, data3);
    //    data1[0] = 'z';
    //    data1[1] = 'z';
    //    data1[2] = 'z';
    //    data1[3] = '\0';
    //    printString(data1, data2, data3, 0x0);
    //    data1[0] = 'q';
    //    data1[1] = 'q';
    //    data1[2] = 'q';
    //    data1[3] = '\0';
    //    data2 = 0xFFFFFFFF;
    //    printInt(data2, data3, data4, data5);
    //    data4 = 0xDDDDDDDD;
    //    printString(data3, 0x0, data5, data6);
    //    data1[0] = 'n';
    //    data1[1] = 'n';
    //    data1[2] = 'n';
    //    data1[3] = '\0';
    //    //printInt(data4);
    //    //printString(data5);
    //    //printInt(data6);

    //}

    return NULL;
}
