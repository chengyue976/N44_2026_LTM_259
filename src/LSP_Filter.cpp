#include <ws2spi.h>
#include <winsock2.h>
#include <windows.h>
#include "PacketHeaders.h"

#pragma comment(lib, "ws2_32.lib")

WSPPROC_TABLE          g_NextProcTable;
WSPUPCALLTABLE         g_UpCallTable;
HMODULE                g_hNextProviderDll = NULL;
HANDLE                 g_hMapFile         = NULL;
const SharedBlacklist* g_pSharedBlacklist = nullptr;

// Ánh xạ vùng nhớ chia sẻ một lần duy nhất khi DLL được nạp vào tiến trình
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hinstDLL);
        g_hMapFile = OpenFileMappingW(FILE_MAP_READ, FALSE, SHARED_MEM_NAME);
        if (g_hMapFile) {
            g_pSharedBlacklist = reinterpret_cast<const SharedBlacklist*>(
                MapViewOfFile(g_hMapFile, FILE_MAP_READ, 0, 0, sizeof(SharedBlacklist))
            );
        }
    }
    else if (fdwReason == DLL_PROCESS_DETACH) {
        if (g_pSharedBlacklist) UnmapViewOfFile(g_pSharedBlacklist);
        if (g_hMapFile) CloseHandle(g_hMapFile);
        if (g_hNextProviderDll) FreeLibrary(g_hNextProviderDll);
    }
    return TRUE;
}

// Kiểm tra IP có nằm trong Blacklist hay không (O(1) memory read, không syscall)
bool IsIpBlacklisted(uint32_t ipAddr) {
    if (!g_pSharedBlacklist) {
        // Thử mở lại nếu IDS_Monitor.exe được khởi động sau ứng dụng
        HANDLE hMap = OpenFileMappingW(FILE_MAP_READ, FALSE, SHARED_MEM_NAME);
        if (!hMap) return false;
        g_hMapFile = hMap;
        g_pSharedBlacklist = reinterpret_cast<const SharedBlacklist*>(
            MapViewOfFile(g_hMapFile, FILE_MAP_READ, 0, 0, sizeof(SharedBlacklist))
        );
        if (!g_pSharedBlacklist) return false;
    }

    LONG count = g_pSharedBlacklist->count;
    if (count > MAX_BLACKLIST_IPS) count = MAX_BLACKLIST_IPS;

    for (LONG i = 0; i < count; ++i) {
        if (g_pSharedBlacklist->ips[i] == ipAddr) {
            return true;
        }
    }
    return false;
}

// Hook 1: Từ chối chấp nhận kết nối TCP từ IP nằm trong danh sách đen
SOCKET WSPAPI Hook_WSPAccept(
    SOCKET s,
    struct sockaddr* addr,
    LPINT addrlen,
    LPCONDITIONPROC lpfnCondition,
    DWORD_PTR dwCallbackData,
    LPINT lpErrno)
{
    SOCKET clientSock = g_NextProcTable.lpWSPAccept(
        s, addr, addrlen, lpfnCondition, dwCallbackData, lpErrno
    );

    if (clientSock != INVALID_SOCKET && addr != nullptr && addr->sa_family == AF_INET) {
        const sockaddr_in* addrIn = reinterpret_cast<const sockaddr_in*>(addr);
        if (IsIpBlacklisted(addrIn->sin_addr.s_addr)) {
            INT closeErr = 0;
            g_NextProcTable.lpWSPCloseSocket(clientSock, &closeErr);
            *lpErrno = WSAECONNREFUSED;
            return INVALID_SOCKET;
        }
    }
    return clientSock;
}

// Hook 2: Chặn gói tin UDP / Datagram đến từ IP độc hại tại tầng SPI
int WSPAPI Hook_WSPRecvFrom(
    SOCKET s,
    LPWSABUF lpBuffers,
    DWORD dwBufferCount,
    LPDWORD lpNumberOfBytesRecvd,
    LPDWORD lpFlags,
    struct sockaddr* lpFrom,
    LPINT lpFromlen,
    LPWSAOVERLAPPED lpOverlapped,
    LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine,
    LPWSATHREADID lpThreadId,
    LPINT lpErrno)
{
    int ret = g_NextProcTable.lpWSPRecvFrom(
        s, lpBuffers, dwBufferCount, lpNumberOfBytesRecvd, lpFlags,
        lpFrom, lpFromlen, lpOverlapped, lpCompletionRoutine, lpThreadId, lpErrno
    );

    if (ret == 0 && lpFrom != nullptr && lpFrom->sa_family == AF_INET) {
        const sockaddr_in* addrIn = reinterpret_cast<const sockaddr_in*>(lpFrom);
        if (IsIpBlacklisted(addrIn->sin_addr.s_addr)) {
            if (lpNumberOfBytesRecvd) *lpNumberOfBytesRecvd = 0;
            *lpErrno = WSAECONNREFUSED;
            return SOCKET_ERROR;
        }
    }
    return ret;
}

// Điểm vào bắt buộc của mọi Winsock 2 Layered Service Provider
int WSPAPI WSPStartup(
    WORD wVersionRequested,
    LPWSPDATA lpWSPData,
    LPWSAPROTOCOL_INFOW lpProtocolInfo,
    WSPUPCALLTABLE UpcallTable,
    LPWSPPROC_TABLE lpProcTable)
{
    if (lpProtocolInfo->ProtocolChain.ChainLen <= 1) {
        return WSAEPROVIDERFAILEDINIT;
    }

    g_UpCallTable = UpcallTable;

    // Tìm nhà cung cấp dịch vụ kế tiếp trong chuỗi giao thức (Protocol Chain)
    DWORD nextCatalogId = lpProtocolInfo->ProtocolChain.ChainEntries[1];
    DWORD bufLen = 0;
    INT err = 0;
    WSCEnumProtocols(NULL, NULL, &bufLen, &err);

    LPWSAPROTOCOL_INFOW pProtoList = reinterpret_cast<LPWSAPROTOCOL_INFOW>(HeapAlloc(GetProcessHeap(), 0, bufLen));
    if (!pProtoList) return WSAENOBUFS;

    int numProtos = WSCEnumProtocols(NULL, pProtoList, &bufLen, &err);
    WSAPROTOCOL_INFOW nextProtoInfo{};
    bool found = false;

    for (int i = 0; i < numProtos; ++i) {
        if (pProtoList[i].dwCatalogEntryId == nextCatalogId) {
            nextProtoInfo = pProtoList[i];
            found = true;
            break;
        }
    }
    HeapFree(GetProcessHeap(), 0, pProtoList);
    if (!found) return WSAEPROVIDERFAILEDINIT;

    WCHAR providerPath[MAX_PATH];
    INT pathLen = MAX_PATH;
    if (WSCGetProviderPath(&nextProtoInfo.ProviderId, providerPath, &pathLen, &err) == SOCKET_ERROR) {
        return WSAEPROVIDERFAILEDINIT;
    }

    WCHAR expandedPath[MAX_PATH];
    ExpandEnvironmentStringsW(providerPath, expandedPath, MAX_PATH);

    g_hNextProviderDll = LoadLibraryW(expandedPath);
    if (!g_hNextProviderDll) return WSAEPROVIDERFAILEDINIT;

    LPWSPSTARTUP pfnWSPStartup = reinterpret_cast<LPWSPSTARTUP>(
        GetProcAddress(g_hNextProviderDll, "WSPStartup")
    );
    if (!pfnWSPStartup) return WSAEPROVIDERFAILEDINIT;

    int ret = pfnWSPStartup(wVersionRequested, lpWSPData, &nextProtoInfo, UpcallTable, &g_NextProcTable);
    if (ret != 0) return ret;

    // Sao chép bảng 30 con trỏ hàm SPI và thay thế các hàm cần lọc
    *lpProcTable = g_NextProcTable;
    lpProcTable->lpWSPAccept   = Hook_WSPAccept;
    lpProcTable->lpWSPRecvFrom = Hook_WSPRecvFrom;

    return 0;
}