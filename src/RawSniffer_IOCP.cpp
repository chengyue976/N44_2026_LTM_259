#include "PacketHeaders.h"
#include <ws2tcpip.h>
#include <mstcpip.h>
#include <iostream>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <string>

#pragma comment(lib, "ws2_32.lib")

#define BUFFER_SIZE     65536
#define THRESHOLD_SYN   100     
#define THRESHOLD_UDP   1000    
#define WINDOW_MS       1000    
#define NUM_POSTED_RECV 16      

struct IpTrafficStats {
    uint32_t  syn_count    = 0;
    uint32_t  udp_count    = 0;
    ULONGLONG window_start = 0;
};

struct PerIoContext {
    WSAOVERLAPPED overlapped;
    WSABUF        wsaBuf;
    char          buffer[BUFFER_SIZE];
    DWORD         flags;
};

CRITICAL_SECTION g_Lock;
std::unordered_map<uint32_t, IpTrafficStats> g_TrafficTable;
std::unordered_set<uint32_t> g_Blacklist;

SOCKET           g_RawSocket        = INVALID_SOCKET;
HANDLE           g_hMapFile         = NULL;
SharedBlacklist* g_pSharedBlacklist = nullptr;

// Chuyển đổi địa chỉ IP 32-bit sang chuỗi để in log
std::string IpToString(uint32_t ipNetOrder) {
    char ipStr[INET_ADDRSTRLEN] = { 0 };
    in_addr addr;
    addr.s_addr = ipNetOrder;
    InetNtopA(AF_INET, &addr, ipStr, INET_ADDRSTRLEN);
    return std::string(ipStr);
}

// Khởi tạo vùng nhớ chia sẻ để giao tiếp với LSP_Filter.dll
bool InitSharedMemory() {
    g_hMapFile = CreateFileMappingW(
        INVALID_HANDLE_VALUE,
        NULL,
        PAGE_READWRITE,
        0,
        sizeof(SharedBlacklist),
        SHARED_MEM_NAME
    );
    if (!g_hMapFile) {
        std::cerr << "[ERROR] CreateFileMappingW that bai: " << GetLastError() << "\n";
        return false;
    }

    g_pSharedBlacklist = reinterpret_cast<SharedBlacklist*>(
        MapViewOfFile(g_hMapFile, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(SharedBlacklist))
    );
    if (!g_pSharedBlacklist) {
        std::cerr << "[ERROR] MapViewOfFile that bai: " << GetLastError() << "\n";
        CloseHandle(g_hMapFile);
        return false;
    }

    ZeroMemory(g_pSharedBlacklist, sizeof(SharedBlacklist));
    return true;
}

// Cập nhật danh sách IP bị chặn sang Shared Memory (gọi bên trong g_Lock)
void SyncBlacklistToSharedMemory() {
    if (!g_pSharedBlacklist) return;
    LONG idx = 0;
    for (uint32_t ip : g_Blacklist) {
        if (idx >= MAX_BLACKLIST_IPS) break;
        g_pSharedBlacklist->ips[idx++] = ip;
    }
    InterlockedExchange(&g_pSharedBlacklist->count, idx);
}

// Phân tách tầng giao thức và kiểm tra ngưỡng Flood
void AnalyzePacket(const char* buffer, DWORD bytesTransferred) {
    if (bytesTransferred < sizeof(ip_hdr)) return;

    const ip_hdr* ip = reinterpret_cast<const ip_hdr*>(buffer);
    if (ip->version != 4) return;

    uint32_t ipHeaderLen = ip->ihl * 4;
    if (ipHeaderLen < sizeof(ip_hdr) || bytesTransferred < ipHeaderLen) return;

    uint32_t srcIp = ip->saddr;
    ULONGLONG now = GetTickCount64();

    EnterCriticalSection(&g_Lock);

    // Bỏ qua nếu IP đã nằm trong danh sách đen
    if (g_Blacklist.find(srcIp) != g_Blacklist.end()) {
        LeaveCriticalSection(&g_Lock);
        return;
    }

    IpTrafficStats& stats = g_TrafficTable[srcIp];
    if (now - stats.window_start >= WINDOW_MS) {
        stats.syn_count    = 0;
        stats.udp_count    = 0;
        stats.window_start = now;
    }

    bool detected = false;
    std::string attackType;

    if (ip->protocol == IPPROTO_TCP) {
        if (bytesTransferred >= ipHeaderLen + sizeof(tcp_hdr)) {
            const tcp_hdr* tcp = reinterpret_cast<const tcp_hdr*>(buffer + ipHeaderLen);
            // Chỉ đếm gói SYN thuần (SYN=1, ACK=0) để tránh kẻ tấn công giả mạo ACK làm giảm bộ đếm
            if (tcp->syn == 1 && tcp->ack == 0) {
                stats.syn_count++;
                if (stats.syn_count > THRESHOLD_SYN) {
                    detected = true;
                    attackType = "TCP SYN Flood";
                }
            }
        }
    }
    else if (ip->protocol == IPPROTO_UDP) {
        if (bytesTransferred >= ipHeaderLen + sizeof(udp_hdr)) {
            stats.udp_count++;
            if (stats.udp_count > THRESHOLD_UDP) {
                detected = true;
                attackType = "UDP Flood";
            }
        }
    }

    if (detected) {
        g_Blacklist.insert(srcIp);
        SyncBlacklistToSharedMemory();
        std::cout << "[ALERT] Phat hien " << attackType
                  << " tu IP: " << IpToString(srcIp)
                  << " -> Da them vao Blacklist LSP!\n";
    }

    LeaveCriticalSection(&g_Lock);
}

// Đẩy yêu cầu nhận gói tin bất đồng bộ vào IOCP
void PostAsyncRecv(PerIoContext* ctx) {
    ZeroMemory(&ctx->overlapped, sizeof(WSAOVERLAPPED));
    ctx->wsaBuf.buf = ctx->buffer;
    ctx->wsaBuf.len = BUFFER_SIZE;
    ctx->flags      = 0;

    DWORD bytesRecvd = 0;
    int ret = WSARecv(g_RawSocket, &ctx->wsaBuf, 1, &bytesRecvd, &ctx->flags, &ctx->overlapped, NULL);
    if (ret == SOCKET_ERROR && WSAGetLastError() != WSA_IO_PENDING) {
        std::cerr << "[WARN] WSARecv loi: " << WSAGetLastError() << "\n";
    }
}

// Luồng công nhân IOCP (Worker Thread)
DWORD WINAPI WorkerThread(LPVOID lpParam) {
    HANDLE hIocp = reinterpret_cast<HANDLE>(lpParam);
    DWORD bytesTransferred = 0;
    ULONG_PTR completionKey = 0;
    LPOVERLAPPED pOverlapped = nullptr;

    while (true) {
        BOOL ok = GetQueuedCompletionStatus(
            hIocp,
            &bytesTransferred,
            &completionKey,
            &pOverlapped,
            INFINITE
        );

        if (!ok || pOverlapped == nullptr) {
            if (pOverlapped == nullptr) break; 
            PerIoContext* ctx = CONTAINING_RECORD(pOverlapped, PerIoContext, overlapped);
            PostAsyncRecv(ctx);
            continue;
        }

        PerIoContext* ctx = CONTAINING_RECORD(pOverlapped, PerIoContext, overlapped);
        if (bytesTransferred > 0) {
            AnalyzePacket(ctx->buffer, bytesTransferred);
        }

        PostAsyncRecv(ctx);
    }
    return 0;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cout << "Cach dung: IDS_Monitor.exe <IP_Card_Mang_Cuc_Bo>\n";
        std::cout << "Vi du:    IDS_Monitor.exe 192.168.56.102\n";
        return 1;
    }

    const char* localIpStr = argv[1];
    InitializeCriticalSection(&g_Lock);

    if (!InitSharedMemory()) {
        return 1;
    }

    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "[ERROR] WSAStartup that bai.\n";
        return 1;
    }

    // Tạo Raw Socket hỗ trợ Overlapped I/O (yêu cầu quyền Administrator)
    g_RawSocket = WSASocketW(AF_INET, SOCK_RAW, IPPROTO_IP, NULL, 0, WSA_FLAG_OVERLAPPED);
    if (g_RawSocket == INVALID_SOCKET) {
        std::cerr << "[ERROR] Khong the tao SOCK_RAW (Hay chay voi quyen Admin!). Ma loi: "
                  << WSAGetLastError() << "\n";
        WSACleanup();
        return 1;
    }

    // Ràng buộc socket vào IP giao diện mạng cục bộ cụ thể (bắt buộc cho SIO_RCVALL)
    sockaddr_in localAddr{};
    localAddr.sin_family = AF_INET;
    localAddr.sin_port   = 0;
    if (InetPtonA(AF_INET, localIpStr, &localAddr.sin_addr) != 1) {
        std::cerr << "[ERROR] Dia chi IP khong hop le: " << localIpStr << "\n";
        closesocket(g_RawSocket);
        WSACleanup();
        return 1;
    }

    if (bind(g_RawSocket, reinterpret_cast<sockaddr*>(&localAddr), sizeof(localAddr)) == SOCKET_ERROR) {
        std::cerr << "[ERROR] bind() that bai: " << WSAGetLastError() << "\n";
        closesocket(g_RawSocket);
        WSACleanup();
        return 1;
    }

    // Kích hoạt chế độ Promiscuous (SIO_RCVALL) để bắt toàn bộ gói tin IPv4
    DWORD rcvAllOption = RCVALL_ON;
    DWORD bytesReturned = 0;
    if (WSAIoctl(g_RawSocket, SIO_RCVALL, &rcvAllOption, sizeof(rcvAllOption),
                 NULL, 0, &bytesReturned, NULL, NULL) == SOCKET_ERROR) {
        std::cerr << "[ERROR] WSAIoctl(SIO_RCVALL) that bai: " << WSAGetLastError() << "\n";
        closesocket(g_RawSocket);
        WSACleanup();
        return 1;
    }

    // Khởi tạo I/O Completion Port và gắn Raw Socket vào cổng
    HANDLE hIocp = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
    CreateIoCompletionPort(reinterpret_cast<HANDLE>(g_RawSocket), hIocp, 0, 0);

    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    DWORD numThreads = sysInfo.dwNumberOfProcessors;
    if (numThreads == 0) numThreads = 4;

    std::vector<HANDLE> workers;
    for (DWORD i = 0; i < numThreads; ++i) {
        workers.push_back(CreateThread(NULL, 0, WorkerThread, hIocp, 0, NULL));
    }

    // Cấp phát nhóm bộ đệm bất đồng bộ
    std::vector<PerIoContext*> ioContexts(NUM_POSTED_RECV);
    for (int i = 0; i < NUM_POSTED_RECV; ++i) {
        ioContexts[i] = new PerIoContext();
        PostAsyncRecv(ioContexts[i]);
    }

    std::cout << "[INFO] He thong IDS/IPS dang giam sat tren " << localIpStr
              << " voi " << numThreads << " IOCP Worker Threads...\n";
    std::cout << "[INFO] Nhan Enter de dung he thong.\n";
    std::cin.get();

    // Dọn dẹp tài nguyên
    closesocket(g_RawSocket);
    for (DWORD i = 0; i < numThreads; ++i) {
        PostQueuedCompletionStatus(hIocp, 0, 0, NULL);
    }
    WaitForMultipleObjects(numThreads, workers.data(), TRUE, 3000);

    for (HANDLE h : workers) CloseHandle(h);
    for (PerIoContext* ctx : ioContexts) delete ctx;
    CloseHandle(hIocp);

    if (g_pSharedBlacklist) UnmapViewOfFile(g_pSharedBlacklist);
    if (g_hMapFile) CloseHandle(g_hMapFile);
    DeleteCriticalSection(&g_Lock);
    WSACleanup();

    return 0;
}