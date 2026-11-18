#include <winsock2.h>
#include <ws2spi.h>
#include <sporder.h>
#include <windows.h>
#include <iostream>
#include <vector>
#include <string>

#pragma comment(lib, "ws2_32.lib")

// Hai GUID định danh duy nhất cho Dummy Provider và Protocol Chain của LSP
static GUID GUID_LSP_DUMMY = { 0xa1b2c3d4, 0x1111, 0x2222, { 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa } };
static GUID GUID_LSP_CHAIN = { 0xb2c3d4e5, 0x2222, 0x3333, { 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb } };

std::vector<WSAPROTOCOL_INFOW> EnumerateAllProtocols() {
    DWORD size = 0;
    INT err = 0;
    WSCEnumProtocols(NULL, NULL, &size, &err);
    std::vector<WSAPROTOCOL_INFOW> list(size / sizeof(WSAPROTOCOL_INFOW));
    int count = WSCEnumProtocols(NULL, list.data(), &size, &err);
    if (count == SOCKET_ERROR) return {};
    list.resize(count);
    return list;
}

void InstallLSP(const wchar_t* dllPath) {
    auto protos = EnumerateAllProtocols();
    WSAPROTOCOL_INFOW baseTcp{}, baseUdp{};
    bool foundTcp = false, foundUdp = false;

    // 1. Tìm Base Provider TCP/IP và UDP/IP (IPv4, ChainLen == 1)
    for (const auto& p : protos) {
        if (p.iAddressFamily == AF_INET && p.ProtocolChain.ChainLen == 1) {
            if (p.iProtocol == IPPROTO_TCP && !foundTcp) { baseTcp = p; foundTcp = true; }
            if (p.iProtocol == IPPROTO_UDP && !foundUdp) { baseUdp = p; foundUdp = true; }
        }
    }
    if (!foundTcp || !foundUdp) {
        std::cerr << "[ERROR] Khong tim thay Base TCP/UDP Provider.\n";
        return;
    }

    // 2. Cài đặt Dummy Provider (ChainLen = 0) để hệ thống cấp Catalog ID
    WSAPROTOCOL_INFOW dummyInfo = baseTcp;
    wcscpy_s(dummyInfo.szProtocol, L"IDS_LSP_Dummy");
    dummyInfo.ProtocolChain.ChainLen = 0;
    dummyInfo.dwProviderFlags |= PFL_HIDDEN;

    INT err = 0;
    if (WSCInstallProvider(&GUID_LSP_DUMMY, dllPath, &dummyInfo, 1, &err) == SOCKET_ERROR) {
        std::cerr << "[ERROR] Cai dat Dummy Provider that bai. Ma loi: " << err << "\n";
        return;
    }

    // Lấy Catalog ID vừa được cấp cho Dummy Provider
    DWORD dummyId = 0;
    for (const auto& p : EnumerateAllProtocols()) {
        if (IsEqualGUID(p.ProviderId, GUID_LSP_DUMMY)) {
            dummyId = p.dwCatalogEntryId;
            break;
        }
    }

    // 3. Tạo 2 chuỗi giao thức (ChainLen = 2) đè lên TCP và UDP cơ sở
    WSAPROTOCOL_INFOW chains[2] = { baseTcp, baseUdp };
    wcscpy_s(chains[0].szProtocol, L"IDS_LSP_TCP_Filter");
    wcscpy_s(chains[1].szProtocol, L"IDS_LSP_UDP_Filter");

    for (int i = 0; i < 2; ++i) {
        chains[i].ProtocolChain.ChainLen = 2;
        chains[i].ProtocolChain.ChainEntries[0] = dummyId;
        chains[i].ProtocolChain.ChainEntries[1] = (i == 0) ? baseTcp.dwCatalogEntryId : baseUdp.dwCatalogEntryId;
    }

    if (WSCInstallProvider(&GUID_LSP_CHAIN, dllPath, chains, 2, &err) == SOCKET_ERROR) {
        std::cerr << "[ERROR] Cai dat Protocol Chain that bai. Ma loi: " << err << "\n";
        WSCDeinstallProvider(&GUID_LSP_DUMMY, &err);
        return;
    }

    // 4. Đưa 2 mục LSP mới lên đầu danh mục Winsock (WSCWriteProviderOrder)
    auto updatedProtos = EnumerateAllProtocols();
    std::vector<DWORD> newOrder;
    for (const auto& p : updatedProtos) {
        if (IsEqualGUID(p.ProviderId, GUID_LSP_CHAIN)) newOrder.push_back(p.dwCatalogEntryId);
    }
    for (const auto& p : updatedProtos) {
        if (!IsEqualGUID(p.ProviderId, GUID_LSP_CHAIN)) newOrder.push_back(p.dwCatalogEntryId);
    }

    if (WSCWriteProviderOrder(newOrder.data(), static_cast<DWORD>(newOrder.size())) != ERROR_SUCCESS) {
        std::cerr << "[WARN] Khong the sap xep lai thu tu Catalog.\n";
    }
    std::cout << "[OK] Da cai dat va dua IDS_LSP_Filter len dau Winsock Catalog!\n";
}

void RemoveLSP() {
    INT err = 0;
    WSCDeinstallProvider(&GUID_LSP_CHAIN, &err);
    WSCDeinstallProvider(&GUID_LSP_DUMMY, &err);
    std::cout << "[OK] Da go bo IDS_LSP_Filter khoi Winsock Catalog.\n";
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cout << "Cach dung: LSP_Installer.exe <install | remove>\n";
        return 1;
    }
    std::string cmd = argv[1];
    if (cmd == "install") InstallLSP(L"%SystemRoot%\\System32\\LSP_Filter.dll");
    else if (cmd == "remove") RemoveLSP();
    return 0;
}