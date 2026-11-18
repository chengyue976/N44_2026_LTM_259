#ifndef PACKET_HEADERS_H
#define PACKET_HEADERS_H

#include <winsock2.h>
#include <windows.h>
#include <cstdint>

#define SHARED_MEM_NAME L"Local\\IDS_Blacklist_SharedMem"
#define MAX_BLACKLIST_IPS 1024

struct SharedBlacklist{
    volatile LONG count;
    uint32_t ips[MAX_BLACKLIST_IPS]; // luu Ip o dang Network Byte Order 
};

#pragma pack(push, 1);

// cau truc IPv4 header chuan
struct ip_hdr{
    uint8_t ihl : 4;         // do dai header
    uint8_t version : 4;     // phien ban Ip
    uint8_t tos;             // loai dich vu
    uint16_t tot_len;        // tong chieu dai goi tin (header + data)
    uint16_t id;             // dinh danh goi tin
    uint16_t frag_off;       // co phan manh va offset
    uint8_t ttl;             // thoi gian song 
    uint8_t protocol;        // giao thuc tang tren
    uint16_t check;          // ma kiem tra loi header checksum
    uint32_t saddr;          // dia chi IP nguon
    uint32_t daddr;          // dia chi IP dich
};

// cau truc TCP header chuan 
struct tcp_hdr{
    uint16_t source;         
    uint16_t dest;           
    uint32_t seq;            
    uint32_t ack_seq;        
    uint8_t res1 : 4;        
    uint8_t doff : 4;        
    uint8_t fin : 1;         
    uint8_t syn : 1;         
    uint8_t rst : 1;         
    uint8_t psh : 1;         
    uint8_t ack : 1;        
    uint8_t urg : 1;         
    uint8_t ece : 1;         
    uint8_t cwr : 1;         
    uint16_t window;         
    uint16_t check;          
    uint16_t urg_ptr;       
};

// cau truc UDP header
struct udp_hdr{
    uint16_t source;         
    uint16_t dest;           
    uint16_t len;
    uint16_t check;
};

// header gia ( dung de tinh checksum cho TCP/UDP)
struct pseudo_hdr{
    uint32_t source_address;
    uint32_t dest_address;
    uint8_t placeholder;
    uint8_t protocol;
    uint16_t tcp_udp_length;
};

#pragma pack(pop);

// ham tinh ma kiem tra checksum
inline uint16_t CalculateChecksum(const uint16_t* buffer, int size){
    uint32_t Cksum = 0;
    while (size > 1) {
        Cksum += *buffer++;
        size -= sizeof(uint16_t);
    }
    if(size){
        Cksum += *reinterpret_cast < const uint8_t* >(buffer);
    }
    Cksum = (Cksum >> 16) + (Cksum & 0xffff);
    Cksum += (Cksum >> 16);
    return static_cast<uint16_t>(~Cksum);
}

#endif