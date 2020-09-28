#include "include.h"

#pragma pack(push,1)
typedef struct {
    uint8_t dst_mac[6];
    uint8_t src_mac[6];
    uint16_t ether_type;
}Ether;

typedef struct {
    uint16_t hw_type;
    uint16_t p_type;
    uint8_t hw_len;
    uint8_t p_len;
    uint16_t opcode;
    uint8_t sender_mac[6];
    uint32_t sender_ip;
    uint8_t target_mac[6];
    uint32_t target_ip;
}ARP;

typedef struct {
    uint8_t v_l;
    uint8_t tos;
    uint16_t total_len;
    uint16_t id;
    uint16_t flag;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    uint32_t src_ip;
    uint32_t dst_ip;
}IP;

typedef struct {
    Ether eth;
    ARP arp;
}arp_frame;

typedef struct {
    Ether eth;
    IP ip;
}ip_frame;

typedef struct info_{
    char name[30];
    char desc[50];
    pcap_if_t * dev{nullptr};
    uint32_t ip;
    uint32_t subnetmask;
    uint32_t gateway;
    uint32_t ip_and_mask;
}info;
#pragma pack(pop)