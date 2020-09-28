#include "include.h"

int main(){
    uint32_t my_ip;
    uint32_t gateway_ip;
    uint32_t subnet_mask;
    uint32_t broadcast_ip;
    uint8_t broadcast_mac[6];
    uint8_t my_mac[6] = {0, };
    uint8_t gateway_mac[6] = {0, };
    char interface_name[10] = { 0, };

    memset(broadcast_mac, 0xff, sizeof(uint8_t)*6);

    get_gw_ip(&my_ip, &gateway_ip, &subnet_mask, interface_name);
    get_my_mac(my_mac, interface_name);
    get_gw_mac(interface_name, my_mac, my_ip, gateway_mac, gateway_ip);
    get_broadcast_ip(&broadcast_ip, my_ip, subnet_mask);

    // printf("interface name >> %s\n", interface_name);
    // printf("my ip >> ");print_ip(my_ip);
    // printf("gateway ip >> "); print_ip(gateway_ip);
    // printf("subnet mask >> "); print_ip(subnet_mask);
    // printf("my mac >> "); print_mac(my_mac);
    // printf("gateway mac >> "); print_mac(gateway_mac);
    // printf("network ip >> "); print_ip(broadcast_ip);

    // arp_frame * arp_pkt = (arp_frame *)malloc(sizeof(arp_frame));
    // unsigned char data[50];
    // memset(data, 0, sizeof(data));
    // make_arp_packet(broadcast_mac, my_mac, 0x1, my_ip, broadcast_ip, arp_pkt);
    // memcpy(data, arp_pkt, sizeof(arp_frame));

    // char errbuf[PCAP_ERRBUF_SIZE];
    // pcap_t* handle = pcap_open_live(interface_name, BUFSIZ, 1, 1000, errbuf);
    // struct pcap_pkthdr* header;
    // const u_char *rep;

    // // send arp req to find taregt mac
    // if(pcap_sendpacket(handle, data ,sizeof(data))!=0){
    //     printf("[-] Error in find target's MAC\n");
    //     pcap_close(handle);
    //     exit(0);
    // }printf("[+] Success to find target's MAC\n");
    scanning_ap(my_mac, my_ip, broadcast_mac, broadcast_ip, subnet_mask, interface_name);
}