#include "include.h"

void make_arp_packet(uint8_t *target_mac, uint8_t *src_mac, int op, uint32_t sender_ip, uint32_t target_ip, arp_frame * packet){
    memcpy(packet->eth.dst_mac,target_mac,sizeof(packet->eth.dst_mac)); 
    memcpy(packet->eth.src_mac,src_mac,sizeof(packet->eth.src_mac));
    packet->eth.ether_type=htons(0x0806);
    packet->arp.hw_type=htons(0x0001);
    packet->arp.p_type=htons(0x0800);
    packet->arp.hw_len=0x06;
    packet->arp.p_len=0x04;
    packet->arp.opcode=htons(op);

    memcpy(packet->arp.sender_mac, src_mac, sizeof(packet->arp.sender_mac));
    if(op==1) { // ARP request, target == broadcast
        memcpy(packet->arp.target_mac, "\x00\x00\x00\x00\x00\x00", sizeof(packet->arp.target_mac));
    }
    if(op==2) { // ARP reply
        memcpy(packet->arp.target_mac, target_mac, sizeof(packet->arp.target_mac));
    }
    packet->arp.sender_ip = sender_ip;
    packet->arp.target_ip = target_ip;

}

void check_arp_reply(pcap_t* handle, pcap_pkthdr* header, uint32_t ip, const u_char * rep, uint8_t * mac){
    arp_frame * arp_packet;
    while(1){ //check correct arp reply
        pcap_next_ex(handle, &header, &rep);
        printf("test\n");
        arp_packet = (arp_frame *)rep;
        if((arp_packet->arp.sender_ip == ip) && (ntohs(arp_packet->arp.opcode) == 2)){
            memcpy(mac, arp_packet->arp.sender_mac, 6);
            printf("%02X:%02X:%02X:%02X:%02X:%02X\n",mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
            break;
        }
    }
}

void find_mac(pcap_t* handle, pcap_pkthdr *header, const u_char * rep, 
    uint8_t * sender_mac, uint32_t sender_ip, uint8_t * target_mac, uint32_t target_ip){
    unsigned char data[50];
    arp_frame * arp_pkt = (arp_frame *)malloc(sizeof(arp_frame));
    uint8_t broadcast[6];
    memcpy(broadcast,"\xFF\xFF\xFF\xFF\xFF\xFF",6);
    memset(data, 0, sizeof(data));
    make_arp_packet(broadcast, sender_mac, 1, sender_ip, target_ip, arp_pkt);
    memcpy(data, arp_pkt, sizeof(arp_frame));

    // send arp req to find taregt mac
    if(pcap_sendpacket(handle, data ,sizeof(data))!=0){
        printf("[-] Error in find target's MAC\n");
        pcap_close(handle);
        exit(0);
    }printf("[+] Success to find target's MAC\n");

    // check correct arp reply
    check_arp_reply(handle, header, target_ip, rep, target_mac);       
}

void scanning_ap(uint8_t * sender_mac, uint32_t sender_ip, uint8_t * target_mac, uint32_t target_ip, 
                uint32_t subnet_mask, char * ineterface_name){
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(ineterface_name, BUFSIZ, 1, 1000, errbuf);
    struct pcap_pkthdr* header;
    const u_char *rep;
    unsigned char data[50];
    arp_frame * arp_pkt = (arp_frame *)malloc(sizeof(arp_frame));

    for(int i = 1; i < 256; i++){
        memset(data, 0, sizeof(data));
        uint32_t tmp_target_ip = target_ip + htonl(i);
        make_arp_packet(target_mac, sender_mac, 1, sender_ip, tmp_target_ip, arp_pkt);
        memcpy(data, arp_pkt, sizeof(arp_frame));

        // send arp req to find taregt mac
        if(pcap_sendpacket(handle, data ,sizeof(data))!=0){
            printf("[-] Error in find target's MAC\n");
            pcap_close(handle);
            exit(0);
        }printf("[+] Success to find target's MAC\n");
        usleep( 1000 * 500 );

        // check correct arp reply
        check_arp_reply(handle, header, target_ip, rep, target_mac); 

    }
    
}