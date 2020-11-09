#include "include.h"

bool is_scanning = false;

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
        arp_packet = (arp_frame *)rep;
        if((arp_packet->arp.sender_ip == ip) && (ntohs(arp_packet->arp.opcode) == 2)){
            memcpy(mac, arp_packet->arp.sender_mac, 6);
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
    }

    // check correct arp reply
    check_arp_reply(handle, header, target_ip, rep, target_mac);  
}


void scan_pkt_check(char * iface_name, uint32_t my_ip, uint32_t gw_ip, uint8_t * my_mac){
    int k = 0;
    char err[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(iface_name, BUFSIZ, 1, 1000, err);
    struct pcap_pkthdr* header;
    const u_char *rep;
    arp_frame * pkt_ptr;

    // scan_pkt_send 스레드에서 전송한 reqeust 패킷에 대해 응답이 있으면 여기서 저장
    while(1){
        char data[1024] = {0,};
        data[0] = '3';
        data[1] = '\t';
        if(k == 5){
            break; // scanning end
        }

        // 패킷 하나씩 캡처. pcap_next_ex 함수를 호출할 때마다 다음 패킷을 가리키게 된다
        int ret = pcap_next_ex(handle, &header, &rep);          
        if(ret == 0 || ret == -1){
            if(!is_scanning){
                k++;
            }
            continue;
        }
        pkt_ptr = (arp_frame *)rep;

        // arp response이고, 응답 패킷이고, 그 응답 패킷이 프로그램을 실행한 호스트로 온 것이라면
        // 해당 패킷은 arp reqeust에 대한 제대로 된 응답이라고 판단. ip와 mac 주소 확인 가능
        if((ntohs(pkt_ptr->eth.ether_type) == 0x0806) && (pkt_ptr->arp.target_ip == my_ip) &&
            (memcpy(pkt_ptr->arp.target_mac, my_mac, sizeof(uint8_t)*6))
            && (ntohs(pkt_ptr->arp.opcode) == 2) && (pkt_ptr->arp.sender_ip != gw_ip)){
            
            bool check = false;

            if(check == true){
                continue;
            }

            char str_mac[21];
            char str_ip[16] = {0, };
            uint8_t find_mac[6] = {0,};
            uint32_t find_ip;

            sprintf(str_mac, "%02X:%02X:%02X:%02X:%02X:%02X",pkt_ptr->arp.sender_mac[0],pkt_ptr->arp.sender_mac[1],pkt_ptr->arp.sender_mac[2],
            pkt_ptr->arp.sender_mac[3],pkt_ptr->arp.sender_mac[4],pkt_ptr->arp.sender_mac[5]);
            for(int i = 0; i < 6; i++){
                find_mac[i] = pkt_ptr->arp.sender_mac[i];
            }
            
            sprintf(str_ip, "%d.%d.%d.%d", (pkt_ptr->arp.sender_ip)&0xFF, (pkt_ptr->arp.sender_ip>>8)&0xFF,
             (pkt_ptr->arp.sender_ip>>16)&0xFF, (pkt_ptr->arp.sender_ip>>24)&0xFF);
            find_ip = pkt_ptr->arp.sender_ip;

            // str_mac에는 문자열 형태의 MAC. str_ip에는 dotted 형식의 문자열 IP 저장
            // find_mac에는 바이트 단위로 저장된 MAC. find_ip에는 숫자 형식의 IP 저장.
            printf("[+] FIND dev\n");
            printf("\t[*] IP: %s\n\t[*] MAC: %s\n", str_ip, str_mac);

        }
        if(!is_scanning){
            k++;
        }
    }
    printf("\n*******************************************\n");
    printf("**            Made by BIJI               **\n");
    printf("*******************************************\n");
    pcap_close(handle); 
}

void scan_pkt_send(uint32_t subnet, char * iface_name, uint32_t my_ip, uint8_t * my_mac){

    uint32_t broad_ip = 0;
    uint8_t broad_mac[6];
    memset(broad_mac, 0xff, sizeof(uint8_t)*6);

    char err[PCAP_ERRBUF_SIZE];
    pcap_t * handle = pcap_open_live(iface_name, BUFSIZ, 1, 1000, err);
    struct pcap_pkthdr* header;
    const u_char *rep;
    arp_frame * arp_pkt = (arp_frame *)malloc(sizeof(arp_frame));

    uint32_t start_ip = (ntohl(my_ip) & ntohl(subnet)) +1;
    uint32_t end_ip = (ntohl(my_ip) | ntohl(~subnet)) +1;

    // scanning
    // subnet mask를 기준으로, 사용 가능한 아이피 대역에 대한 스캐닝 진행
    for(start_ip; start_ip <= end_ip; start_ip++){
        memset(arp_pkt, 0, sizeof(arp_frame));
        u_char pkt[sizeof(arp_frame)];
        memset(pkt, 0, sizeof(arp_frame));

        make_arp_packet(broad_mac, my_mac, 0x1,
        my_ip, htonl(start_ip), arp_pkt); //

        memcpy(pkt, arp_pkt, sizeof(arp_frame));

        // 아이피 하나씩 차례대로 arp request 전송
        // 응답이 제대로 왔는지는 send_pkt_check 스레드에서 따로 진행
        if(pcap_sendpacket(handle, pkt ,sizeof(pkt))!=0){
            printf("[-] Error in find target's MAC\n");
            pcap_close(handle);
            exit(0);
        }
        // packet 전송 주기. 이보다 짧게하면 손실되는 패킷이 존재한다.
        usleep( 1000 * 350 );
    }
    pcap_close(handle); 
    free(arp_pkt);
    is_scanning = false;
}