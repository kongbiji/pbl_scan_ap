#include "include.h"

bool get_iface_name(char * iface_name){
    // interface name
    char output[100] = {0,};
    FILE * stream = popen("ip route get 8.8.8.8", "r");

    fgets(output, 100, stream);

    // Check Network
    if(strcmp(output, "") == 0){
        return false;
    }

    char *ptr = strtok(output, " ");
    int i = 0;
    while (ptr != nullptr){
        if(i == 4){
            strcpy(iface_name, ptr);
            break;
        }
        i++;
        ptr = strtok(nullptr, " ");
    }
    return true;
}

bool get_gw_ip(char * gw_ip){
    // gateway ip
    char output[100] = {0,};
    FILE * stream = popen("ip route get 8.8.8.8", "r");

    fgets(output, 100, stream);

    // Check Network
    if(strcmp(output, "") == 0){
        return false;
    }

    char *ptr = strtok(output, " ");
    int i = 0;
    while (ptr != nullptr){
        if(i == 2){
            strcpy(gw_ip, ptr);
            break;
        }
        i++;
        ptr = strtok(nullptr, " ");
    }
    return true;
}


uint32_t get_subnet(char * dev)
{
    int sock;
    struct ifreq ifr;
    struct sockaddr_in *sin;

    sock = socket(AF_INET, SOCK_STREAM, 0);

    if (sock < 0) {
        return 0;
    }


    strcpy(ifr.ifr_name, dev);
    if (ioctl(sock, SIOCGIFNETMASK, &ifr)< 0)
    {
        printf("[-] cannot get subnet mask.\n");
        close(sock);
        return 0;
    }

    sin = (struct sockaddr_in*)&ifr.ifr_addr;
    uint32_t subnet_mask = sin->sin_addr.s_addr;
    close(sock);

    return subnet_mask;
}

bool get_my_ip(char * my_ip){
    char output[100] = {0,};
    FILE * stream = popen("ip route get 8.8.8.8", "r");

    fgets(output, 100, stream);

    char *ptr = strtok(output, " ");
    int i = 0;
    while (ptr != nullptr){
        if(i == 6){
            strcpy(my_ip, ptr);
            return true;
        }
        i++;
        ptr = strtok(nullptr, " ");
    }
    return false;
}

void get_gw_mac(char * dev, uint8_t * sender_mac, uint32_t sender_ip, uint8_t * target_mac, uint32_t target_ip){
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        printf("[-] cannot open pcap handle\n");
        exit(1);
    }
    struct pcap_pkthdr* header;
    const u_char *rep;
    find_mac(handle, header, rep, sender_mac, sender_ip, target_mac, target_ip);

    pcap_close(handle);
}

void get_my_mac(uint8_t * mac, char * dev){
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if(s < 0) perror("socket fail");
    struct ifreq ifr;
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    if(ioctl(s, SIOCGIFHWADDR, &ifr) < 0){
        printf("[-] cannot get Host's MAC\n");
        exit(1);
    }
    unsigned char * tmp = reinterpret_cast<unsigned char *>(ifr.ifr_hwaddr.sa_data);

    memcpy(mac, tmp, sizeof(uint8_t)*6);

}

void print_mac(uint8_t *mac){
    printf("%02X:%02X:%02X:%02X:%02X:%02X\n",mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
}

void print_ip(uint32_t ip){
    printf("%d.%d.%d.%d\n", (ip)&0xFF, (ip>>8)&0xFF, (ip>>16)&0xFF, (ip>>24)&0xFF);
}

