#include "include.h"

void get_gw_ip(uint32_t * my_ip, uint32_t * gw_ip, uint32_t *subnet_mask, char * iface_name){
    // Find available interface
    char error[PCAP_ERRBUF_SIZE];
    pcap_if_t* all_devs;
    char buf[1024];
    info *iface_info = (info *)malloc(sizeof(info));

    if(pcap_findalldevs(&all_devs, error) == -1) {
        printf("[-] error in pcap_findalldevs(%s)\n", error);
        return;
    }
    char auto_gateway_ip[20];
    char auto_iface_name[20];
    if(!get_gateway(auto_iface_name, auto_gateway_ip, 20)){
        printf("[-] Can not auto find interface\n");
        return;
    }
    char auto_gateway_ip_[30], auto_iface_name_[30];
    memset(auto_gateway_ip_, 0, 30);
    memset(auto_iface_name_, 0, 30);
    memcpy(auto_gateway_ip_, auto_gateway_ip, sizeof(auto_gateway_ip));
    memcpy(auto_iface_name_, auto_iface_name, sizeof(auto_iface_name));

    while(all_devs != nullptr){
        sprintf(iface_info->name, "%s", all_devs->name);
        sprintf(iface_info->desc, "%s", all_devs->description);

        iface_info->dev = all_devs;
        for(pcap_addr_t* pa = all_devs->addresses; pa != nullptr; pa = pa->next) {
            sockaddr* addr = pa->addr;
            sockaddr_in* addr_in = reinterpret_cast<sockaddr_in*>(addr);
            if(addr != nullptr && addr->sa_family == AF_INET)
                iface_info->ip = addr_in->sin_addr.s_addr;

            addr = pa->netmask;
            addr_in = reinterpret_cast<sockaddr_in*>(addr);
            if(addr != nullptr && addr->sa_family == AF_INET) {
                iface_info->subnetmask = addr_in->sin_addr.s_addr;

            }
        }
        iface_info->ip_and_mask = iface_info->ip & iface_info->subnetmask;

        char my_ip_tmp[30], iface_subnet[30];
        memset(my_ip_tmp, 0, 30);
        memset(iface_subnet, 0, 30);

        all_devs = all_devs->next;
        sprintf(my_ip_tmp, "%d.%d.%d.%d", (iface_info->ip)&0xFF, (iface_info->ip>>8)&0xFF, (iface_info->ip>>16)&0xFF, (iface_info->ip>>24)&0xFF);
        sprintf(iface_subnet, "%d.%d.%d.%d", (iface_info->subnetmask)&0xFF, (iface_info->subnetmask>>8)&0xFF, (iface_info->subnetmask>>16)&0xFF, (iface_info->subnetmask>>24)&0xFF);

        if(strcmp(auto_iface_name_, iface_info->name) == 0){
            *gw_ip = inet_addr(auto_gateway_ip_);
            *my_ip = inet_addr(my_ip_tmp);
            *subnet_mask = inet_addr(iface_subnet);
            strcpy(iface_name, iface_info->name);
            break;
        }
    }
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
        close(sock);
        return 0;
    }

    sin = (struct sockaddr_in*)&ifr.ifr_addr;
    uint32_t subnet_mask = sin->sin_addr.s_addr;
    close(sock);

    return subnet_mask;
}

void get_broadcast_ip(uint32_t * broadcast_ip, uint32_t ip, uint32_t subnet_mask){
    uint32_t network_addr = ip & subnet_mask;
    uint32_t tmp = subnet_mask ^ 0b11111111111111111111111111111111;
    //*broadcast_ip = network_addr | tmp;
    *broadcast_ip = network_addr;
}

void get_gw_mac(char * dev, uint8_t * sender_mac, uint32_t sender_ip, uint8_t * target_mac, uint32_t target_ip){
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
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
    if(ioctl(s, SIOCGIFHWADDR, &ifr) < 0)
        perror("ioctl fail");
    unsigned char * tmp = reinterpret_cast<unsigned char *>(ifr.ifr_hwaddr.sa_data);
    
    memcpy(mac, tmp, sizeof(uint8_t)*6);

}

void print_mac(uint8_t *mac){
    printf("%02X:%02X:%02X:%02X:%02X:%02X\n",mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
}

void print_ip(uint32_t ip){
    printf("%d.%d.%d.%d\n", (ip)&0xFF, (ip>>8)&0xFF, (ip>>16)&0xFF, (ip>>24)&0xFF);
}

