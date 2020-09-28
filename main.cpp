#include "include.h"

int main(){
    char errbuf[PCAP_ERRBUF_SIZE];
    // pcap_t * handle = pcap_open_live("wlan0", BUFSIZ, 1, 1000, errbuf);

    uint32_t my_ip;
    uint32_t gateway_ip;
    uint8_t my_mac[6] = {0, };
    uint8_t gateway_mac[6] = {0, };
    char interface_name[10] = { 0, };

    
    get_gw_ip(&my_ip, &gateway_ip, interface_name);
    get_my_mac(my_mac, interface_name);
    
    get_gw_mac(interface_name, my_mac, my_ip, gateway_mac, gateway_ip);

    printf("interface name >> %s\n", interface_name);
    printf("my ip >> ");print_ip(my_ip);
    printf("gateway ip >> "); print_ip(gateway_ip);
    printf("my mac >> "); print_mac(my_mac);
    printf("gateway mac >> "); print_mac(gateway_mac);
    
}