#include "include.h"

// 기기 스캐닝 스레드를 멈추기 위한 boolean 변수
extern bool is_scanning;

int main(){
    printf("*******************************************\n");
    printf("*******************************************\n");
    printf("**     AP Scanning program using ARP     **\n");
    printf("**                                       **\n");
    printf("**           Scanning Start!             **\n");
    printf("*******************************************\n");
    printf("*******************************************\n\n");

    uint32_t my_ip;
    uint32_t gateway_ip;
    uint32_t subnet_mask;
    uint32_t broadcast_ip;
    uint32_t subnet;
    uint8_t broadcast_mac[6];
    uint8_t my_mac[6] = {0, };
    uint8_t gateway_mac[6] = {0, };
    char interface_name[10] = { 0, };

    memset(broadcast_mac, 0xff, sizeof(uint8_t)*6);

    // 게이트웨이, 자신의 IP, MAC을 수집함 (함수 내용이 딱히 중요하진 않음)
    get_gw_ip(&my_ip, &gateway_ip, &subnet_mask, interface_name);
    get_my_mac(my_mac, interface_name);
    get_gw_mac(interface_name, my_mac, my_ip, gateway_mac, gateway_ip);
    get_broadcast_ip(&broadcast_ip, my_ip, subnet_mask);
    subnet = get_subnet(interface_name);


    // 스캐닝 스레드 시작
    is_scanning = true;
    // 실제 어떤 아이피에 어떤 MAC인지 확인하기 위해서는 아래의 scan_pkt_check 함수로 들어가보면 됨. 다른건 크게 중요 X
    std::thread scan_thread(scan_pkt_check, interface_name, my_ip, gateway_ip, my_mac); 
    std::thread scan_send_thread(scan_pkt_send, subnet, interface_name, my_ip, my_mac);

    scan_thread.join();
    scan_send_thread.join();
}