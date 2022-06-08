#include <stdio.h>
#include <unistd.h>
#include<stdlib.h>
#include<string.h>
#include<net/ethernet.h>
#include<netinet/ip.h>
#include<netinet/if_ether.h>
#include<sys/socket.h>
#include <sys/types.h>
#include<arpa/inet.h>
#include<stdint.h>
#include <sys/cdefs.h>
#include <netinet/ip_icmp.h>
#include <netinet/in.h>
#include <netinet/icmp6.h>
#include <errno.h>

#define ICMP_HDRLEN 8 
/**
 * @brief : for making this sniffer we used this site for helping:
 *  https://www.binarytides.com/packet-sniffer-code-c-linux/
 */


#define Max_packet 1600 // define the max length of a packet
void print_info(const uint8_t * pkt_buffer, uint16_t pkt_length);
int main(int argc, char* argv[])
{
    
    int error_code =0;
    ssize_t data_size; /// this is type that has -1 and all the positive numbers
    uint8_t packet_buffer[Max_packet]; // will be our buffer to remember the buffer there.
    struct in_addr in;
    struct sockaddr saddr;
    printf("Starting...\n");

    if(argc!=2){
        printf("usage %s [IFNAME]\n", argv[0]);
        error_code =1;
    }

    const char* interface_name = argv[1];
    int raw_socket = socket(AF_PACKET,SOCK_RAW,htons(ETH_P_ALL));
                    ///socket |||||domain, type, protocol|||
    if(raw_socket<0){
        perror("socket Error\n");
        error_code =2;
    }
    while(1){
        socklen_t saddr_size = sizeof(saddr);
        data_size = recvfrom(raw_socket, packet_buffer, Max_packet,0,&saddr,&saddr_size);
        if(data_size==-1){
            error_code =3;
        }
        //here we have packet already
        print_info(packet_buffer, data_size);
    }


}

void print_info(const uint8_t * pkt_buffer, uint16_t pkt_length){
    if(pkt_buffer==NULL){
        perror("the packed is not good");
    }
    
    struct iphdr * iph =(struct iphdr*) (pkt_buffer+sizeof(struct ethhdr));
    if(iph->protocol==IPPROTO_ICMP)
    {
        unsigned short iphdrlen;
	    iphdrlen = iph->ihl*4;
	    struct udphdr *udph = (struct udphdr*)(pkt_buffer + iphdrlen);
        struct sockaddr_in source,dest;
        memset(&source,0,sizeof(source));
        source.sin_addr.s_addr = iph->saddr;
	
	    memset(&dest, 0, sizeof(dest));
	    dest.sin_addr.s_addr = iph->daddr;

        printf("IP Header\n");
        printf("   |-IP Version        : %d\n",(unsigned int)iph->version);
        printf("   |-IP Header Length  : %d DWORDS or %d Bytes\n",(unsigned int)iph->ihl,((unsigned int)(iph->ihl))*4);
        printf("   |-Type Of Service   : %d\n",(unsigned int)iph->tos);
        printf("   |-IP Total Length   : %d  Bytes(Size of Packet)\n",ntohs(iph->tot_len));
        printf("   |-Identification    : %d\n",ntohs(iph->id));
        printf("   |-TTL      : %d\n",(unsigned int)iph->ttl);
        printf("   |-Protocol : %d\n",(unsigned int)iph->protocol);
        printf("   |-Checksum : %d\n",ntohs(iph->check));
        printf("   |-Source IP        : %s\n",inet_ntoa(source.sin_addr));
        printf("   |-Destination IP   : %s\n",inet_ntoa(dest.sin_addr));
    }
}