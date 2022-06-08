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
/// The size of the ICMPHDR
/**
 * @brief : for making this sniffer we used this site helping build this sniffer:
 *  https://www.binarytides.com/packet-sniffer-code-c-linux/
 */


#define Max_packet 1600 // define the max length of a packet
void print_info(const uint8_t * pkt_buffer, uint16_t pkt_length);  //use for print the info of the packet
int main()
{
    ssize_t data_size; /// this is type that has -1 and all the positive numbers
    uint8_t packet_buffer[Max_packet]; // will be our buffer to remember the buffer there. 
    struct sockaddr saddr; //  that struct save part of the information of packet.
    printf("Starting...\n"); // start to sniff packet - if it will be ICMP type we will print it.
    int raw_socket = socket(AF_PACKET,SOCK_RAW,htons(ETH_P_ALL)); /// open our socket. 
                    ///socket |||||domain -->AF_PACKET  = L2 socket, type--> SOCK_RAW, protocol --> in our case we bind to all the protocol type|||
    if(raw_socket<0){ //if the socket not success opening --> the return value is negative.
        perror("socket Error\n");
    }
    while(EOF){
        /// run untill the program end (stream end)
        socklen_t saddr_size = sizeof(saddr); // save the size of the sockaddr information
        data_size = recvfrom(raw_socket, packet_buffer, Max_packet,0,&saddr,&saddr_size);
        // save the size of the data we get for socket whren we get a packet.

        //here we have packet already and we send it to a function that will check if this is a ICMP protocol and print it if it is.
        print_info(packet_buffer, data_size);
    }
    printf("closing the socket\n");
    /// end the bind for packet of the socket
    close(raw_socket);
}

void print_info(const uint8_t * pkt_buffer, uint16_t pkt_length){
    if(pkt_buffer==NULL){
        perror("the packed is not good");
    }
    
    struct iphdr * iph =(struct iphdr*) (pkt_buffer+sizeof(struct ethhdr));
    // its jump to the part in the inforamtion of the socket that belong to ip and ICMP.
    if(iph->protocol==IPPROTO_ICMP)
    // protocol of ICMP is 1.
    {
        unsigned short iphdrlen;
	    iphdrlen = iph->ihl*4;
        /// get the length of the ipv4 on the packet
	    struct udphdr *udph = (struct udphdr*)(pkt_buffer + iphdrlen); 
        /// point to the place of the beginig of the iphdr info 
        struct sockaddr_in source,dest;
        memset(&source,0,sizeof(source));
        source.sin_addr.s_addr = iph->saddr;
        // copy the src info from the packet with casting to the sutable struct
	
	    memset(&dest, 0, sizeof(dest));
	    dest.sin_addr.s_addr = iph->daddr;
        // copy the dst info from the packet with casting to the sutable struct

        printf("IP Header\n");
        printf("   |-IP Version        : %d\n",(unsigned int)iph->version);
        printf("   |-IP Header Length  : %d DWORDS or %d Bytes\n",(unsigned int)iph->ihl,((unsigned int)(iph->ihl))*4);
        printf("   |-Type Of Service   : %d\n",(unsigned int)iph->tos);
        printf("   |-IP Total Length   : %d  Bytes(Size of Packet)\n",ntohs(iph->tot_len));
        printf("   |-Identification    : %d\n",ntohs(iph->id));
        printf("   |-TTL               : %d\n",(unsigned int)iph->ttl);
        printf("   |-Protocol          : %d\n",(unsigned int)iph->protocol);
        printf("   |-Checksum          : %d\n",ntohs(iph->check));
        printf("   |-Source IP         : %s\n",inet_ntoa(source.sin_addr));
        printf("   |-Destination IP    : %s\n",inet_ntoa(dest.sin_addr));
    }
}