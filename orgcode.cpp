
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/time.h> // gettimeofday()



 // IPv4 header len without options
#define IP4_HDRLEN 20

// ICMP header len for echo req
#define ICMP_HDRLEN 8 

// Checksum algo
unsigned short calculate_checksum(unsigned short * paddress, int len);

// 1. Change SOURCE_IP and DESTINATION_IP to the relevant
//     for your computer
// 2. Compile it using MSVC compiler or g++
// 3. Run it from the account with administrative permissions,
//    since opening of a raw-socket requires elevated preveledges.
//
//    On Windows, right click the exe and select "Run as administrator"
//    On Linux, run it as a root or with sudo.
//
// 4. For debugging and development, run MS Visual Studio (MSVS) as admin by
//    right-clicking at the icon of MSVS and selecting from the right-click 
//    menu "Run as administrator"
//
//  Note. You can place another IP-source address that does not belong to your
//  computer (IP-spoofing), i.e. just another IP from your subnet, and the ICMP
//  still be sent, but do not expect to see ICMP_ECHO_REPLY in most such cases
//  since anti-spoofing is wide-spread.

#define SOURCE_IP "10.0.2.15"
// i.e the gateway or ping to google.com for their ip-address
#define DESTINATION_IP "8.8.8.8"

int main ()
{
    struct icmp icmphdr; // ICMP-header
    char data[IP_MAXPACKET] = "This is the ping of Aviad Gilboa and Ofir Regev\n";
    int datalen = strlen(data) + 1;

    //===================
    // ICMP header
    //===================

    // Message Type (8 bits): ICMP_ECHO_REQUEST
    icmphdr.icmp_type = ICMP_ECHO;

    // Message Code (8 bits): echo request
    icmphdr.icmp_code = 0;

    // Identifier (16 bits): some number to trace the response.
    // It will be copied to the response packet and used to map response to the request sent earlier.
    // Thus, it serves as a Transaction-ID when we need to make "ping"
    icmphdr.icmp_id = 18; // hai

    // Sequence Number (16 bits): starts at 0
    icmphdr.icmp_seq = 0;

    // ICMP header checksum (16 bits): set to 0 not to include into checksum calculation
    icmphdr.icmp_cksum = 0;

    // Combine the packet 
    char packet[IP_MAXPACKET];

    // First, ICMP header.
    memcpy (packet, &icmphdr, ICMP_HDRLEN);

    // After ICMP header, add the ICMP data.
    memcpy (packet + ICMP_HDRLEN, data, datalen);

    // Calculate the ICMP header checksum
    icmphdr.icmp_cksum = calculate_checksum((unsigned short *) (packet), ICMP_HDRLEN + datalen);
    memcpy ((packet ), &icmphdr, ICMP_HDRLEN);

    struct sockaddr_in dest_in;
    memset (&dest_in, 0, sizeof (struct sockaddr_in));//We initialize the dest_in with 0
    dest_in.sin_family = AF_INET;
    dest_in.sin_addr.s_addr = inet_addr(DESTINATION_IP);
    
    // Create raw socket for IP-RAW (make IP-header by yourself)
    int sock = -1;
    if ((sock = socket (AF_INET, SOCK_RAW, IPPROTO_ICMP)) == -1) 
    {
        fprintf (stderr, "socket() failed with error: %d"
#if defined _WIN32
			, WSAGetLastError()
#else
			, errno
#endif
			);
        fprintf (stderr, "To create a raw socket, the process needs to be run by Admin/root user.\n\n");
        return -1;
    }
    //delete all about iphdr
    struct timeval start, stop; // we will use this to measure the time it takes to do the ping
    gettimeofday(&start, NULL);
    // Send the packet using sendto() for sending datagrams.
    if (sendto (sock, packet, ICMP_HDRLEN + datalen, 0, (struct sockaddr *) &dest_in, sizeof (dest_in)) == -1)  
    {
        fprintf (stderr, "sendto() failed with error: %d",errno);

        return -1;
    }
    printf("The packet was successfuly sent to %s\n", DESTINATION_IP);


char rec_buff[IP_MAXPACKET] = {0};//Init with zeroes
size_t buffer_size = sizeof(rec_buff); 
printf("got here1");
socklen_t len = sizeof(dest_in);
int rec_bytes = recvfrom(sock, rec_buff, buffer_size, 0 ,(struct sockaddr *) &dest_in, &len);
printf("got here");
if (rec_bytes > 0)
{
    printf("Recieved from %s\n", SOURCE_IP);
}


gettimeofday(&stop, NULL);

//calculating the rtt
double microSeconds = (double) stop.tv_usec - start.tv_usec;
double miliSeconds = microSeconds / 1000 ;
printf("The RTT in microseconds is : %.0f\n", microSeconds);
printf("The RTT in miliseconds is : %f\n", miliSeconds);

char icmp_rec_buf[IP_MAXPACKET];//buffer for the recieve packet
memcpy(icmp_rec_buf,rec_buff + IP4_HDRLEN +ICMP_HDRLEN, datalen);
printf ("The message that recieved in the destination ip is: %s\n", icmp_rec_buf);

  // Close the raw socket descriptor.
#if defined _WIN32
  closesocket(sock);
  WSACleanup();
#else
  close(sock);
#endif

  return 0;
}

// Compute checksum (RFC 1071).
unsigned short calculate_checksum(unsigned short * paddress, int len)
{
	int nleft = len;
	int sum = 0;
	unsigned short * w = paddress;
	unsigned short answer = 0;

	while (nleft > 1)
	{
		sum += *w++;
		nleft -= 2;
	}

	if (nleft == 1)
	{
		*((unsigned char *)&answer) = *((unsigned char *)w);
		sum += answer;
	}

	// add back carry outs from top 16 bits to low 16 bits
	sum = (sum >> 16) + (sum & 0xffff); // add hi 16 to low 16
	sum += (sum >> 16);                 // add carry
	answer = ~sum;                      // truncate to 16 bits

	return answer;
}


