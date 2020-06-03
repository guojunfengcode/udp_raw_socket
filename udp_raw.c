#include <unistd.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include<memory.h>
#include<stdlib.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h> 
#include<arpa/inet.h>
#include<netinet/if_ether.h>

#define PCKT_LEN 100

typedef struct
{
	u_int32_t src;
	u_int32_t des;
	u_int8_t  zero;
	u_int8_t pro;
	u_int16_t len;
}UDP_PSEUDO_HEADER;

unsigned short checksum(unsigned short *buf, int nwords)
{ 
	unsigned long sum;
	for (sum = 0; nwords > 0; nwords--)
	{
		sum += *buf++;
	}
	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	return (unsigned short)(~sum);
}

int main(int argc, char *argv[])
{
	int fd;
	char buffer[PCKT_LEN] ;
	
	unsigned char DNS[] = { 0x11, 0x12, 0x01, 0x00, 0x00, 0x01, 
		0x00 ,0x00, 0x00, 0x00, 0x00, 0x00, 
		0x03, 0x77, 0x77, 0x77, 0x05, 0x62, 0x61, 0x69, 0x64, 0x75, 0x03, 0x63, 0x6F, 0x6D, 0x00,
		0x00, 0x01, 0x00, 0x01};
	struct iphdr *ip = (struct iphdr *) buffer;
	struct udphdr *udp = (struct udphdr *) (buffer + sizeof(struct iphdr));

	struct sockaddr_in sin, din;
	int  one = 1;
	const int *val = &one;
	memset(buffer, 0, PCKT_LEN);
 
	if (argc != 5)
	{
		printf("- Usage %s <source hostname/IP> <source port> <target hostname/IP> <target port>\n ./udp_raw 192.168.1.90 50000 114.114.114.114 53 tcpdump -i eno16777736 udp port 50000\n", argv[0]);
		exit(-1);
	}
 
	fd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
	if (fd < 0) {
		perror("socket() error");
		exit(-1);
	}
	printf("socket() - Using SOCK_RAW socket and UDP protocol is OK.\n");

	if (setsockopt(fd, IPPROTO_IP, IP_HDRINCL, val, sizeof(int))) {
		perror("setsockopt() error");
		exit(-1);
	}
	printf("setsockopt() is OK.\n");
 
	sin.sin_family = AF_INET;
	din.sin_family = AF_INET;
	
	sin.sin_port = htons(atoi(argv[2]));
	din.sin_port = htons(atoi(argv[4]));

	sin.sin_addr.s_addr = inet_addr(argv[1]);
	din.sin_addr.s_addr = inet_addr(argv[3]);
	
	ip->ihl = 5;
	ip->version = 4;
	ip->tos = 0;
	ip->tot_len = ((sizeof(struct iphdr) + sizeof(struct udphdr)+sizeof(DNS)));
	ip->ttl = 64;
	ip->protocol = 17;
	ip->check = 0;
	ip->saddr = inet_addr(argv[1]);
	ip->daddr = inet_addr(argv[3]);
	
	udp->source = htons(atoi(argv[2]));
	udp->dest = htons(atoi(argv[4]));
	udp->len = htons(sizeof(struct udphdr)+sizeof(DNS));

	char for_udp_check[sizeof(UDP_PSEUDO_HEADER) + sizeof(struct udphdr)+sizeof(DNS)+1] = {0};
	char * udpchecksum = for_udp_check;
	memset(udpchecksum, 0, sizeof(UDP_PSEUDO_HEADER) + sizeof(struct udphdr) + sizeof(DNS) + 1);
	UDP_PSEUDO_HEADER * udp_psd_Header = (UDP_PSEUDO_HEADER *)udpchecksum;
	
	udp_psd_Header->src = inet_addr(argv[1]);
	udp_psd_Header->des = inet_addr(argv[3]);
	udp_psd_Header->zero = 0;
	udp_psd_Header->pro = 17;
	udp_psd_Header->len = htons(sizeof(struct udphdr)+sizeof(DNS));
	
	memcpy(udpchecksum + sizeof(UDP_PSEUDO_HEADER), udp, sizeof(struct udphdr));
	memcpy(udpchecksum + sizeof(UDP_PSEUDO_HEADER) + sizeof(struct udphdr), DNS, sizeof(DNS));

	udp->check = checksum((unsigned short *)udpchecksum,(sizeof(struct udphdr)+sizeof(UDP_PSEUDO_HEADER)+sizeof(DNS)+1)/2);


	printf("Source IP: %s port: %u, Target IP: %s port: %u. Ip length: %d\n\n", argv[1], atoi(argv[2]), argv[3], atoi(argv[4]), ip->tot_len);
	int count;

	memcpy(buffer + sizeof(struct iphdr) + sizeof(struct udphdr), DNS, sizeof(DNS));
	
	for (count = 1; count <= 2000000; count++)
	{
		if (sendto(fd, buffer, ip->tot_len, 0, (struct sockaddr *)&din, sizeof(din)) < 0) {
			perror("sendto() error");
			exit(-1);
		} else {
			printf("Count #%u - sendto() is OK.\n", count);
			sleep(2);
		}
	}
	close(fd);
	return 0;
}