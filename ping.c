/*************************************************************************
	> File Name: ping.c
	> Author: yuxintao
	> Mail: 1921056015@qq.com 
	> Created Time: 2022年03月08日 星期二 16时35分55秒
 ************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <unistd.h>
#include <signal.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/time.h>
#include <string.h>
#include <netdb.h>
#include <pthread.h>

typedef struct pingm_packet{
	struct timeval tv_begin;
	struct timeval tv_end;
	short seq;
	int flag;
}pingm_packet;

static pingm_packet pingpacket[128];
#define K 1024
#define BUFFERSIZE 72
static unsigned char send_buff[BUFFERSIZE];
static unsigned char recv_buff[2 * K];
static struct sockaddr_in dest;
static int rawsock = 0;
static pid_t pid = 0;
static int alive = 0;
static short packet_send = 0;
static short packet_recv = 0;
static char dest_str[80];
static struct timeval tv_begin, tv_end, tv_interval;

static void icmp_sigint(int signo);
static pingm_packet* icmp_findpacket(int seq);
static void icmp_statistics();
static void icmp_pack(struct icmp* icmph, int seq, int length);
static struct timeval icmp_tvsub(struct timeval end, struct timeval begin);
static int icmp_unpack(char *buf, int len);
static void* icmp_send(void* argv);
static void* icmp_recv(void* argv);

static unsigned short icmp_cksum(unsigned char* data, int len) {
	int sum = 0;
	int odd = len & 0x01;
	while (len & 0xfffe) {
		sum += *(unsigned short *)data;
		data += 2;
		len -= 2;
	}
	if (odd) {
		unsigned short tmp = ((*data) << 8) & 0xff00;
		sum += tmp;
	}
	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);

	return ~sum;
}
static void icmp_sigint(int signo) {
	alive = 0;
	gettimeofday(&tv_end, NULL);
	tv_interval = icmp_tvsub(tv_end, tv_begin);
	return;
}
static pingm_packet* icmp_findpacket(int seq) {
	int i = 0;
	pingm_packet* found = NULL;
	if (seq == -1) {
		for (i = 0; i < 128; ++i) {
			if (pingpacket[i].flag == 0) {
				found = pingpacket + i;
				break;
			}
		}
	} else {
		for (i = 0; i < 128; ++i) {
			if (pingpacket[i].flag == 1 && pingpacket[i].seq == seq) {
				found = pingpacket + i;
				break;
			}
		}
	}
	return found;
}


static void icmp_statistic() {
	long time = (tv_interval.tv_sec * 1000) + (tv_interval.tv_usec / 1000);
	printf("--%s ping statistics--\n", dest_str);
	printf("%d packets transmitted, %d received, %d%c packet loss, time %d ms\n", packet_send, packet_recv, (packet_send - packet_recv) * 100 / packet_send, '%', time);
}

static void icmp_pack(struct icmp* icmph, int seq, int length) {
	unsigned char i = 0;
	icmph->icmp_type = ICMP_ECHO;
	icmph->icmp_code = 0;
	icmph->icmp_cksum = 0;
	icmph->icmp_seq = seq;
	icmph->icmp_id = pid & 0xffff;
	for (i = 0; i < length - 8; i++) {
		icmph->icmp_data[i] = i;
	}
	icmph->icmp_cksum = icmp_cksum((unsigned char*)icmph, length);
}

static struct timeval icmp_tvsub(struct timeval end, struct timeval begin) {
	struct timeval tv;
	tv.tv_sec = end.tv_sec - begin.tv_sec;
	tv.tv_usec = end.tv_usec - begin.tv_usec;
	if (tv.tv_usec < 0) {
		tv.tv_sec--;
		tv.tv_usec += 1000000;
	}
	return tv;
}

static int icmp_unpack(char *buf, int len) {
	int i, iphdrlen;
	struct ip *ip = NULL;
	struct icmp* icmp = NULL;
	ip = (struct ip*)buf;
	iphdrlen = ip->ip_hl * 4;
	icmp = (struct icmp *)(buf + iphdrlen);
	len -= iphdrlen;
	if ((icmp->icmp_type == ICMP_ECHOREPLY) && (icmp->icmp_id == pid)) {//modify
		struct timeval tv_interval, tv_recv, tv_send;
		pingm_packet* packet = icmp_findpacket(icmp->icmp_seq);
		if (packet == NULL) {
			return -1;
		}
		packet->flag = 0;
		tv_send = packet->tv_begin;
		
		gettimeofday(&tv_recv, NULL);
		tv_interval = icmp_tvsub(tv_recv, tv_send);
		int rtt = tv_interval.tv_sec * 1000 + tv_interval.tv_usec / 1000;

		printf("%d byte from %s: icmp_seq=%u ttl=%d rtt=%d ms\n", len, inet_ntoa(ip->ip_src), icmp->icmp_seq, ip->ip_ttl, rtt);
		packet_recv++;
		return 0;
	} else {
		return -1;
	}
}

static void* icmp_send(void* argv) {
	gettimeofday(&tv_begin, NULL);
	while (alive) {
	
		pingm_packet *packet = icmp_findpacket(-1);
		if (packet) {
			packet->seq = packet_send;
			packet->flag = 1;
			gettimeofday(&packet->tv_begin, NULL);
		}
		icmp_pack((struct icmp*)send_buff, packet_send, 64);
	
		int size = 0;	
		size = sendto(rawsock, send_buff, 64, 0, (struct sockaddr *)&dest, sizeof(dest));

		if (size < 0) {
			perror("sendto error");
			continue;
		}
		packet_send++;
		sleep(1);
	}
}

static void* icmp_recv(void* argv) {
	struct timeval tv;
	tv.tv_usec = 200;
	tv.tv_sec = 0;
	fd_set readfd;
	while (alive) {
		int ret = 0;
		FD_ZERO(&readfd);
		FD_SET(rawsock, &readfd);
		ret = select(rawsock + 1, &readfd, NULL, NULL, &tv);
		int size = 0;
		switch(ret) {
			case -1:
				break;
			case 0:
				break;
			default:
				//int fromlen = 0;
				//struct sockaddr from;
				size = recv(rawsock, recv_buff, sizeof(recv_buff), 0);
				if (errno == EINTR) {
					perror("recvfrom error");
				}
				ret = icmp_unpack(recv_buff, size);
				if (ret == -1) 
					printf("miss\n");
				break;
		}
	}
}

static void icmp_usage()
{
	printf("ping aaa.bbb.ccc.ddd\n");
}

int main(int argc, char** argv)
{
	if (argc < 2) {
		icmp_usage();
		return -1;
	}
	//create socket
	struct protoent* protocol = NULL;
	char protoname[] = "icmp";
	protocol = getprotobyname(protoname);
	if (protocol == NULL) {
		perror("getprotobyname()");
		return -1;
	}
	rawsock = socket(AF_INET, SOCK_RAW, protocol->p_proto);
	if (rawsock < 0) {
		perror("socket");
		return -1;
	}

	
	//increase buffer
	int size = 128 * K;
	setsockopt(rawsock, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size));
	
	//write dest
	memcpy(dest_str, argv[1], strlen(argv[1]) + 1);
	bzero(&dest, sizeof(dest));

	dest.sin_family = AF_INET;
	unsigned long inaddr = 1;	
	inaddr = inet_addr(argv[1]);
	if (inaddr == INADDR_NONE) {
		struct hostent* host = NULL;
		host = gethostbyname(argv[1]);
		if (host == NULL) {
			perror("gethostbyname");
			return -1;
		}
		memcpy((char*)&dest.sin_addr, host->h_addr, host->h_length);
	} else {
		memcpy((char*)&dest.sin_addr, &inaddr, sizeof(inaddr));
	}

	inaddr = dest.sin_addr.s_addr;
	printf("PING %s (%d.%d.%d.%d) 56(84) bytes of data.\n", dest_str, inaddr & 0xFF, (inaddr & 0xFF00) >> 8, (inaddr & 0xFF0000)>>16, (inaddr & 0xFF000000)>>24);
	signal(SIGINT, icmp_sigint);
	memset(pingpacket, 0, sizeof(pingm_packet) * 128);	
	pid = getuid();
	alive = 1;
	pthread_t send_id, recv_id;
	pthread_create(&send_id, NULL, icmp_send, NULL);
	pthread_create(&recv_id, NULL, icmp_recv, NULL);
	pthread_join(send_id, NULL);
	pthread_join(recv_id, NULL);

	close(rawsock);
	icmp_statistic();
	return 0;
}
