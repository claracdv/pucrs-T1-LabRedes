/*-------------------------------------------------------------*/
/* Exemplo Socket Raw - Captura pacotes recebidos na interface */
/*-------------------------------------------------------------*/
#include <poll.h> // n sei

#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <string.h>
#include <unistd.h>
#include <libgen.h> // n sei
#include <netdb.h>	// n sei

/* Diretorios: net, netinet, linux contem os includes que descrevem */
/* as estruturas de dados do header dos protocolos                */

#include <net/if.h>			 //estrutura ifr
#include <netinet/tcp.h>	 //estrutura ifr
#include <netinet/udp.h>	 //estrutura ifr
#include <netinet/ether.h>	 //header ethernet
#include <netinet/in.h>		 //definicao de protocolos
#include <netinet/ip.h>		 //definicao de protocolos
#include <netinet/ip_icmp.h> //definicao de protocolos
#include <arpa/inet.h>		 //funcoes para manipulacao de enderecos IP

#include <netinet/in_systm.h> //tipos de dados

#define BUFFSIZE 1518

// Atencao!! Confira no /usr/include do seu sisop o nome correto
// das estruturas de dados dos protocolos.
struct porta_acessada
{
	uint16_t porta;
	int contador;
};

struct ip_acessado
{
	struct in_addr ip;
	int contador;
};

struct ip_acessado mais_acessados_ip[BUFFSIZE];
struct porta_acessada mais_acessados_portas[BUFFSIZE];

int pos_ip_mais_acessados = 0;
int pos_portas_mais_acessados = 0;

unsigned char buff1[BUFFSIZE]; // buffer de recepcao

int sockd;
int on;
struct ifreq ifr;

struct ether_header header;

int offset = 0;
int count_packet = 0;
int count_ipv4 = 0;
int count_arp_request = 0;
int count_arp_reply = 0;
int count_icmp_reply = 0;
int count_icmp_request = 0;
int count_tcp = 0;
int count_udp = 0;
int count_http = 0;
int count_https = 0;
int count_telnet = 0;
int count_dns = 0;

unsigned long total_size_packet = 0;
int current_size_packet = 14;
int min_size_packet = 1518;
int max_size_packet = 0;

// Implementar melhor, fazer pra os três vetores :D
//   struct ip_acessado        mais_acessados_ip[BUFFSIZE] ;
//   struct porta_acessada     mais_acessados_portas[BUFFSIZE] ;

int cmpfuncIp(const void *a, const void *b)
{
	struct ip_acessado *ia = (struct ip_acessado *)a;
	struct ip_acessado *ib = (struct ip_acessado *)b;

	return (ib->contador - ia->contador);
}

int cmpfuncPorta(const void *a, const void *b)
{
	struct porta_acessada *ia = (struct porta_acessada *)a;
	struct porta_acessada *ib = (struct porta_acessada *)b;

	return (ib->contador - ia->contador);
}

// void addIp(struct in_addr ip_address)
// {
// 	// procura a porta
// 	int i;
// 	for (i = 0; i < BUFFSIZE; i++)
// 	{
// 		if (mais_acessados_ip[i].ip.s_addr == ip_address.s_addr)
// 		{
// 			mais_acessados_ip[i].contador++;
// 			return;
// 		}
// 	}

// 	struct ip_acessado ip_temp;
// 	ip_temp.ip = ip_address;
// 	ip_temp.contador = 1;
// 	mais_acessados_ip[pos_ip_mais_acessados++] = ip_temp;
// }

// portas mais acessadas - separar 5 UDP 5 TCP
void addPorta(uint16_t porta)
{
	// procura a porta
	int i;
	for (i = 0; i < BUFFSIZE; i++)
	{
		if (mais_acessados_portas[i].porta == porta)
		{
			mais_acessados_portas[i].contador++;
			return;
		}
	}

	struct porta_acessada porta_temp;
	porta_temp.porta = porta;
	porta_temp.contador = 1;
	mais_acessados_portas[pos_portas_mais_acessados++] = porta_temp;
}

// void printArp(struct ether_arp etherArp)
// {

// 	printf("\n--ARP HEADER--");
// 	int i;
// 	printf("\n/* Format of hardware address.  */ %04x", htons(etherArp.ea_hdr.ar_hrd));
// 	printf("\n/* Format of protocol address.  */ %04x", htons(etherArp.ea_hdr.ar_pro));
// 	printf("\n/* Length of hardware address.  */ %02x", etherArp.ea_hdr.ar_hln);
// 	printf("\n/* Length of protocol address.  */ %02x", etherArp.ea_hdr.ar_pln);
// 	printf("\n/* ARP opcode (command).  */ %04x", htons(etherArp.ea_hdr.ar_op));

// 	printf("\n--ARP DATA--");
// 	printf("\n/* sender hardware address */ ");
// 	for (i = 0; i < ETH_ALEN; i++)
// 	{
// 		printf("%02x ", etherArp.arp_sha[i]);
// 	}
// 	printf("\n/* sender protocol address */ ");
// 	for (i = 0; i < 4; i++)
// 	{
// 		printf("%02x ", etherArp.arp_spa[i]);
// 	}
// 	printf("\n/* target hardware addres */ ");

// 	for (i = 0; i < ETH_ALEN; i++)
// 	{
// 		printf("%02x ", etherArp.arp_tha[i]);
// 	}
// 	printf("\n/* target protocol address */ ");
// 	for (i = 0; i < 4; i++)
// 	{
// 		printf("%02x ", etherArp.arp_tpa[i]);
// 	}
// }

// void printRaw()
// {
// 	int i;
// 	printf("\n");
// 	for (i = 0; i <= BUFFSIZE; i++)
// 	{
// 		printf("%02x ", buff1[i]);
// 	}
// }

// void printEthernet(struct ether_header header)
// {
// 	printf("\n--ETHERNET HEADER--");
// 	int i;
// 	printf("\n/* destination eth addr */ ");
// 	for (i = 0; i <= 5; i++)
// 	{
// 		printf("%02x ", header.ether_dhost[i]);
// 	}
// 	printf("\n/*source ether address*/ ");
// 	for (i = 0; i <= 5; i++)
// 	{
// 		printf("%02x ", header.ether_shost[i]);
// 	}
// 	printf("\n/* packet type ID field */ %04x", htons(header.ether_type));
// }

// void printIcmp(struct icmphdr icmp_header)
// {
// 	printf("\n--ICMP HEADER--\n");
// 	printf("/* message type */ %x\n", icmp_header.type);
// 	printf("/* type sub-code*/ %x\n", icmp_header.code);
// 	printf("/* message type */ %x\n", htons(icmp_header.checksum));

// 	printf("/* echo datagram */ \n");
// 	printf("Sequence %x\n", htons(icmp_header.un.echo.id));
// 	printf("Sequence %x\n", htons(icmp_header.un.echo.sequence));

// 	printf("/* gateway address */ %x\n", icmp_header.un.gateway);

// 	printf("/* path mtu discovery */\n");
// 	printf("__glibc_reserved %x\n", htons(icmp_header.un.frag.__glibc_reserved));
// 	printf("mtu %x\n", htons(icmp_header.un.frag.mtu));
// }

// void printIpv4(struct ip ip_header)
// {
// 	printf("\n--IP HEADER--\n");

// 	printf("/* header length */ %x\n", ip_header.ip_hl);
// 	printf("/* version */ %x\n", ip_header.ip_v);
// 	printf("/* total length */ %x\n", ip_header.ip_tos);
// 	printf("/* header length */ %x\n", ip_header.ip_len);
// 	printf("/* identification */ %x\n", ip_header.ip_id);

// 	printf("/* fragment offset field */ %x\n", ip_header.ip_off);
// 	printf("/* time to live */ %x\n", ip_header.ip_ttl);
// 	printf("/* protocol */ %x\n", ip_header.ip_p);
// 	printf("/* checksum */ %x\n", ip_header.ip_sum);

// 	printf("/* source address */ %x\n", ip_header.ip_src.s_addr);
// 	printf("/* dest address */ %x\n", ip_header.ip_dst.s_addr);
// }

void countpacket(struct ether_header header)
{

	if (htons(header.ether_type) == ETHERTYPE_IP)
	{
		count_ipv4++;

		struct ip ip_address;
		memcpy(&ip_address, &buff1[offset], sizeof(ip_address));

		offset += sizeof(ip_address);
		current_size_packet += (ip_address.ip_len);

		if (ip_address.ip_p == IPPROTO_ICMP)
		{

			struct icmphdr icmp_header;
			memcpy(&icmp_header, &buff1[offset], sizeof(icmp_header));
			offset += sizeof(icmp_header);

			if (icmp_header.type == ICMP_ECHOREPLY)
			{
				count_icmp_reply++;
			}
			else if (icmp_header.type == ICMP_ECHO)
			{
				count_icmp_request++;
			}
		}
		else if (ip_address.ip_p == IPPROTO_UDP)
		{
			count_udp++;
			struct udphdr udp_header;
			memcpy(&udp_header, &buff1[offset], sizeof(udp_header));
			offset += sizeof(udp_header);

			addPorta(udp_header.uh_sport);
			addPorta(udp_header.uh_dport);
			// printf("adding %x %x",udp_header.uh_sport,udp_header.uh_dport);
			if (htons(udp_header.uh_dport) == 0x35 || htons(udp_header.uh_sport) == 0x35)
			{
				count_dns++;
			}
		}

		else if (ip_address.ip_p == IPPROTO_TCP)
		{
			count_tcp++;

			struct tcphdr tcp_header;
			memcpy(&tcp_header, &buff1[offset], sizeof(tcp_header));
			offset += sizeof(tcp_header);

			addPorta(tcp_header.th_sport);
			addPorta(tcp_header.th_dport);

			if (htons(tcp_header.th_dport) == 0x50 || htons(tcp_header.th_sport) == 0x50)
			{
				count_http++;
			}
			else if (htons(tcp_header.th_dport) == 0x35 || htons(tcp_header.th_sport) == 0x35)
			{
				count_dns++;
			}
			else if (htons(tcp_header.th_dport) == 0x1bb || htons(tcp_header.th_sport) == 0x1bb)
			{
				addIp(ip_address.ip_dst);
				count_https++;
			}
			else if (htons(tcp_header.th_dport) == 0x17 || htons(tcp_header.th_sport) == 0x17)
			{
				count_telnet++;
			}
		}
	}
	else if (htons(header.ether_type) == ETHERTYPE_ARP)
	{
		struct ether_arp etherArp;
		memcpy(&etherArp, &buff1[offset], sizeof(etherArp));
		offset += sizeof(etherArp);

		current_size_packet += sizeof(etherArp);

		if (htons(etherArp.ea_hdr.ar_op) == ARPOP_REQUEST)
		{
			count_arp_request++;
		}
		else if (htons(etherArp.ea_hdr.ar_op) == ARPOP_REPLY)
		{
			count_arp_reply++;
		}
	}
}

// void printIps(int n)
// {
// 	printf("\n%d ips mais utilizadas\n", n);
// 	int i;
// 	for (i = 0; i < n; i++)
// 	{
// 		printf("Ip: %s \t\t", inet_ntoa(mais_acessados_ip[i].ip));
// 		printf("Quantidade : %d\n", mais_acessados_ip[i].contador);
// 	}
// }
void printPortas(int n)
{
	printf("\n%d portas mais utilizadas\n", n);
	int i;

	for (i = 0; i < n; i++)
	{
		printf("Porta : %x\t\t", htons(mais_acessados_portas[i].porta));
		printf("Quantidade : %d\n", mais_acessados_portas[i].contador);
	}
}

void printStatistics()
{
	printf("\nPackets Total: %d", count_packet);
	printf("\nPackets MIN Packet: %d", min_size_packet);
	printf("\nPackets MAX Packet: %d", max_size_packet);
	printf("\nPackets AVG Packet: %lu", (total_size_packet / count_packet));

	printf("\nPackets ARP Request :  %.2f %% (%d)", ((float)(100 * count_arp_request) / count_packet), count_arp_request);
	printf("\nPackets ARP Reply: %.2f %% (%d)", ((float)(100 * count_arp_reply) / count_packet), count_arp_reply);

	printf("\nPackets IPV4: %.2f %% (%d)", ((float)(100 * count_ipv4) / count_packet), count_ipv4);
	printf("\nPackets ICMP Request: %.2f %% (%d)", ((float)(100 * count_icmp_request) / count_packet), count_icmp_request);
	printf("\nPackets ICMP Reply: %.2f %% (%d)", ((float)(100 * count_icmp_reply) / count_packet), count_icmp_reply);

	printf("\nPackets TCP: %d", count_tcp);
	printf("\nPortas utilizadas: %d\n", pos_portas_mais_acessados);
	// 5 UDP 5 TCP
	// if (pos_portas_mais_acessados < 10)
	// {
	// 	printPortas(pos_ip_mais_acessados);
	// }
	// else
	// {
	printPortas(10);
	//}

	printf("\nPackets HTTP: %d", count_http);
	printf("\nPackets DNS: %d", count_dns);
	printf("\nPackets HTTPs: %d", count_https);
}

void clearScreen()
{
	// \e[1;1H - move o cursor para linha 1 coluna 1
	// \e[2J - move todo texto que esta no terminal para o scrollback buffer
	const char *CLEAR_SCREE_ANSI = "\e[1;1H\e[2J";
	write(STDOUT_FILENO, CLEAR_SCREE_ANSI, 12);
}

int loop()
{

	struct pollfd pfd;
	int s;

	pfd.fd = fileno(stdin);
	pfd.events = POLLRDNORM;

	while ((s = poll(&pfd, 1, 0)) == 0)
	{

		struct ether_header current;
		// Cleaning buffer...
		memset(&buff1[0], 0, sizeof(buff1));
		// Reseting offset
		offset = 0;
		// Reseting current size to 14 bytes
		current_size_packet = sizeof(current);

		recv(sockd, (char *)&buff1, sizeof(buff1), 0x0);
		memcpy(&current, &buff1, sizeof(current));

		offset += sizeof(current);
		countpacket(current);
		// guarda o menor e o maior tamanho de pacote
		if (current_size_packet > sizeof(current))
		{
			count_packet++;
			total_size_packet += current_size_packet;
			if (current_size_packet < min_size_packet)
			{
				min_size_packet = current_size_packet;
			}
			if (current_size_packet > max_size_packet)
			{
				max_size_packet = current_size_packet;
			}
		}

		// sort das listas
		//qsort(mais_acessados_ip, pos_ip_mais_acessados, sizeof(struct ip_acessado), cmpfuncIp);
		qsort(mais_acessados_portas, pos_portas_mais_acessados, sizeof(struct porta_acessada), cmpfuncPorta);

		printStatistics();
		// \033[2J - limpa a tela toda
		// \033[1;1H - posiciona o cursos na linha 1 coluna 1
		printf("\033[2J\033[1;1H");
	}

	return 0;
}

int main(int argc, char *argv[])
{
	/* Criacao do socket. Todos os pacotes devem ser construidos a partir do protocolo Ethernet. */
	/* De um "man" para ver os parametros.*/
	/* htons: converte um short (2-byte) integer para standard network byte order. */
	if ((sockd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
	{
		printf("Erro na criacao do socket.\n");
		exit(1);
	}

	// O procedimento abaixo eh utilizado para "setar" a interface em modo promiscuo
	strcpy(ifr.ifr_name, "enp0s3"); // eth0
	if (ioctl(sockd, SIOCGIFINDEX, &ifr) < 0)
		printf("erro no ioctl!");
	ioctl(sockd, SIOCGIFFLAGS, &ifr);
	ifr.ifr_flags |= IFF_PROMISC;
	ioctl(sockd, SIOCSIFFLAGS, &ifr);

	/*
	// recepcao de pacotes
	while (1)
	{
		recv(sockd, (char *)&buff1, sizeof(buff1), 0x0);
		// impress�o do conteudo - exemplo Endereco Destino e Endereco Origem
		printf("MAC Destino: %x:%x:%x:%x:%x:%x \n", buff1[0], buff1[1], buff1[2], buff1[3], buff1[4], buff1[5]);
		printf("MAC Origem:  %x:%x:%x:%x:%x:%x \n\n", buff1[6], buff1[7], buff1[8], buff1[9], buff1[10], buff1[11]);
	}
	*/

	return loop();
}
