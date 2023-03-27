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

struct porta_acessada
{
	uint16_t porta;
	int contador;
};

struct porta_acessada mais_acessados_portas_udp[BUFFSIZE];
struct porta_acessada mais_acessados_portas_tcp[BUFFSIZE];

int pos_portas_mais_acessados_udp = 0;
int pos_portas_mais_acessados_tcp = 0;

unsigned char buff1[BUFFSIZE]; // buffer de recepcao

int sockd;
int on;
struct ifreq ifr;

struct ether_header header;

int offset = 0;
int count_pacote = 0;
int count_arp_request = 0;
int count_arp_reply = 0;
int count_ipv4 = 0;
int count_icmp_reply = 0;
int count_icmp_request = 0;
int count_ipv6 = 0;
int count_icmpv6_reply = 0;
int count_icmpv6_request = 0;
int count_udp = 0;
int count_tcp = 0;
int count_http = 0;
int count_dns = 0;
int count_https = 0;

unsigned long total_tam_pacote = 0;
int atual_tam_pacote = 14;
int min_tam_pacote = 1518;
int max_tam_pacote = 0;

// metodo para sort das listas
int cmpfuncPorta(const void *a, const void *b)
{
	struct porta_acessada *ia = (struct porta_acessada *)a;
	struct porta_acessada *ib = (struct porta_acessada *)b;

	return (ib->contador - ia->contador);
}

void addPortaUdp(uint16_t porta)
{
	// procura a porta
	int i;
	for (i = 0; i < BUFFSIZE; i++)
	{
		if (mais_acessados_portas_udp[i].porta == porta)
		{
			mais_acessados_portas_udp[i].contador++;
			return;
		}
	}

	struct porta_acessada porta_temp;
	porta_temp.porta = porta;
	porta_temp.contador = 1;
	mais_acessados_portas_udp[pos_portas_mais_acessados_udp++] = porta_temp;
}

void addPortaTcp(uint16_t porta)
{
	// procura a porta
	int i;
	for (i = 0; i < BUFFSIZE; i++)
	{
		if (mais_acessados_portas_tcp[i].porta == porta)
		{
			mais_acessados_portas_tcp[i].contador++;
			return;
		}
	}

	struct porta_acessada porta_temp;
	porta_temp.porta = porta;
	porta_temp.contador = 1;
	mais_acessados_portas_tcp[pos_portas_mais_acessados_tcp++] = porta_temp;
}

void countpacote(struct ether_header header)
{

	if (htons(header.ether_type) == ETHERTYPE_IP)
	{
		count_ipv4++;

		struct ip ip_address;
		memcpy(&ip_address, &buff1[offset], sizeof(ip_address));

		offset += sizeof(ip_address);
		atual_tam_pacote += (ip_address.ip_len);

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

			addPortaUdp(udp_header.uh_sport);
			addPortaUdp(udp_header.uh_dport);

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

			addPortaTcp(tcp_header.th_sport);
			addPortaTcp(tcp_header.th_dport);

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
				count_https++;
			}
		}
	}
	else if (htons(header.ether_type) == ETHERTYPE_ARP)
	{
		struct ether_arp etherArp;
		memcpy(&etherArp, &buff1[offset], sizeof(etherArp));
		offset += sizeof(etherArp);

		atual_tam_pacote += sizeof(etherArp);

		if (htons(etherArp.ea_hdr.ar_op) == ARPOP_REQUEST)
		{
			count_arp_request++;
		}
		else if (htons(etherArp.ea_hdr.ar_op) == ARPOP_REPLY)
		{
			count_arp_reply++;
		}
	}
	else if (htons(header.ether_type) == ETHERTYPE_IPV6)
	{
		count_ipv6++;

		struct ip ip_address;
		memcpy(&ip_address, &buff1[offset], sizeof(ip_address));

		offset += sizeof(ip_address);
		atual_tam_pacote += (ip_address.ip_len);

		if (ip_address.ip_p == IPPROTO_ICMPV6)
		{
			struct icmphdr icmpv6_header;
			memcpy(&icmpv6_header, &buff1[offset], sizeof(icmpv6_header));
			offset += sizeof(icmpv6_header);

			if (icmpv6_header.type == ICMP_ECHOREPLY)
			{
				count_icmpv6_reply++;
			}
			else if (icmpv6_header.type == ICMP_ECHO)
			{
				count_icmpv6_request++;
			}
		}
		else if (ip_address.ip_p == IPPROTO_UDP)
		{
			count_udp++;
			struct udphdr udp_header;
			memcpy(&udp_header, &buff1[offset], sizeof(udp_header));
			offset += sizeof(udp_header);

			addPortaUdp(udp_header.uh_sport);
			addPortaUdp(udp_header.uh_dport);

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

			addPortaTcp(tcp_header.th_sport);
			addPortaTcp(tcp_header.th_dport);

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
				count_https++;
			}
		}
	}
}

void printPortasUdp(int n)
{
	printf("\n%d portas UDP mais utilizadas\n", n);
	int i;

	for (i = 0; i < n; i++)
	{
		printf("Porta : %x\t\t", htons(mais_acessados_portas_udp[i].porta));
		printf("Quantidade : %d\n", mais_acessados_portas_udp[i].contador);
	}
}

void printPortasTcp(int n)
{
	printf("\n%d portas TCP mais utilizadas\n", n);
	int i;

	for (i = 0; i < n; i++)
	{
		printf("Porta : %x\t\t", htons(mais_acessados_portas_tcp[i].porta));
		printf("Quantidade : %d\n", mais_acessados_portas_tcp[i].contador);
	}
}

void printEstatisticas()
{
	printf("\nPacotes Total: %d\n", count_pacote);
	printf("\nPacotes MIN Pacote: %d", min_tam_pacote);
	printf("\nPacotes MAX Pacote: %d", max_tam_pacote);
	printf("\nPacotes AVG Pacote: %lu\n", (total_tam_pacote / count_pacote));

	printf("\nPacotes ARP Request : %d (%.2f %%)", count_arp_request, ((float)(100 * count_arp_request) / count_pacote));
	printf("\nPacotes ARP Reply: %d (%.2f %%)\n", count_arp_reply, ((float)(100 * count_arp_reply) / count_pacote));

	printf("\nPacotes IPV4: %d (%.2f %%)", count_ipv4, ((float)(100 * count_ipv4) / count_pacote));
	printf("\nPacotes ICMP Request: %d (%.2f %%)", count_icmp_request, ((float)(100 * count_icmp_request) / count_pacote));
	printf("\nPacotes ICMP Reply: %d (%.2f %% )", count_icmp_reply, ((float)(100 * count_icmp_reply) / count_pacote));
	printf("\nPacotes IPV6: %d (%.2f %%)", count_ipv6, ((float)(100 * count_ipv6) / count_pacote));
	printf("\nPacotes ICMPV6 Request: %d (%.2f %%)", count_icmpv6_request, ((float)(100 * count_icmpv6_request) / count_pacote));
	printf("\nPacotes ICMPV6 Reply: %d (%.2f %% )\n", count_icmpv6_reply, ((float)(100 * count_icmpv6_reply) / count_pacote));

	printf("\nPacotes UDP: %d (%.2f %%)", count_udp, ((float)(100 * count_udp) / count_pacote));
	printf("\nPacotes TCP: %d (%.2f %%)\n", count_tcp, ((float)(100 * count_tcp) / count_pacote));
	printPortasUdp(5);
	printPortasTcp(5);

	printf("\nPacotes HTTP: %d (%.2f %%)", count_http, ((float)(100 * count_http) / count_pacote));
	printf("\nPacotes DNS: %d (%.2f %%)", count_dns, ((float)(100 * count_dns) / count_pacote));
	printf("\nPacotes HTTPs: %d (%.2f %%)", count_https, ((float)(100 * count_https) / count_pacote));
}

void limpaTela()
{
	// \e[1;1H - move o cursor para linha 1 coluna 1
	// \e[2J - move todo texto que esta no terminal para o scrollback buffer
	const char *CLEAR_SCREE_ANSI = "\e[1;1H\e[2J";
	write(STDOUT_FILENO, CLEAR_SCREE_ANSI, 11);
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
		// Limpando buffer
		memset(&buff1[0], 0, sizeof(buff1));
		// Resetando offset
		offset = 0;
		// Resetando tamanho atual para 14 bytes
		atual_tam_pacote = sizeof(atual);

		recv(sockd, (char *)&buff1, sizeof(buff1), 0x0);
		memcpy(&atual, &buff1, sizeof(atual));

		offset += sizeof(atual);
		countpacote(atual);
		// guarda o menor e o maior tamanho de pacote
		if (atual_tam_pacote > sizeof(atual))
		{
			count_pacote++;
			total_tam_pacote += atual_tam_pacote;
			if (atual_tam_pacote < min_tam_pacote)
			{
				min_tam_pacote = atual_tam_pacote;
			}
			if (atual_tam_pacote > max_tam_pacote)
			{
				max_tam_pacote = atual_tam_pacote;
			}
		}

		// sort das listas
		qsort(mais_acessados_portas_udp, pos_portas_mais_acessados_udp, sizeof(struct porta_acessada), cmpfuncPorta);
		qsort(mais_acessados_portas_tcp, pos_portas_mais_acessados_tcp, sizeof(struct porta_acessada), cmpfuncPorta);

		printEstatisticas();

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
