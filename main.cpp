#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h> /* for NF_ACCEPT */
#include <errno.h>
#include "iphdr.h"
#include "tcphdr.h"
#include <string.h>
#include <string>
#include <iostream>
#include <sqlite3.h>

#include <libnetfilter_queue/libnetfilter_queue.h>

char *my_strnstr(const char *big, const char *little, size_t len);  //출처: https://wonillism.tistory.com/163
bool check_list();
void usage();
std::string domain;
sqlite3 *db;
#pragma pack(push, 1)
struct Ip_Tcp final
{
	IpHdr ip_hdr;
	TcpHdr tcp_hdr;
	char data[256];
};
#pragma pack(pop)

/* returns packet id */
static u_int32_t print_pkt(struct nfq_data *tb)
{
	int id = 0;
	struct nfqnl_msg_packet_hdr *ph;
	struct nfqnl_msg_packet_hw *hwph;
	u_int32_t mark, ifi;
	int ret;
	unsigned char *data;

	ph = nfq_get_msg_packet_hdr(tb);
	if (ph)
	{
		id = ntohl(ph->packet_id);
		printf("hw_protocol=0x%04x hook=%u id=%u ",
			   ntohs(ph->hw_protocol), ph->hook, id);
	}

	hwph = nfq_get_packet_hw(tb);
	if (hwph)
	{
		int i, hlen = ntohs(hwph->hw_addrlen);

		printf("hw_src_addr=");
		for (i = 0; i < hlen - 1; i++)
			printf("%02x:", hwph->hw_addr[i]);
		printf("%02x ", hwph->hw_addr[hlen - 1]);
	}

	mark = nfq_get_nfmark(tb);
	if (mark)
		printf("mark=%u ", mark);

	ifi = nfq_get_indev(tb);
	if (ifi)
		printf("indev=%u ", ifi);

	ifi = nfq_get_outdev(tb);
	if (ifi)
		printf("outdev=%u ", ifi);
	ifi = nfq_get_physindev(tb);
	if (ifi)
		printf("physindev=%u ", ifi);

	ifi = nfq_get_physoutdev(tb);
	if (ifi)
		printf("physoutdev=%u ", ifi);

	ret = nfq_get_payload(tb, &data);
	if (ret >= 0)
		printf("payload_len=%d\n", ret);

	fputc('\n', stdout);

	return id;
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
			  struct nfq_data *nfa, void *data)
{
	u_int32_t id = print_pkt(nfa);
	printf("entering callback\n");
	int ret = 0;
	int data_size = 0;
	unsigned char *tempdata;
	const char *domain_name;
	const char *temp;
	int start = 5;
	int end = 5;

	ret = nfq_get_payload(nfa, &tempdata);
	if (ret >= 0)
	{
		//Tcp 확인
		IpHdr *ip_hdr = (struct IpHdr *)tempdata;
		if (ip_hdr->p_ != IpHdr::Tcp)
			return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);

		//Http 확인
		Ip_Tcp *ip_tcp = (struct Ip_Tcp *)tempdata;
		if (ip_tcp->tcp_hdr.sport() != 80 && ip_tcp->tcp_hdr.dport() != 80)
		{
			return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
		}

		data_size = ip_tcp->ip_hdr.len() - ip_tcp->ip_hdr.hl() * 4 - ip_tcp->tcp_hdr.off() * 4;
		printf("Data Size: %d \n", data_size);
		if (data_size > 0)
		{
			//Host가 존재하는지 데이터 길이만큼 확인 
			domain_name = my_strnstr(ip_tcp->data, "Host:", data_size);

			if (domain_name != NULL)
			{
				temp = domain_name;
				temp += 5;

				if (*temp == ' ')
				{
					temp += 1;
					start += 1;
					end += 1;
				}

				while (1)
				{
					if (*temp == '\r')
						break;
					else
					{
						temp += 1;
						end += 1;
						continue;
					}
				}
				printf("디비와 비교해서 검사 시작!!\n");
				std::string str(domain_name + start, domain_name + end);
				domain = str;
				//sqlite3 쿼리문 발생해서 디비에서 존재 검사
				if (check_list())
				{
					printf("존재합니다\n");
				 	return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
				}					
			}
		}
		return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
	}

	return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

char *my_strnstr(const char *big, const char *little, size_t len)
{
	size_t llen;
	size_t blen;
	size_t i;

	if (!*little)
		return ((char *)big);
	llen = strlen(little);
	blen = strlen(big);
	i = 0;
	if (blen < llen || len < llen)
		return (0);
	while (i + llen <= len)
	{
		if (big[i] == *little && !strncmp(big + i, little, llen))
			return ((char *)big + i);
		i++;
	}
	return (0);
}

bool check_list()
{
	int rc = 0;
	sqlite3_stmt *res;
	std::string query = "SELECT EXISTS (SELECT * FROM top_1m WHERE field2 = \"";
	query += domain;
	query += "\")";
	printf("%s \n", query.c_str());

	rc = sqlite3_prepare_v2(db, query.c_str(), -1, &res, 0);

	if (rc != SQLITE_OK)
	{
		fprintf(stderr, "Failed to fetch data: %s\n", sqlite3_errmsg(db));
		sqlite3_close(db);

		return 1;
	}

	rc = sqlite3_step(res);

	if (rc == SQLITE_ROW)
	{
		//printf("함수내 결과 : %d \n", sqlite3_column_int(res,0));
		if (sqlite3_column_int(res,0))
		{
			printf("함수내 존재\n");
			sqlite3_finalize(res);
			return true;
		}
		else
		{
			printf("함수내 비존재\n");
			sqlite3_finalize(res);
			return false;
		}
	}
	else
		return -1;
}

int main(int argc, char **argv)
{
	if (argc != 1)
	{
		usage();
		return -1;
	}

	int rc = sqlite3_open("Block_List", &db);

	if (rc != SQLITE_OK)
	{
		fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db));
		sqlite3_close(db);

		return 1;
	}
	else
		printf("open succesfully\n");

	

	//domain_name = &argv[1];
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	struct nfnl_handle *nh;
	int fd;
	int rv;
	char buf[4096] __attribute__((aligned));

	printf("opening library handle\n");
	h = nfq_open();
	if (!h)
	{
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}

	printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0)
	{
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}

	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0)
	{
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

	printf("binding this socket to queue '0'\n");
	qh = nfq_create_queue(h, 0, &cb, NULL);
	if (!qh)
	{
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0)
	{
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}

	fd = nfq_fd(h);

	for (;;)
	{
		if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0)
		{
			printf("pkt received\n");
			nfq_handle_packet(h, buf, rv);
			continue;
		}
		/* if your application is too slow to digest the packets that
		 * are sent from kernel-space, the socket buffer that we use
		 * to enqueue packets may fill up returning ENOBUFS. Depending
		 * on your application, this error may be ignored. nfq_nlmsg_verdict_putPlease, see
		 * the doxygen documentation of this library on how to improve
		 * this situation.
		 */
		if (rv < 0 && errno == ENOBUFS)
		{
			printf("losing packets!\n");
			continue;
		}
		perror("recv failed");
		break;
	}

	printf("unbinding from queue 0\n");
	nfq_destroy_queue(qh);

#ifdef INSANE
	/* normally, applications SHOULD NOT issue this command, since
	 * it detaches other programs/sockets from AF_INET, too ! */
	printf("unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);
#endif

	printf("closing library handle\n");
	sqlite3_close(db);
	nfq_close(h);

	exit(0);
}

void usage()
{
	printf("syntax : 1m-block\n");
	printf("sample : 1m-block\n");
}
