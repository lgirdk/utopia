/*********************************************************************************
 * Copyright 2022 Liberty Global B.V
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *********************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/file.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <poll.h>
#include <resolv.h>
#include <arpa/inet.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <syscfg/syscfg.h>

#define DNSv4_FILTER_QUEUE 47
#define DNSv6_FILTER_QUEUE 48

#define ipv6_optlen(p) (((p)->hdrlen + 1) << 3)
#define ipv6_authlen(p) (((p)->hdrlen + 2) << 2)

// #define DEBUG 1

typedef struct dns_whitelist_url
{
    char hostname[48];
    struct dns_whitelist_url *next;
} dns_whitelist_url_t;

struct frag_hdr
{
    __u8 nexthdr;
    __u8 reserved;
    __be16 frag_off;
    __be32 identification;
};

static dns_whitelist_url_t *whitelisted_urls;

static int load_whitelisted_urls (void)
{
    char dns_syscfg_buff[16];
    int dns_no;
    int i;

    whitelisted_urls = NULL;

    syscfg_get(NULL, "dns_rebind_protection_enable", dns_syscfg_buff, sizeof(dns_syscfg_buff));

    if (strcmp(dns_syscfg_buff, "1") != 0)
    {
        return 0;
    }

    syscfg_get(NULL, "DNSRebindWhitelistUrlCount", dns_syscfg_buff, sizeof(dns_syscfg_buff));
    dns_no = atoi(dns_syscfg_buff);

    // Create a linked list
    for (i = 1; i <= dns_no; i++)
    {
        char prefix[32];
        dns_whitelist_url_t *dns_entry;

        if ((dns_entry = malloc(sizeof(dns_whitelist_url_t))) == NULL)
        {
            break;
        }

        snprintf(prefix, sizeof(prefix), "dnswhitelisted_%d", i);
        syscfg_get(prefix, "url", dns_entry->hostname, sizeof(dns_entry->hostname));

        if (dns_entry->hostname[0] == 0)
        {
            free(dns_entry);
            continue;
        }

        dns_entry->next = NULL;

        if (whitelisted_urls == NULL)
        {
            whitelisted_urls = dns_entry;
        }
        else
        {
            dns_whitelist_url_t *dns_entry_tail = whitelisted_urls;

            while (dns_entry_tail->next != NULL)
            {
                dns_entry_tail = dns_entry_tail->next;
            }

            dns_entry_tail->next = dns_entry;
        }
    }

    return 1;
}

static void print_whitelist_urls (void)
{
    dns_whitelist_url_t *dns_entry_tail = whitelisted_urls;
    int no = 1;

    while (dns_entry_tail != NULL)
    {
        fprintf(stdout, "Hostname-%d -> %s\n", no, dns_entry_tail->hostname);
        dns_entry_tail = dns_entry_tail->next;
        no++;
    }
}

static void free_whitelist_urls (void)
{
    while (whitelisted_urls != NULL)
    {
        dns_whitelist_url_t *dns_entry = whitelisted_urls;
        whitelisted_urls = whitelisted_urls->next;
        free(dns_entry);
    }
}

static int is_private_ip (const unsigned char *ip)
{
    int ret = 0;

    if (ip[0] == 10)
    {
        // 10.0.0.0/8
        ret = 1;
    }
    else if (ip[0] == 172 && ip[1] >= 16 && ip[1] <= 31)
    {
        // 172.16.0.0/12
        ret = 1;
    }
    else if (ip[0] == 192 && ip[1] == 168)
    {
        // 192.168.0.0/16
        ret = 1;
    }
    else if (ip[0] == 127)
    {
        // 127.0.0.0/8
        ret = 1;
    }

    return ret;
}

static int is_whitelisted (char *hostname)
{
    dns_whitelist_url_t *dns_entry_tail = whitelisted_urls;

    while (dns_entry_tail != NULL)
    {
        if (strcmp(dns_entry_tail->hostname, hostname) == 0)
        {
            return 1;
        }

        dns_entry_tail = dns_entry_tail->next;
    }

    return 0;
}

static int parse_dns_response (const unsigned char *msg, size_t len)
{
    ns_msg handle;
    ns_rr rr;
    int i, rdlen;
    char astr[INET6_ADDRSTRLEN];

    if (ns_initparse(msg, len, &handle) != 0)
    {
        /* TCP packets can come in segments. If a TCP DNS
           response comes in segments drop it for now.
           ns_initparse() will fail if msg not a
           full/valid dns response. */
        return NF_DROP;
    }

    for (i = 0; i < ns_msg_count(handle, ns_s_an); i++)
    {
        if (ns_parserr(&handle, ns_s_an, i, &rr) != 0)
        {
            continue;
        }

        rdlen = ns_rr_rdlen(rr);

        // Inspect only IPv4 address from the DNS Response
        if (ns_rr_type(rr) == ns_t_a)
        {
            if (rdlen != 4)
            {
                continue;
            }

            if (inet_ntop(AF_INET, ns_rr_rdata(rr), astr, sizeof(astr)))
            {
                // Need to check if the IP is private first, if not then continue parsing remaining packet
                if (is_private_ip(ns_rr_rdata(rr)))
                {
                    if (is_whitelisted(ns_rr_name(rr)))
                    {
                        // A reply can have multiple A records. inspect the remaining packet
                        continue;
                    }
                    else
                    {
                        return NF_DROP;
                    }
                }
            }
        }
    }

    return NF_ACCEPT;
}

static int process_ipv4_packet (struct nfq_data *tb)
{
    unsigned char *nfq_payload;
    int nfq_payload_len;
    int dns_proto_start = 0;
    int verdict = NF_ACCEPT;

    nfq_payload_len = nfq_get_payload(tb, &nfq_payload);
    if (nfq_payload_len >= 0)
    {
        struct iphdr *ip_header = (struct iphdr *)(nfq_payload);

        // If the ip header is more than nfq payload then it is a malformed packet. so drop it.
        if ((sizeof(struct iphdr) > nfq_payload_len) || ntohs(ip_header->tot_len) > nfq_payload_len)
        {
            return NF_DROP;
        }

        if (ip_header->protocol == IPPROTO_UDP)
        {
            if ((ip_header->ihl * 4 + sizeof(struct udphdr)) > ntohs(ip_header->tot_len))
            {
                return NF_DROP;
            }

            struct udphdr *udp_header = (struct udphdr *)&nfq_payload[ip_header->ihl * 4];
            if ((ip_header->ihl * 4 + ntohs(udp_header->len)) > ntohs(ip_header->tot_len))
            {
                return NF_DROP;
            }
            if (sizeof(struct udphdr) > ntohs(udp_header->len))
            {
                return NF_DROP;
            }
            dns_proto_start = ip_header->ihl * 4 + sizeof(struct udphdr);
            verdict = parse_dns_response(&nfq_payload[dns_proto_start], ntohs(udp_header->len) - sizeof(struct udphdr));
        }
        else
        {
            if ((ip_header->ihl * 4 + sizeof(struct tcphdr)) > nfq_payload_len)
            {
                return NF_DROP;
            }

            struct tcphdr *tcp_header = (struct tcphdr *)(&nfq_payload[ip_header->ihl * 4]);
            int tcp_payload_len = nfq_payload_len - (tcp_header->doff * 4) - (ip_header->ihl * 4);
            // Just send tcp packets which has payload
            if (tcp_payload_len > 0)
            {
                dns_proto_start = (ip_header->ihl * 4) + (tcp_header->doff * 4);
                // tcp DNS header has a length field which is 2 bytes
                dns_proto_start = dns_proto_start + 2;
                if (dns_proto_start > ntohs(ip_header->tot_len))
                {
                    return NF_DROP;
                }

                verdict = parse_dns_response(&nfq_payload[dns_proto_start], ntohs(ip_header->tot_len) - dns_proto_start);
            }
        }
    }

    return verdict;
}

static int ipv6_ext_hdr (uint8_t nexthdr)
{
    /*
     * find out if nexthdr is an extension header or a protocol
     */
    return (nexthdr == IPPROTO_HOPOPTS) ||
           (nexthdr == IPPROTO_ROUTING) ||
           (nexthdr == IPPROTO_FRAGMENT) ||
           (nexthdr == IPPROTO_AH) ||
           (nexthdr == IPPROTO_NONE) ||
           (nexthdr == IPPROTO_DSTOPTS);
}

static int ipv6_skip_exthdr (unsigned char *nfq_payload, int nfq_payload_len, int start, uint8_t *nexthdrp, __be16 *frag_offp)
{
    uint8_t nexthdr = *nexthdrp;
    *frag_offp = 0;

    while (ipv6_ext_hdr(nexthdr))
    {
        struct ipv6_opt_hdr *hp;
        int hdrlen;

        if (start + sizeof(struct ipv6_opt_hdr) > nfq_payload_len)
        {
            return -1;
        }

        hp = (struct ipv6_opt_hdr *)&nfq_payload[start];

        if (nexthdr == IPPROTO_NONE)
        {
            *nexthdrp = nexthdr;
            return -1;
        }

        if (start > nfq_payload_len)
        {
            return -1;
        }

        if (nexthdr == IPPROTO_FRAGMENT)
        {
            struct frag_hdr *frag;

            if (start + sizeof(struct frag_hdr) > nfq_payload_len)
            {
                return -1;
            }

            frag = (struct frag_hdr *)&nfq_payload[start];
            *frag_offp = frag->frag_off;
            if (ntohs(frag->frag_off) & ~0x7)
            {
                break;
            }
            hdrlen = 8;
        }
        else if (nexthdr == IPPROTO_AH)
        {
            hdrlen = ipv6_authlen(hp);
        }
        else
        {
            hdrlen = ipv6_optlen(hp);
        }

        nexthdr = hp->nexthdr;
        start += hdrlen;
    }

    *nexthdrp = nexthdr;

    return start;
}

static int process_ipv6_packet (struct nfq_data *tb)
{
    unsigned char *nfq_payload;
    int nfq_payload_len;
    int dns_proto_start = 0;
    int l4_proto_start = 0;
    struct ipv6hdr *ip_header = NULL;
    int verdict = NF_ACCEPT;

    nfq_payload_len = nfq_get_payload(tb, &nfq_payload);
    if (nfq_payload_len >= 0)
    {
        /*
            Need to validate whether we have at least a minimal IP header size in buffer before accessing any IP header element.
            Also unlike IPv4, IPv6 payload_len field doesn't include the IPv6 header.
        */
        ip_header = (struct ipv6hdr *)(nfq_payload);
        if ((sizeof(struct ipv6hdr) > nfq_payload_len) || ((sizeof(struct ipv6hdr) + ntohs(ip_header->payload_len)) > nfq_payload_len))
        {
            return NF_DROP;
        }

        /* IPv6 header can have extension headers. Need to skip all
            extension headers and parse L4 protocol data */
        uint8_t l4_hdr = ip_header->nexthdr;
        __be16 frag_off = 0;
        l4_proto_start = ipv6_skip_exthdr(nfq_payload, nfq_payload_len, sizeof(struct ipv6hdr), &l4_hdr, &frag_off);

        if (l4_proto_start > 0 && (l4_hdr == IPPROTO_TCP || l4_hdr == IPPROTO_UDP))
        {
            if (l4_hdr == IPPROTO_UDP)
            {
                if ((l4_proto_start + sizeof(struct udphdr)) > (sizeof(struct ipv6hdr) + ntohs(ip_header->payload_len)))
                {
                    return NF_DROP;
                }

                struct udphdr *udp_header = (struct udphdr *)&nfq_payload[l4_proto_start];
                if ((l4_proto_start + ntohs(udp_header->len)) > (sizeof(struct ipv6hdr) + ntohs(ip_header->payload_len)))
                {
                    return NF_DROP;
                }
                if (sizeof(struct udphdr) > ntohs(udp_header->len))
                {
                    return NF_DROP;
                }
                dns_proto_start = l4_proto_start + sizeof(struct udphdr);
                verdict = parse_dns_response(&nfq_payload[dns_proto_start], ntohs(udp_header->len) - sizeof(struct udphdr));
            }
            else if (l4_hdr == IPPROTO_TCP)
            {
                if ((l4_proto_start + sizeof(struct tcphdr)) > nfq_payload_len)
                {
                    return NF_DROP;
                }

                struct tcphdr *tcp_header = (struct tcphdr *)(&nfq_payload[l4_proto_start]);
                int tcp_payload_len = nfq_payload_len - (l4_proto_start + (tcp_header->doff * 4));
                if (tcp_payload_len > 0)
                {
                    dns_proto_start = l4_proto_start + (tcp_header->doff * 4);
                    // tcp DNS header has a length field which is 2 bytes
                    dns_proto_start = dns_proto_start + 2;
                    if (dns_proto_start > (sizeof(struct ipv6hdr) + ntohs(ip_header->payload_len)))
                    {
                        return NF_DROP;
                    }

                    verdict = parse_dns_response(&nfq_payload[dns_proto_start], sizeof(struct ipv6hdr) + ntohs(ip_header->payload_len) - dns_proto_start);
                }
            }
        }
    }

    return verdict;
}

static int dnsv4_filter (struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data)
{
    u_int32_t id = 0;
    int verdict = NF_ACCEPT;
    struct nfqnl_msg_packet_hdr *ph;

    verdict = process_ipv4_packet(nfa);
    ph = nfq_get_msg_packet_hdr(nfa);
    if (ph)
    {
        id = ntohl(ph->packet_id);
    }

    return nfq_set_verdict(qh, id, verdict, 0, NULL);
}

static int dnsv6_filter (struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data)
{
    u_int32_t id = 0;
    int verdict = NF_ACCEPT;
    struct nfqnl_msg_packet_hdr *ph;

    verdict = process_ipv6_packet(nfa);
    ph = nfq_get_msg_packet_hdr(nfa);
    id = ntohl(ph->packet_id);

    return nfq_set_verdict(qh, id, verdict, 0, NULL);
}

static int prepare_ipv4_nf_queue (struct nfq_handle **ipv4_handle, struct nfq_q_handle **ipv4_queue)
{
    *ipv4_handle = nfq_open();
    if (!*ipv4_handle)
    {
        fprintf(stderr, "error during IPv6 nfq_open()\n");
        return -1;
    }
    /*
        Don't call nfq_unbind_pf(). It detaches other programs/sockets from AF_INET, too!
        we use another AF_INET nfqueue application "trigger"
        if (nfq_unbind_pf(h, AF_INET) < 0)
        {
            fprintf(stderr, "error during nfq_unbind_pf()\n");
            return -1;
        }
    */
    if (nfq_bind_pf(*ipv4_handle, AF_INET) < 0)
    {
        fprintf(stderr, "error during IPv4 nfq_bind_pf()\n");
        return -1;
    }

    *ipv4_queue = nfq_create_queue(*ipv4_handle, DNSv4_FILTER_QUEUE, &dnsv4_filter, NULL);
    if (!*ipv4_queue)
    {
        fprintf(stderr, "error during nfq_create_queue()\n");
        return -1;
    }

    if (nfq_set_mode(*ipv4_queue, NFQNL_COPY_PACKET, 0xffff) < 0)
    {
        fprintf(stderr, "can't set IPv4 packet_copy mode\n");
        return -1;
    }

    return 0;
}

static int prepare_ipv6_nf_queue (struct nfq_handle **ipv6_handle, struct nfq_q_handle **ipv6_queue)
{
    *ipv6_handle = nfq_open();
    if (!*ipv6_handle)
    {
        fprintf(stderr, "error during IPv6 nfq_open()\n");
        return -1;
    }

    if (nfq_unbind_pf(*ipv6_handle, AF_INET6) < 0)
    {
        fprintf(stderr, "error during IPv6 nfq_unbind_pf()\n");
        return -1;
    }
    if (nfq_bind_pf(*ipv6_handle, AF_INET6) < 0)
    {
        fprintf(stderr, "error during IPv6 nfq_bind_pf()\n");
        return -1;
    }

    *ipv6_queue = nfq_create_queue(*ipv6_handle, DNSv6_FILTER_QUEUE, &dnsv6_filter, NULL);
    if (!*ipv6_queue)
    {
        fprintf(stderr, "error during IPv6 nfq_create_queue()\n");
        return -1;
    }

    if (nfq_set_mode(*ipv6_queue, NFQNL_COPY_PACKET, 0xffff) < 0)
    {
        fprintf(stderr, "can't set IPv6 packet_copy mode\n");
        return -1;
    }

    return 0;
}

static int check_existing_instance (void)
{
    int fd;

    fd = open("/var/run/dns-filter.pid", O_CREAT | O_RDWR, 0666);

    if (fd == -1)
    {
        fprintf(stderr, "dns_filter: Failed to open lock file\n");
        return 0;
    }

    if (flock(fd, LOCK_EX | LOCK_NB) != 0)
    {
        fprintf(stderr, "dns_filter: Failed to acquire lock file\n");
        close(fd);
        return 1;
    }

    /* OK to proceed (lock will be released and file descriptor will be closed on exit) */
    return 0;
}

static void daemonize (void)
{
    pid_t pid;
    FILE *pid_file;

    if ((pid = fork()) < 0)
    {
        return;
    }
    else if (pid != 0)
    {
        // exit the parent process
        exit(0);
    }
    else
    {
        /* Abort if another instance of dns_filter is already running */
        if (check_existing_instance())
        {
            exit(0);
        }
        // write the pid to a file. easy to kill later
        pid_file = fopen("/var/run/dns-filter.pid", "w");
        if (pid_file)
        {
            fprintf(pid_file, "%d", getpid());
            fclose(pid_file);
        }
    }

    setsid();   // become session leader
    chdir("/"); // change working directory
    umask(0);   // clear file mode creation mask

    close(STDIN_FILENO);
#ifndef DEBUG
    close(STDOUT_FILENO);
    close(STDERR_FILENO);
#endif
}

int main (int argc, char **argv)
{
    char buf[4096];
    int recv_len;
    int ipv4_fd, ipv6_fd;
    struct nfq_handle *ipv4_handle, *ipv6_handle;
    struct nfq_q_handle *ipv4_queue, *ipv6_queue;
    struct pollfd poll_fds[2];
    int ret;

    daemonize();

    if (load_whitelisted_urls() == 0)
    {
        fprintf(stdout, "dns-rebind protection is disabled\b");
        exit(0);
    }

#ifdef DEBUG
    print_whitelist_urls();
#endif

    if (prepare_ipv4_nf_queue(&ipv4_handle, &ipv4_queue) == -1)
    {
        return 1;
    }

    if (prepare_ipv6_nf_queue(&ipv6_handle, &ipv6_queue) == -1)
    {
        return 1;
    }

    ipv4_fd = nfq_fd(ipv4_handle);
    ipv6_fd = nfq_fd(ipv6_handle);

    poll_fds[0].fd = ipv4_fd;
    poll_fds[0].events = POLLIN;
    poll_fds[1].fd = ipv6_fd;
    poll_fds[1].events = POLLIN;

    while ((ret = poll(poll_fds, 2, -1)))
    {
        if (ret == -1)
        {
            fprintf(stderr, "poll error : %s", strerror(errno));
            continue;
        }

        if (poll_fds[0].revents & POLLIN)
        {
            recv_len = recv(ipv4_fd, buf, sizeof(buf), 0);
            nfq_handle_packet(ipv4_handle, buf, recv_len);
        }

        if (poll_fds[1].revents & POLLIN)
        {
            recv_len = recv(ipv6_fd, buf, sizeof(buf), 0);
            nfq_handle_packet(ipv6_handle, buf, recv_len);
        }
    }

    nfq_destroy_queue(ipv4_queue);
    nfq_destroy_queue(ipv6_queue);

    nfq_close(ipv4_handle);
    nfq_close(ipv6_handle);

    free_whitelist_urls();

    return 0;
}
