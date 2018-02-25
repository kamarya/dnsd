/*
 * Copyright (C) 2016  Behrooz Kamary Aliabadi

 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.

 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef _DNSSSEC_H_
#define _DNSSSEC_H_

#define PIDFILE             "/var/run/dnsd.pid"

#define LICENSE             "DNSd  Copyright (C) 2016  Behrooz Kamary Aliabadi.\n"\
                            "This program comes with ABSOLUTELY NO WARRANTY. \n"\
                            "You should have received a copy of the GNU General Public License\n"\
                            "along with this program. If not, see <http://www.gnu.org/licenses/>."
// Resource Record (RR)

#define DNS_QR_RESPONSE     0x8000
#define DNS_AUTH_ANS        0x0400
#define DNS_TRUNCATED       0x0200
#define DNS_USE_RECURSION   0x0100
#define DNS_RECURSION_AVAIL 0x0080

#define DNS_FORMAT_ERROR    0x0001
#define DNS_SERVER_FAILURE  0x0002
#define DNS_NAME_ERROR      0x0003
#define DNS_NOT_IMPLEMENTED 0x0004
#define DNS_REFUSED         0x0005
#define DNS_ERROR_MASK      0x000F

#define DNS_INET_ADDR       0x0001

#define DNS_A_RECORD        0x0001
#define DNS_NS_RECORD       0x0002
#define DNS_CNAME_RECORD    0x0005
#define DNS_SOA_RECORD      0x0006
#define DNS_MX_RECORD       0x000F
#define DNS_OPT_RECORD      0x0029
#define DNS_AAA_RECORD      0x001C

#define MAX_DOMAIN_LENGTH       255
#define MAX_SUBDOMAIN_LENGTH    63

#define JSON_NO_ANSWER          -1
#define JSON_NULL               -2

#define TRUE                    1
#define FALSE                   0

#define OPT_CONIG_FILE_LEN      256
#define OPT_HTTPS_PROXY         "https_proxy"
#define OPT_HTTPS_PROXY_LEN     64
#define OPT_SERVER_URL          "server_url"
#define OPT_SERVER_URL_LEN      64
#define OPT_SERVER_IP           "server_ip_list"
#define OPT_SERVER_IP_LEN       512
#define OPT_ENABLE_EDNS         "enable_edns_ecs"
#define OPT_DEFAULT_URL         "https://dns.google.com"
#define OPT_SERVICE_PORT        "service_port"
#define OPT_ENABLE_TRUE         "true"
#define OPT_ENABLE_FALSE        "false"

#define MX_PREF_MAX_LEN         5
#define DNS_ANSWER_LEN          12

#define LOG_LEVEL               LEV_NO_DEV_LOG
#define DEBUG_ENABLE            0
#define DEBUG_AUDIT_ENABLE      0
#define BUFFER_SIZE             102400
#define DNS_MAX_SIZE            512
#define EDNS_MAX_SIZE           4096
#define DNS_SERVER_PORT         53
#define DNS_SERVER_TIMEOUT      10

#define UNUSED(x) (void)(x)

struct func_options
{
    char      config_file[OPT_CONIG_FILE_LEN];
    char      https_proxy[OPT_HTTPS_PROXY_LEN];
    char      server_url[OPT_SERVER_URL_LEN];
    char      server_ip_list[OPT_SERVER_IP_LEN];
    uint16_t  server_timeout;
    uint16_t  service_port;
    uint8_t   enable_debug;
    uint8_t   enable_edns;
};

struct dns_header
{
    uint16_t id;
    uint16_t flags;
    uint16_t q_count;
    uint16_t ans_count;
    uint16_t auth_count;
    uint16_t add_count;
};

struct dns_header_detail
{
    uint16_t id;                   // identification number

    uint8_t rd :1;                 // recursion desired
    uint8_t tc :1;                 // truncated message
    uint8_t aa :1;                 // authoritive answer
    uint8_t opcode :4;             // purpose of message
    uint8_t qr :1;                 // query/response flag

    uint8_t rcode :4;              // response code
    uint8_t cd :1;                 // checking disabled
    uint8_t ad :1;                 // authenticated data
    uint8_t z :1;                  // reserved
    uint8_t ra :1;                 // recursion available

    uint16_t q_count;              // number of question entries
    uint16_t ans_count;            // number of answer entries
    uint16_t auth_count;           // number of authority entries
    uint16_t add_count;            // number of resource entries
};

struct dns_question
{
    uint16_t qtype;
    uint16_t qclass;
};

struct dns_query
{
    char*                      names;
    struct dns_header_detail*  header;
    struct dns_question*       qstn;
    int                        length;
};

#pragma pack(push)  /* push current alignment to stack */
#pragma pack(2)
struct dns_answer
{
    uint16_t  name;
    uint16_t  atype;
    uint16_t  aclass;
    uint32_t  ttl;
    uint16_t  rdlen;
};

struct dns_soa
{
    char*       mname;
    char*       rname;
    uint32_t    serial;
    uint32_t    refresh;
    uint32_t    retry;
    uint32_t    expire;
    uint32_t    ttl;
};

#pragma pack(pop)

/*      functions         */


size_t  json_to_answer(char*, struct dns_header_detail*, size_t);

void    format(char*, size_t);

void    copy(char* const, const char*, size_t);

char*   getTypeString(uint16_t, int);

void    handle_signal(int);

void    usage(char*);

int     parse_options();

int     create_pidfile();

int     remove_spaces(char*);

void    hexdump(char*, void*, int);

#endif /* DNSSL_H */

/*
   Notes
   -----------------------------------------------------
   TYPE            value and meaning
   A               1 a host address IPv4
   NS              2 an authoritative name server
   MD              3 a mail destination (Obsolete - use MX)
   MF              4 a mail forwarder (Obsolete - use MX)
   CNAME           5 the canonical name for an alias
   SOA             6 marks the start of a zone of authority
   MB              7 a mailbox domain name (EXPERIMENTAL)
   MG              8 a mail group member (EXPERIMENTAL)
   MR              9 a mail rename domain name (EXPERIMENTAL)
   NULL            10 a null RR (EXPERIMENTAL)
   WKS             11 a well known service description
   PTR             12 a domain name pointer
   HINFO           13 host information
   MINFO           14 mailbox or mail list information
   MX              15 mail exchange
   TXT             16 text strings
   AAAA            28 a host address IPv6

   -----------------------------------------------------
   Class           value and meaning
   IN              1 the Internet
   CS              2 the CSNET class (Obsolete - used only for examples in some obsolete RFCs)
   CH              3 the CHAOS class
   HS              4 Hesiod [Dyer 87]
*/
