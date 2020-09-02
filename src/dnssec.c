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
#define _GNU_SOURCE
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <signal.h>
#include <getopt.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <curl/curl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <poll.h>
#include <sys/stat.h>   // umask()
#include <dnssec.h>
#include <log.h>


sig_atomic_t                        running = 0;
static int                          sock;
static int                          pidfp;
static char*                        buffer;
static char*                        data;
static char*                        json;
static struct sockaddr_storage      peer_add;
static socklen_t                    peer_add_len;
static size_t                       total_read;
static struct func_options          options;

static void __attribute__ ((unused)) start_daemon()
{
    pid_t process_id = 0;
    pid_t sid        = 0;
    process_id = fork();
    if (process_id < 0)
    {
        fprintf(stderr, "fork() failed.\n");
        exit(EXIT_FAILURE);
    }

    if (process_id > 0)
    {
        fprintf(stdout, "daemon process id is %d. \n", process_id);
        exit(EXIT_SUCCESS);
    }

    umask(0);
    sid = setsid();
    if(sid < 0)
    {
        fprintf(stderr, "setsid() failed.\n");
        exit(EXIT_FAILURE);
    }

    chdir("/");

    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);

    if (open("/dev/null", O_RDONLY) == -1)
    {
        fprintf(stderr, "open(stdin)");
        exit(EXIT_FAILURE);
    }
    if (open("/dev/null", O_WRONLY) == -1)
    {
        fprintf(stderr, "open(stdout)");
        exit(EXIT_FAILURE);
    }
    if (open("/dev/null", O_RDWR) == -1)
    {
        fprintf(stderr, "open(stderr)");
        exit(EXIT_FAILURE);
    }

}

#if DEBUG_AUDIT_ENABLE
void audit_pid(const char* port)
{
    int   failed = 1;
    FILE* fp;
    char  buffer[2048];

    fp = popen("netstat -npau 2>&1", "r");
    if (fp == NULL)
    {
        LOG_DEBUG("failed to run 'netstat'");
        return;
    }


    while (fgets(buffer, sizeof(buffer), fp) != NULL)
    {
        char * curLine = buffer;
        while(curLine)
        {
            char * nextLine = strchr(curLine, '\n');
            if (nextLine) *nextLine = '\0';
            if (strstr(curLine, "udp") && strstr(curLine, port))
            {
                LOG_DEBUG("%s", curLine);
                failed = 0;
            }
            if (nextLine) *nextLine = '\n';
            curLine = nextLine ? (nextLine + 1) : NULL;
        }
    }

    if (failed) LOG_DEBUG("PID audit failed.");

    pclose(fp);
}
#endif

int ipoll()
{
    struct pollfd fds;
    fds.fd      = sock;
    fds.events  = POLLIN;

    return poll(&fds, 1, 1000);
}

size_t body_callback (void* contents, size_t size, size_t nmemb, void* userp)
{
    size_t chunk = size * nmemb;
    strncpy(json + total_read, contents, chunk);

    total_read += chunk;
    LOG_DEBUG("read totaly %zu bytes.", total_read);

    return chunk;
}

int https_query (struct dns_query* query)
{

    CURL*     curl;
    CURLcode  res;

    char query_str[3 * (MAX_DOMAIN_LENGTH + MAX_SUBDOMAIN_LENGTH)] = {0};

    if (options.server_url[0])
    {
        strncpy(query_str, options.server_url, OPT_SERVER_URL_LEN);
    }
    else
    {
        strncpy(query_str, OPT_DEFAULT_URL, OPT_SERVER_URL_LEN);
    }

    strcat(query_str, "/resolve?name=");
    strcat(query_str, query->names);
    strcat(query_str, "&type=");
    strcat(query_str, getTypeString(ntohs(query->qstn->qtype), FALSE));

    if (!options.enable_edns)
        strcat(query_str, "&edns_client_subnet=0.0.0.0/0");

    LOG_DEBUG("query : %s", query_str);

    struct curl_slist* headers = NULL;

    headers = curl_slist_append(headers, "Accept-Encoding : deflate, sdch, br");
    headers = curl_slist_append(headers, "Accept : txt/html, application/xml;q=0.8");
    headers = curl_slist_append(headers, "Accept-Language : en-US,en;q=0.8");
    headers = curl_slist_append(headers, "Cache-Control : max-age=0");

    curl = curl_easy_init();
    if(curl && strlen(getTypeString(ntohs(query->qstn->qtype), FALSE)))
    {

        curl_easy_setopt(curl, CURLOPT_URL, query_str);
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

        // do not check the SSL certificate authenticity
        //curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0);
        //curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0);

        // failed to work with libcurl/7.65.3 and HTTP/2.0
        curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_1);
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, options.server_timeout);

        if (options.https_proxy[0])
        {
            curl_easy_setopt(curl, CURLOPT_PROXY, options.https_proxy);
        }

        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, body_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)query);

        total_read = 0;

        res = curl_easy_perform(curl);

        curl_easy_cleanup(curl);
        curl_slist_free_all(headers);
        LOG_DEBUG("curl_easy_perform() has returned.");

        if (res != CURLE_OK)
        {
            LOG_ERROR("curl_easy_perform() failed: %s", curl_easy_strerror(res));
            return EXIT_FAILURE;
        }
        return EXIT_SUCCESS;
    }

    curl_global_cleanup();

    return EXIT_FAILURE;
}

int server()
{

    struct sockaddr_in        server_add;
    buffer        = malloc(BUFFER_SIZE);
    json          = malloc(BUFFER_SIZE);
    data          = malloc(MAX_DOMAIN_LENGTH);
    char*  names  = malloc(MAX_DOMAIN_LENGTH);

    if (buffer == NULL || json == NULL ||
      data == NULL || names == NULL) return EXIT_FAILURE;

    memset(buffer, 0x00, BUFFER_SIZE);
    memset(json,   0x00, BUFFER_SIZE);
    memset(data,   0x00, MAX_DOMAIN_LENGTH);
    memset(names,  0x00, MAX_DOMAIN_LENGTH);

    server_add.sin_family      = AF_INET;
    server_add.sin_port        = htons(options.service_port);
    server_add.sin_addr.s_addr = htonl(INADDR_ANY);

    if (options.service_ip[0] != '\0')
    {
        if (inet_pton(AF_INET, options.service_ip, &(server_add.sin_addr)) == 1)
        {
            LOG_INFO("service ip (%s)", options.service_ip);
        }
        else
        {
            LOG_ERROR("invalid service ip (%s)", options.service_ip);
        }
    }

    LOG_DEBUG("service port (%d)", options.service_port);

    sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0)
    {
        perror("socket()");
        return EXIT_FAILURE;
    }

    if (bind(sock, (struct sockaddr*) &server_add, sizeof(server_add)))
    {
        perror("bind()");
        return EXIT_FAILURE;
    }


    while (running)
    {
        int rp    = ipoll();

        if (rp == 0) continue;
        else if (rp < 0)
        {
            if (running)
            {
                LOG_ERROR("socket poll failed.");
                running = 0;
            }
            break;
        }

        int nread = recvfrom(sock, buffer, BUFFER_SIZE, MSG_WAITALL, (struct sockaddr*)&peer_add, &peer_add_len);

        if (nread < 0) continue;

        char host[NI_MAXHOST], service[NI_MAXSERV], ip[INET6_ADDRSTRLEN];

        int res = getnameinfo((struct sockaddr *) &peer_add, peer_add_len, host, NI_MAXHOST, service, NI_MAXSERV, NI_NUMERICSERV);

        if (peer_add.ss_family == AF_INET)
        {
            struct sockaddr_in *p = (struct sockaddr_in *) &peer_add;
            inet_ntop(peer_add.ss_family, &(p->sin_addr), ip, sizeof(ip));
        }
        else if (peer_add.ss_family == AF_INET6)
        {
            struct sockaddr_in6 *p = (struct sockaddr_in6 *) &peer_add;
            inet_ntop(peer_add.ss_family, &(p->sin6_addr), ip, sizeof(ip));
        }

        if (res == 0)
            LOG_DEBUG("received %ld bytes from [%s] [%s:%s]", (long) nread, host, ip, service);
        else
            LOG_ERROR("getnameinfo() : %s", gai_strerror(res));
#if DEBUG_AUDIT_ENABLE
        audit_pid(service);
#endif

        struct dns_header_detail* header  = (struct dns_header_detail*)buffer;

        LOG_DEBUG("number of questions   (%u)", ntohs(header->q_count));
        LOG_DEBUG("number of answers     (%u)", ntohs(header->ans_count));
        LOG_DEBUG("number of authorities (%u)", ntohs(header->auth_count));
        LOG_DEBUG("number of addtionals  (%u)", ntohs(header->add_count));


        const char* dn = buffer + sizeof(struct dns_header);

        size_t dnlen = 0;
        for (;(dnlen < MAX_DOMAIN_LENGTH && *dn); dnlen++)
        {
            names[dnlen] = *dn++;
            if (names[dnlen] < 0x30) names[dnlen] = '.';
        }

        struct dns_query  query;
        query.header = header;
        query.qstn   = (struct dns_question *)(buffer + sizeof(struct dns_header) + dnlen + 1);
        query.length = sizeof(struct dns_question) + sizeof(struct dns_header) + dnlen + 1;

        query.names  = names;
        LOG_DEBUG("Domain Name (%s) length (%zd)", query.names, dnlen);
        query.names  += (names[0] == '.'?1:0);

        memset(json,   0x00, BUFFER_SIZE);

        size_t  answer_length   = 0;
        size_t  max_len         = 512;

        if (header->add_count &&
            *(buffer + query.length) == 0 &&
            *(uint16_t*)(buffer + query.length + 1) == htons(41))
        {
            max_len = ntohs(*(uint16_t*)(buffer + query.length + 3));
            LOG_DEBUG("client supports EDNS0 OPT packet length (%zd).", max_len);
        }

        header->qr        =   1; // this is a response
        header->rcode     =   0;
        header->ans_count =   0;
        header->add_count =   0; // if needed we set EDNS0 OPT later


        // TODO support multiple questions; however it seems others don't.
        if (ntohs(header->q_count) == 1)
        {
            if (https_query(&query) == EXIT_SUCCESS)
            {
                char* answer = (char *)(buffer + sizeof(struct dns_question) + sizeof(struct dns_header) + dnlen + 1);
                answer_length = json_to_answer(answer, header, max_len);
            }
        }

        if (!answer_length || answer_length == JSON_NO_ANSWER)
        {
            header->rcode = DNS_SERVER_FAILURE;
            answer_length = 0; // the returned value may be less than zero to indicate the error code.
            LOG_DEBUG ("(%x) DNS SERVER FAILURE", header->id);
        }


        if (sendto(sock, buffer, query.length + answer_length, 0, (struct sockaddr *) &peer_add, peer_add_len) != (query.length + answer_length))
        {
            LOG_ERROR("(%x) error sending response.", header->id);
        }
        else
        {
            LOG_DEBUG("(%x) %u bytes has been sent to %s:%s.", header->id, (unsigned int)(query.length + answer_length), ip, service);
        }

        memset(buffer, 0x00, nread);
        memset(names,  0x00, dnlen);
    }

    free(buffer);
    free(data);
    free(names);
    free(json);
    close(sock);

    return EXIT_SUCCESS;
}

int main(int argc, char **argv)
{

    memset(&options, 0x00, sizeof(struct func_options));

    extern char* optarg;
    extern int   optind;
    int          c;


    static struct option long_options[] =
    {
        {"debug",      no_argument,             0, 'D'},
        {"help",       no_argument,             0, 'h'},
        {"config",     required_argument,       0, 'f'},
        {0, 0, 0, 0}
    };

    int option_index = 0;

    while ((c = getopt_long(argc, argv, "hDf:", long_options, &option_index)) != -1)
    {
        switch (c)
        {
        case 'f':
            strncpy(options.config_file, optarg, OPT_CONIG_FILE_LEN);
            break;
        case 'D':
            options.enable_debug = 0xFF;
            break;
        case 'h':
            usage(argv[0]);
            return EXIT_FAILURE;
        default:
            usage(argv[0]);
            return EXIT_FAILURE;
        }
    }

    if (options.config_file[0] != '\0' && parse_options() == EXIT_FAILURE)
    {
        LOG_ERROR("parsing the configuration file has been failed.");
    }

    if (options.service_port == 0) options.service_port = DNS_SERVER_PORT;
    if (options.server_timeout == 0) options.server_timeout = DNS_SERVER_TIMEOUT;

    peer_add_len  = sizeof(struct sockaddr_storage);
    running       = 1;

    // signal handler initialization
    sigset_t sigset;
    sigemptyset(&sigset);
    sigaddset(&sigset, SIGCHLD);
    sigaddset(&sigset, SIGTSTP);
    sigaddset(&sigset, SIGTTOU);
    sigaddset(&sigset, SIGTTIN);
    sigprocmask(SIG_BLOCK, &sigset, NULL);

    struct sigaction sa;
    memset (&sa, '\0', sizeof(sa));
    sa.sa_handler = handle_signal;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;

    sigaction(SIGHUP,   &sa, NULL);
    sigaction(SIGUSR1,  &sa, NULL);
    sigaction(SIGINT,   &sa, NULL);
    sigaction(SIGTERM,  &sa, NULL);
    signal(SIGPIPE, SIG_IGN);

    if (options.enable_debug != 0xFF)
    {
        start_daemon();
        if (create_pidfile() == EXIT_FAILURE) return EXIT_FAILURE;
    }

    if (server() == EXIT_FAILURE)
        LOG_ERROR ("udp server failed to start.");

    LOG_DEBUG ("Process Terminated.");

    return EXIT_SUCCESS;
}


size_t json_to_answer(char* answer, struct dns_header_detail* header, size_t max_len)
{
    size_t      padd    = 0;
    char*       orig    = answer;
    memset(data,   0x00, MAX_DOMAIN_LENGTH);

    char* rdata;

    uint16_t type      = 0;
    char     ctype[10] = "";

    uint32_t ttl       = 0;
    char     cttl[10]  = "";

    if (orig == NULL) return JSON_NULL;

    char* token = strstr(json, "Answer");

    if (token == NULL)
    {
        LOG_DEBUG("no 'Answer' was found");
        return JSON_NO_ANSWER;
    }

    uint16_t num_answers        = 0;
    uint16_t num_additionals    = 0;

    while ((token = strstr(token, "name")))
    {

        token        = strstr(token, "type");
        char*   beg  = strchr(token,   ':') + 2;
        size_t  len  = strchr(beg,   ',') - beg;

        memset(ctype, 0x00, 10);
        strncpy(ctype, beg, len);
        type         = atoi(ctype);

        if  (type != DNS_A_RECORD &&
             type != DNS_AAAA_RECORD &&
             type != DNS_CNAME_RECORD &&
             type != DNS_NS_RECORD &&
             type != DNS_MX_RECORD)
        {   // other types are not supported
            continue;
        }
        else
        {
            token   =  beg + len;
        }

        LOG_DEBUG ("(%x) Type : %d (%s)", header->id, type, getTypeString(type, TRUE));

        token       = strstr(token, "TTL");
        beg         = strchr(beg,   ':') + 2;
        len         = strchr(beg,   ',') - beg;

        memset(cttl, 0x00, 10);
        strncpy(cttl, beg, len);
        ttl         = atoi(cttl);
        token       = beg + len;

        LOG_DEBUG ("(%x) TTL : %d", header->id, ttl);

        size_t offset = (type == DNS_MX_RECORD)?0:1;

        token       = strstr(token, "data");
        beg         = strchr(token,   ':');
        beg         = strchr(beg,   '\"') + 1;
        len         = strchr(beg, '\"') - beg;
        strncpy(data + offset, beg, len);
        token       = beg + len;

        LOG_DEBUG("(%x) data : %s", header->id, data + offset);


        struct dns_answer* ans = (struct dns_answer *)answer;
        ans->name        =  htons(0xc00c);
        ans->atype       =  htons(type);
        ans->aclass      =  htons(0x0001);
        ans->ttl         =  htonl(ttl);
        ans->rdlen  =  0;

        if (type == DNS_A_RECORD)
        {
            ans->rdlen  =  htons(4);
            rdata            =  (char *)(answer + DNS_ANSWER_LEN);
            inet_pton(AF_INET, data + offset, rdata);

            // 4 x 3 + 3 = 15 bytes to be erased
            memset(data,   0x00, INET_ADDRSTRLEN);

            padd = 4 + DNS_ANSWER_LEN;
        }
        else if (type == DNS_AAAA_RECORD)
        {
            ans->rdlen  =  htons(INET_ADDRSTRLEN);
            rdata       =  (char *)(answer + DNS_ANSWER_LEN);
            inet_pton(AF_INET6, data + offset, rdata);

            // maximum string size of an IPv6 address is 45 bytes
            memset(data,   0x00, INET6_ADDRSTRLEN);

            padd = INET_ADDRSTRLEN + DNS_ANSWER_LEN;
        }
        else if (type == DNS_CNAME_RECORD ||
                 type == DNS_NS_RECORD)
        {
            uint8_t     lent  = 0;
            size_t      dot   = 0;

            for (unsigned int i = offset; i < len + offset; ++i)
            {
                if (data[i] != '.') lent++;
                else
                {
                    data[dot] = lent;
                    dot = (uint8_t) i;
                    lent = 0;
                }
            }


            data[len] = 0x00;
            ans->rdlen  =  htons(len + offset);
            rdata            =  (char *)(answer + DNS_ANSWER_LEN);

            memcpy(rdata, data, len + offset);

            memset(data,   0x00, len + offset);
            padd = len + offset + DNS_ANSWER_LEN;

        }
        else if (type == DNS_MX_RECORD)
        {

            rdata             =  (char *)(answer + DNS_ANSWER_LEN);

            size_t      pref_len   = 0;
            while (data[pref_len] != ' ' && pref_len < MX_PREF_MAX_LEN) pref_len++;
            data[pref_len]         = '\0';
            uint16_t    pref       = atoi(data + offset);

            LOG_DEBUG("(%x) MX Preference : %d", header->id, pref);
            LOG_DEBUG("(%x) len [%zu] data [%s]", header->id, len, &data[pref_len + 1]);

            ans->rdlen  =  htons(len - pref_len + sizeof(pref));

            pref = htons(pref);
            memcpy(rdata, (void *)(&pref), sizeof(pref));

            format(data + pref_len, len - pref_len);

            copy(rdata + sizeof(pref), data + pref_len, len + pref_len);

            memset(data,   0x00, MAX_DOMAIN_LENGTH);
            padd = len + DNS_ANSWER_LEN - pref_len + sizeof(pref);
        }
        else
        {
            ans->rdlen  =  htons(len + offset);
            rdata       =  (char *)(answer + DNS_ANSWER_LEN);
            strncpy(rdata, data + offset, len + offset);
            memset(data,   0x00, len + offset);
            padd = len + DNS_ANSWER_LEN + offset;
        }

        if ((answer - orig + padd) > max_len) break;

        answer += padd;

        if ((answer - orig) < DNS_MAX_SIZE)
            num_answers++;
        else
            num_additionals++;
    }

    header->qr        = 1;
    header->ans_count = htons(num_answers);
    header->add_count = htons(num_additionals);

    return (answer - orig);
}


char* getTypeString(uint16_t type, int unknown)
{
    switch(type)
    {
    case DNS_AAAA_RECORD:
        return "AAAA";
        break;
    case DNS_A_RECORD:
        return "A";
        break;
    case DNS_CNAME_RECORD:
        return "CNAME";
        break;
    case DNS_SOA_RECORD:
        return "SOA";
        break;
    case DNS_NS_RECORD:
        return "NS";
        break;
    case DNS_MX_RECORD:
        return "MX";
        break;
    case DNS_OPT_RECORD:
        return "OPT";
        break;
    case 0xFF:
        return "ANY";
        break;
    default:
        return unknown?"UNKNOWN":"ANY";
        break;
    }

    return unknown?"UNKNOWN":"ANY";
}

void format(char* name, size_t length)
{

    uint8_t     lent  = 0;
    size_t      dot   = 0;

    for (unsigned int i = 1; i < length; ++i)
    {
        if (name[i] != '.') lent++;
        else
        {
            name[dot] = lent;
            dot = (uint8_t) i;
            lent = 0;
        }
    }


    name[length - 1] = '\0';
}

void hexdump (char *desc, void *addr, int len)
{
    int i;
    unsigned char buff[17];
    unsigned char *pc = (unsigned char*)addr;

    // Output description if given.
    if (desc != NULL)
        printf ("%s:\n", desc);

    if (len == 0) {
        printf("  ZERO LENGTH\n");
        return;
    }
    if (len < 0) {
        printf("  NEGATIVE LENGTH: %i\n",len);
        return;
    }

    // Process every byte in the data.
    for (i = 0; i < len; i++) {
        // Multiple of 16 means new line (with line offset).

        if ((i % 16) == 0) {
            // Just don't print ASCII for the zeroth line.
            if (i != 0)
                printf ("  %s\n", buff);

            // Output the offset.
            printf ("  %04x ", i);
        }

        // Now the hex code for the specific character.
        printf (" %02x", pc[i]);

        // And store a printable ASCII character for later.
        if ((pc[i] < 0x20) || (pc[i] > 0x7e))
            buff[i % 16] = '.';
        else
            buff[i % 16] = pc[i];
        buff[(i % 16) + 1] = '\0';
    }

    // Pad out last line if not exactly 16 characters.
    while ((i % 16) != 0) {
        printf ("   ");
        i++;
    }

    // And print the final ASCII bit.
    printf ("  %s\n", buff);
}


void copy(char* const dst,const char* src, size_t length)
{
    for (unsigned int indx = 0; indx < length; ++indx)
    {
        dst[indx] = src[indx];
    }
}

void handle_signal(int signal)
{
    switch (signal)
    {
    case SIGHUP:
    case SIGTERM:
    case SIGUSR1:
    case SIGINT:
        close(pidfp);
        running = 0;
    default:
        return;
    }
}

void usage(char* exec_name)
{
    fprintf(stderr, "\n"LICENSE"\n\n");
    fprintf(stderr, "Usage : %s [-D] [-f CONFIG_FILE]\n", exec_name);
    fprintf(stderr, "        %s [-h|--help] Display this information.\n", exec_name);
}

int parse_options()
{
    FILE    *fp     = NULL;
    char    *line   = NULL;
    size_t  len     = 0;
    ssize_t read    = 0;

    options.https_proxy[0]      = 0;
    options.server_url[0]       = 0;
    options.server_ip_list[0]   = 0;
    options.service_ip[0]       = 0;

    fp = fopen(options.config_file, "r");
    if (fp == NULL) return EXIT_FAILURE;

    while ((read = getline(&line, &len, fp)) != -1)
    {

        // replace the trailing newline characters with the space character
        for (size_t indx = 0; indx < read; indx++)
        {
            if (line[indx] == '\n' || line[indx] == '\r') line[indx] = 0x20;
        }

        int shift = remove_spaces(line);
        read -= shift;

        // skip too short lines
        if (read < 3) continue;

        // skip comment lines
        if (line[0] == '#') continue;

        if (strstr(line, OPT_HTTPS_PROXY) != NULL)
        {
            strncpy(options.https_proxy, line + sizeof(OPT_HTTPS_PROXY), OPT_HTTPS_PROXY_LEN);
        }
        else if (strstr(line, OPT_SERVER_URL) != NULL)
        {
            if (line[read - 1] == '/') line[read - 1] = '\0';
            strncpy(options.server_url, line + sizeof(OPT_SERVER_URL), OPT_SERVER_URL_LEN);
        }
        else if (strstr(line, OPT_SERVICE_PORT) != NULL)
        {
            options.service_port = atoi(line + sizeof(OPT_SERVICE_PORT));
        }
        else if (strstr(line, OPT_SERVICE_IP) != NULL)
        {
            strncpy(options.service_ip, line + sizeof(OPT_SERVICE_IP), OPT_SERVICE_IP_LEN);
        }
        else if (strstr(line, OPT_ENABLE_EDNS) != NULL)
        {
            if (strcasestr(line, OPT_ENABLE_TRUE) != NULL) options.enable_edns = 1;
        }
    }

    free(line);

    return EXIT_SUCCESS;
}


int create_pidfile()
{
    char str[10] = {0};

    pidfp        = open(PIDFILE, O_RDWR|O_CREAT, 0600);

    if (pidfp == -1) return EXIT_FAILURE;

    if (lockf(pidfp, F_TLOCK,0) == -1) return EXIT_FAILURE;

    sprintf(str,"%d\n", getpid());

    write(pidfp, str, strlen(str));

    return EXIT_SUCCESS;
}

int remove_spaces(char* str)
{
    if (str == NULL) return 0;

    char* stra = str;
    char* strb = str;
    int shift = 0;

    do
    {
        *stra = *strb;
        if(*stra != ' ') stra++;
        else shift++;
    } while(*strb++ != 0);

    return shift;
}
