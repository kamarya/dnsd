/*
 * Copyright (C) 2016  Behrooz Aliabadi

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

#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <signal.h>
#include <getopt.h>
#include <sys/stat.h>
#include <fcntl.h>
/* Network and Socket */
#include <curl/curl.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>

#include <unistd.h>

/* Logging */
#define LOG_LEVEL                       LEV_NO_DEV_LOG
#include "log.h"


#include <sys/stat.h>   // umask()

#include "dnssec.h"


#define DEBUG_ENABLE                    0
#define DEBUG_AUDIT_ENABLE              0
#define BUFFER_SIZE                     102400
#define DNS_SERVER_PORT                 53

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
        printf("fork failed!\n");
        exit(EXIT_FAILURE);
    }

    if (process_id > 0)
    {
        printf("daemon process id is %d. \n", process_id);
        exit(EXIT_SUCCESS);
    }

    umask(0);
    sid = setsid();
    if(sid < 0)
    {
        exit(1);
    }
    chdir("/");

    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);

    // close all open file descriptors
    for (int fid = sysconf(_SC_OPEN_MAX); fid > 0; fid--)
    {
        close (fid);
    }
}

#if DEBUG_AUDIT_ENABLE
void audit_pid(const char* port)
{
    int failed = 1;
    FILE *fp;
    char buffer[2048];

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

    if(failed) LOG_DEBUG("PID audit failed.");

    pclose(fp);
}
#endif

size_t body_callback (void *contents, size_t size, size_t nmemb, void *userp)
{
    size_t chunk = size * nmemb;
    strncpy(json + total_read, contents, chunk);

    total_read += chunk;
    LOG_DEBUG("read totaly %zu bytes.", total_read);

    return chunk;

}

void https_query(struct dns_query* query)
{

    CURL *curl;
    CURLcode res;

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

    LOG_DEBUG("query : %s", query_str);

    struct curl_slist *headers = NULL;

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
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);

        if (options.https_proxy[0])
        {
            curl_easy_setopt(curl, CURLOPT_PROXY, options.https_proxy);
        }

        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, body_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)query);

        total_read = 0;

        res = curl_easy_perform(curl);

        if (res != CURLE_OK)
        {
            LOG_ERROR("curl_easy_perform() failed: %s", curl_easy_strerror(res));
        }

        curl_easy_cleanup(curl);

        LOG_DEBUG("curl_easy_perform() has returned.");
    }

    curl_global_cleanup();
}

void server(void)
{

    struct sockaddr_in        server_add;
    buffer        = malloc(BUFFER_SIZE);
    json          = malloc(BUFFER_SIZE);
    data          = malloc(MAX_DOMAIN_LENGTH);
    char*  names  = malloc(MAX_DOMAIN_LENGTH);

    if (buffer == NULL) return;
    if (json   == NULL) return;
    if (data   == NULL) return;
    if (names  == NULL) return;

    memset(buffer, 0x00, BUFFER_SIZE);
    memset(json,   0x00, BUFFER_SIZE);
    memset(data,   0x00, MAX_DOMAIN_LENGTH);

    server_add.sin_family      = AF_INET;
    server_add.sin_port        = htons(options.service_port);
    server_add.sin_addr.s_addr = htonl(INADDR_ANY);


    sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if ( sock < 0 )
    {
        perror("socket()");
        return;
    }

    if (bind(sock, (struct sockaddr*) &server_add, sizeof(server_add)))
    {
        perror("bind()");
        return;
    }


    while (running)
    {
        int nread = recvfrom(sock, buffer, BUFFER_SIZE, MSG_WAITALL, (struct sockaddr*)&peer_add, &peer_add_len);

        if (nread < 0) continue;

        char host[NI_MAXHOST], service[NI_MAXSERV], ip[INET6_ADDRSTRLEN];

        int res = getnameinfo((struct sockaddr *) &peer_add,
                peer_add_len, host, NI_MAXHOST,
                service, NI_MAXSERV, NI_NUMERICSERV);
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
            LOG_ERROR( "getnameinfo() : %s", gai_strerror(res));
#if DEBUG_AUDIT_ENABLE
        audit_pid(service);
#endif

        struct dns_header_detail *header  = (struct dns_header_detail *)buffer;
        strncpy(names, buffer + sizeof(struct dns_header), nread - sizeof(struct dns_question) - sizeof(struct dns_header));

        for (int i = 0; i < MAX_DOMAIN_LENGTH; ++i)
        {
            if (names[i] < 0x30 && names[i] != '\0') names[i] = '.';
        }


        struct dns_query  query;
        query.header = header;
        query.qstn   = (struct dns_question *)(buffer + nread - sizeof(struct dns_question));
        query.length = nread;
        query.names  = names + (names[0] == '.'?1:0);


        memset(json,   0x00, BUFFER_SIZE);

        https_query(&query);

        header->qr        =   1; // this is a response
        header->rcode     =   0;
        header->ans_count =   htons(0);

        char* answer = (char *)(buffer + nread);

        int answer_length = 0;
        if ((answer_length = json_to_answer(answer, header)) < 1)
        {
            header->rcode = DNS_SERVER_FAILURE;
            answer_length = 0; // the returned value may be less than zero to indicate the error code.
            LOG_DEBUG ("(%x) DNS SERVER FAILURE", header->id);
        }


        if (sendto(sock, buffer, nread + answer_length, 0, (struct sockaddr *) &peer_add, peer_add_len) != (nread + answer_length))
        {
            LOG_ERROR("(%x) error sending response.", header->id);
        }
        else
        {
            LOG_DEBUG ("(%x) %u bytes has been sent to %s:%s.", header->id, (unsigned int)(nread + answer_length), ip, service);
        }

        memset(buffer, 0x00, BUFFER_SIZE);
        memset(names,  0x00, MAX_DOMAIN_LENGTH);
    }

    free(buffer);
    free(data);
    free(names);
    free(json);
    close(sock);

    LOG_DEBUG ("Process Terminated.");
}

int main(int argc, char **argv)
{

    memset(&options, 0x00, sizeof(struct func_options));

    extern char *optarg;
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

    peer_add_len = sizeof(struct sockaddr_storage);
    running = 1;

    // signal handler initialization
    struct sigaction sa;
    memset (&sa, '\0', sizeof(sa));
    sa.sa_handler = &handle_signal;

    sigaction(SIGHUP,   &sa, NULL);
    sigaction(SIGUSR1,  &sa, NULL);
    sigaction(SIGINT,   &sa, NULL);
    sigaction(SIGTERM,  &sa, NULL);

#if !DEBUG_ENABLE
    start_daemon();
    if (create_pidfile() == EXIT_FAILURE) return EXIT_FAILURE;
#endif

    server();

    return EXIT_SUCCESS;
}


int json_to_answer(char* answer, struct dns_header_detail* header)
{
    char*    orig   = answer;
    memset(data,   0x00, MAX_DOMAIN_LENGTH);

    char* rdata;

    uint16_t type      = 0;
    char     ctype[10] = "";

    uint32_t ttl       = 0;
    char     cttl[10]  = "";

    if (orig == NULL) return JSON_NULL;

    char* token = strstr(json, "Answer");

    if (token == NULL) return JSON_NO_ANSWER;

    uint16_t num_answers = 0;

    while ((token = strstr(token, "name")))
    {

        token        = strstr(token, "type");
        char*   beg  = strchr(token,   ':') + 2;
        size_t  len  = strchr(beg,   ',') - beg;

        memset(ctype, 0x00, 10);
        strncpy(ctype, beg, len);
        type         = atoi(ctype);

        if  (type != DNS_A_RECORD &&
                type != DNS_AAA_RECORD &&
                type != DNS_CNAME_RECORD &&
                type != DNS_NS_RECORD &&
                type != DNS_MX_RECORD)
        {   // other types are not supported
            continue;
        }
        else
        {
            token       =  beg + len;
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
        ans->r_data_len  =  0;

        if (type == DNS_A_RECORD)
        {
            ans->r_data_len  =  htons(4);
            rdata            =  (char *)(answer + 12);
            inet_pton(AF_INET, data + offset, rdata);

            // 4 x 3 + 3 = 15 bytes to be erased
            memset(data,   0x00, 20);

            answer += 4 + 12;
        }
        else if (type == DNS_AAA_RECORD)
        {
            ans->r_data_len  =  htons(16);
            rdata       =  (char *)(answer + 12);
            inet_pton(AF_INET6, data + offset, rdata);

            // maximum string size of an IPv6 address is 45 bytes
            memset(data,   0x00, 50);

            answer += 16 + 12;
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
            ans->r_data_len  =  htons(len + offset);
            rdata            =  (char *)(answer + 12);

            memcpy(rdata, data, len + offset);

            memset(data,   0x00, len + offset);
            answer += len + offset + 12;

        }
        else if (type == DNS_MX_RECORD)
        {

            rdata             =  (char *)(answer + 12);

            size_t      dot   = 0;
            while (data[dot] != ' ' && dot < 3) dot++;
            data[dot]         = '\0';
            uint16_t    pref  = atoi(data + offset);

            LOG_DEBUG("(%x) MX Preference : %d", header->id, pref);
            LOG_DEBUG("(%x) len [%zu] data [%s]", header->id, len, &data[dot + 1]);

            int diff = (dot == 2)?0:1;

            ans->r_data_len  =  htons(len + diff);

            pref = htons(pref);
            memcpy(rdata, (void *)(&pref), sizeof(pref));

            format(data + dot, len - dot);

            copy(rdata + sizeof(pref), data + dot, len + dot);

            memset(data,   0x00, MAX_DOMAIN_LENGTH);
            answer += len + 12 + diff;
        }
        else
        {
            ans->r_data_len  =  htons(len + offset);
            rdata       =  (char *)(answer + 12);
            strncpy(rdata, data + offset, len + offset);
            memset(data,   0x00, len + offset);
            answer += len + 12 + offset;
        }

        num_answers++;
    }

    header->qr        = 1;
    header->ans_count = htons(num_answers);

    return (answer - orig);
}


char* getTypeString(uint16_t type, int unknown)
{
    switch(type)
    {
        case DNS_AAA_RECORD:
            return "AAAA";
            break;
        case DNS_A_RECORD:
            return "A";
            break;
        case DNS_CNAME_RECORD:
            return "CNAME";
            break;
        case DNS_NS_RECORD:
            return "NS";
            break;
        case DNS_MX_RECORD:
            return "MX";
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
    switch (signal) {
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
    ssize_t read;

    fp = fopen(options.config_file, "r");
    if (fp == NULL) return EXIT_FAILURE;

    while ((read = getline(&line, &len, fp)) != -1)
    {

        // remove the trailing newline characters
        if (line[read - 1] == '\n')
        {
            line[read - 1] = '\0';
            --read;
        }

        remove_spaces(line);

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
    }

    free(line);

    return EXIT_SUCCESS;
}


int create_pidfile()
{
    char str[10] = {0};

    pidfp = open(PIDFILE, O_RDWR|O_CREAT, 0600);

    if (pidfp == -1 ) return EXIT_FAILURE;

    if (lockf(pidfp, F_TLOCK,0) == -1) return EXIT_FAILURE;

    sprintf(str,"%d\n", getpid());

    write(pidfp, str, strlen(str));

    return EXIT_SUCCESS;
}

void remove_spaces(char* str)
{
    char* stra = str;
    char* strb = str;

    do
    {
      *stra = *strb;
      if(*stra != ' ') stra++;
    } while(*strb++ != 0);
}
