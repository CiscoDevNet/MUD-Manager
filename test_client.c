/*
 * Copyright (c) 2017-2018 by Cisco Systems, Inc.
 * All rights reserved.
 */

#include <mongoose.h>
#include <cJSON.h>
#include <openssl/evp.h>

int s_exit_flag=0;
struct mg_mgr mgr;
#define MAX_STR_LEN 255

#define WEBSERVERMAX 40
#define MUDFILEMAX 80
#define MACADDRMAX 15
#define NASMAX 15
#define SESSMAX 15

#if 0
static const char* cert="/home/cisco/workspace/enterprise-ca/certs_and_keys/testclient_cert.pem";
static const char* key="/home/cisco/workspace/enterprise-ca/certs_and_keys/testclient_key.pem";
static const char* ca_cert="/home/cisco/workspace/enterprise-ca/demoCA/cacert.pem";
#endif

struct mg_connect_opts connect_opts; 

char mudcontroller_ip[WEBSERVERMAX];

int test_client_get_dacl(char* uri, char* aclname);

static void ev_handler(struct mg_connection *nc, int ev, void *ev_data) 
{
    struct http_message *hm = (struct http_message *) ev_data;
    int connect_status, i;
    cJSON* res_json, *acl_array;
    char* uri;
    uri = (char*)nc->user_data;

    switch (ev) {
        case MG_EV_CONNECT:
            connect_status = *(int *) ev_data;
            if (connect_status != 0) {
                printf("Error connecting to MUD Controller %s\n",
                strerror(connect_status));
                s_exit_flag = 1;
            }
            break;
        case MG_EV_HTTP_REPLY:
            printf("Got reply:\nResponse: <%d>: %.*s\n",hm->resp_code, 
            (int)hm->body.len, hm->body.p);
            if (hm->resp_code == 200) {
                struct mg_str *con_type = mg_get_http_header(hm,"Content-Type");
                if ((con_type != NULL) && 
                        (!strncmp(con_type->p, "application/aclname", strlen("application/aclname")))) {
                    printf("Got ACL Names\n");
                    res_json = cJSON_Parse((char*)hm->body.p);
                    printf("Response Json <%s>\n", cJSON_Print(res_json));
                    acl_array = cJSON_GetObjectItem(res_json, "Cisco-AVPair");
                    for (i=0; i< cJSON_GetArraySize(acl_array); i++) {
                        printf("ACL Name %d: %s\n", i, 
                        cJSON_GetArrayItem(acl_array, i)->valuestring);
                        test_client_get_dacl(uri, cJSON_GetArrayItem(acl_array, i)->valuestring);
                    }
                } else if ((con_type != NULL) && 
                            (!strncmp(con_type->p, "application/dacl", strlen("application/dacl")))) {
                    printf("\n\nGot ACE <%.*s>\n", (int)hm->body.len, hm->body.p);
                } else if ((con_type != NULL) && 
                            (!strncmp(con_type->p, "application/masauri", strlen("application/masauri")))) {
                    printf("\n\nGot MASA URI <%.*s>\n", (int)hm->body.len, hm->body.p);
                }
            } else {
                s_exit_flag = 1;
            }
            nc->flags |= MG_F_SEND_AND_CLOSE;
            break;
        case MG_EV_CLOSE:
            if (s_exit_flag == 0) {
                printf("Server closed connection\n");
            };
            break;
        default:
            break;
    }
}

static void test_client_initialize()
{
    OpenSSL_add_all_algorithms();
    mg_mgr_init(&mgr, NULL);
}

int test_client_get_dacl(char* uri, char* aclname)
{
    struct mg_connection *nc;
    char request_url[MAX_STR_LEN];
    char* request_str;
    cJSON *jsonRequest;

    sprintf(request_url, "http://%s/getaclpolicy", mudcontroller_ip);
    jsonRequest = cJSON_CreateObject();
    aclname = aclname + 28;
    //cJSON_AddItemToObject(jsonRequest, "MUD_URI", 
    //cJSON_CreateString((char*)uri));
    cJSON_AddItemToObject(jsonRequest, "ACL_NAME", 
    cJSON_CreateString((char*)aclname));

    request_str = cJSON_Print(jsonRequest);
    printf ("Connect_opts: %s %s %s\n", connect_opts.ssl_cert, connect_opts.ssl_key, connect_opts.ssl_ca_cert );
    nc = mg_connect_http_opt(&mgr, ev_handler, connect_opts, request_url, 
                "Content-Type: application/json\r\nAccept: application/json\r\n", request_str);
    printf("Send request: %s %s\n", request_url, request_str);
    nc->user_data = (void*)uri;
    mg_set_protocol_http_websocket(nc);

    return(1);
}

int test_client_get_masauri(char* uri)
{
    char *request_str;
    struct mg_connection *nc;
    int status=0;
    cJSON *jsonRequest;
    char get_url[MAX_STR_LEN];

    jsonRequest = cJSON_CreateObject();
    cJSON_AddItemToObject(jsonRequest, "MUD_URI", 
    cJSON_CreateString((char*)uri));

    request_str = cJSON_Print(jsonRequest);

    sprintf(get_url, "http://%s/getmasauri",mudcontroller_ip);
    printf("\nStarting RESTful client against %s\n", get_url);
    nc = mg_connect_http_opt(&mgr, ev_handler, connect_opts, get_url, 
                "Content-Type: application/json\r\nAccept: application/json\r\n", request_str);
    nc->user_data = (void*)uri;
    mg_set_protocol_http_websocket(nc);

    while (s_exit_flag == 0) {
        mg_mgr_poll(&mgr, 1000);
    }

    mg_mgr_free(&mgr);
    return status;
}

int test_client_get_mudfile(char* uri, char* mac_addr, char* nas, char* sess_id)
{
    char *request_str;
    struct mg_connection *nc;
    int status=0;
    cJSON *jsonRequest;
    char get_url[MAX_STR_LEN];

    jsonRequest = cJSON_CreateObject();
    if (uri != NULL) {
        cJSON_AddItemToObject(jsonRequest, "MUD_URI", cJSON_CreateString((char*)uri));
    }
    if (mac_addr != NULL) {
        cJSON_AddItemToObject(jsonRequest, "MAC_ADDR", cJSON_CreateString((char*)mac_addr));
    }
    if (nas != NULL) {
        cJSON_AddItemToObject(jsonRequest, "NAS", cJSON_CreateString((char*)nas));
    }
    if (sess_id != NULL) {
        cJSON_AddItemToObject(jsonRequest, "SESS_ID", cJSON_CreateString((char*)sess_id));
    }

    request_str = cJSON_Print(jsonRequest);

    sprintf(get_url, "http://%s/getaclname",mudcontroller_ip);
    printf ("Connect_opts: %s %s %s\n", connect_opts.ssl_cert, connect_opts.ssl_key, connect_opts.ssl_ca_cert );
    printf("\nStarting RESTful client against %s\n", get_url);
    nc = mg_connect_http_opt(&mgr, ev_handler, connect_opts, get_url, 
                    "Content-Type: application/json\r\nAccept: application/json\r\n", request_str);
    nc->user_data = (void*)uri;
    mg_set_protocol_http_websocket(nc);

    while (s_exit_flag == 0) {
        mg_mgr_poll(&mgr, 1000);
    }

    mg_mgr_free(&mgr);
    return status;
}

void usage(char *filename)
{
    fprintf(stderr, "Usage: %s [-b ] [-m] -f mudfilename "
                "-w <address:port> -c<address:port>\n", filename);
    return;
}

int main(int argc, char *argv[]) 
{
    int testmasa = 0;
    int testmud = 0;
    int testmudwithmac = 0;
    char webserver[WEBSERVERMAX];
    char mudfile[MUDFILEMAX];
    char mac_addr[MACADDRMAX];
    char nas[NASMAX];
    char sess_id[SESSMAX];
    int opt;
    char url[14+WEBSERVERMAX+MUDFILEMAX];

    memset(&connect_opts, 0, sizeof(connect_opts));

    //connect_opts.ssl_ca_cert = ca_cert;
    //connect_opts.ssl_cert = cert;
    //connect_opts.ssl_key = key;
    //connect_opts.ssl_server_name = "*";
    while ((opt = getopt(argc, argv, "a:n:s:bf:mw:c:")) != -1) {
        switch (opt) {
            case 'a': 
                testmudwithmac = 1;
                strncpy(mac_addr, optarg, MACADDRMAX);
                break;
            case 'b':
                testmasa = 1;
                break;
            case 'f':
                strncpy(mudfile, optarg, MUDFILEMAX);
                break;
            case 'n': 
                strncpy(nas, optarg, NASMAX);
                break;
            case 'm':
                testmud = 1;
                break;
            case 's': 
                strncpy(sess_id, optarg, SESSMAX);
                break;
            case 'w':
                strncpy(webserver, optarg, WEBSERVERMAX);
                break;
            case 'c':
                strncpy(mudcontroller_ip, optarg, WEBSERVERMAX);
                break;
            default:
                usage(argv[0]);
                exit(1);
        }
    }

    /*
     * Make sure we got a MUD server address.
    if (argc - optind != 1 && argc - optind != 2) {
        usage(argv[0]);
        exit(1);
    }
    strncpy(mudcontroller_ip, argv[optind], WEBSERVERMAX);
    */

    /*
     * Default is to test for a MUD file.
     */
    if (!testmasa && !testmud) {
        testmud = 1;
    }

    test_client_initialize();

    /*
     * Build URL from args. Save the webserver info too.
     */
    strcpy(url, "https://");
    strncat(url, webserver, WEBSERVERMAX);
    strncat(url, "/", 1);
    strncat(url, mudfile, MUDFILEMAX);

    if (testmasa) {
        test_client_get_masauri(url);
    }
    if (testmudwithmac) {
        test_client_get_mudfile(url, mac_addr, nas, sess_id);
        //test_client_get_mudfile(NULL, mac_addr);
    } else if (testmud) {
        printf ("URL:  %s\n", url);
        test_client_get_mudfile(url, NULL, NULL, NULL);
    }

    return(0);
}


