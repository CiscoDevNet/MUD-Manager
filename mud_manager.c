/*
 * Copyright (c) 2017-2018 by Cisco Systems, Inc.
 * All rights reserved.
 */

#include <mongoose.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>
#include <openssl/asn1.h>
#include <openssl/cms.h>
#include <openssl/pem.h>
#include <openssl/pkcs7.h>
#include <openssl/ssl.h>
#pragma GCC diagnostic push // suppress specific warning from 3rd-party code
#pragma GCC diagnostic ignored "-Wexpansion-to-defined"
#include <mongoc.h>
#pragma GCC diagnostic pop
#include <cJSON.h>
#include "acl.h"
#include "log.h"
#include "sessions.h"
#include "acl_types.h"

#define DACL_INGRESS_EGRESS 0
#define DACL_INGRESS_ONLY 1
#define MAX_BUF 4096
#define MAX_ACL_STATEMENTS 10
#define MAX_ACE_STATEMENTS 10

#define FROM_DEVICE 0
#define TO_DEVICE 1

#define REQUEST_MUD_SIGNATURE_FILE 1
#define REQUEST_MUD_JSON_FILE      2

#define SRCPORT 1
#define DSTPORT 2

static const char *s_http_port = "8000";
static const char *s_https_port = "8443";
static const char *default_dbname = "mud_manager";
static const char *default_policies_coll_name = "mud_policies";
static const char *default_mudfile_coll_name = "mudfile";
static const char *default_macaddr_coll_name = "macaddr";
static const char *default_uri = "mongodb://127.0.0.1:27017";
static struct mg_serve_http_opts s_http_server_opts;

const char *mudmgr_cert=NULL;
const char *mudmgr_CAcert=NULL;
const char *mudmgr_key=NULL;
const char *mudmgr_server=NULL;
const char *mudmgr_coa_pw=NULL;
const char *acl_list_prefix = NULL;
int acl_list_type = INGRESS_EGRESS_ACLS;
enum acl_response_type acl_response = CISCO_DACL;
mongoc_client_t *client=NULL;
mongoc_collection_t *policies_collection=NULL;
mongoc_collection_t *mudfile_collection=NULL;
mongoc_collection_t *macaddr_collection=NULL;

typedef struct _request_context {
    struct mg_connection *in;
    struct mg_connection *out;
    char *uri;
    char *mac_addr;
    char *sess_id;
    char *nas;
    char *signed_mud;
    int signed_mud_len;
    char *orig_mud;
    int orig_mud_len;
    int status;
    int masaurirequest;
    bool send_client_response;
} request_context;

typedef struct _manufacturer_list {
    char* authority;
    char* https_port;
    char* certfile;
    X509 *cert;
    int vlan;
    char* my_ctrl_v4;
    char* my_ctrl_v6;
    char* local_nw_v4;
    char* local_nw_v6;
} manufacturer_list;

cJSON *dnsmap_json=NULL;
cJSON *ctrlmap_json=NULL;
cJSON *defacl_json=NULL;
cJSON *dnsmap_v6_json=NULL;
cJSON *ctrlmap_v6_json=NULL;
cJSON *defacl_v6_json=NULL;
manufacturer_list manuf_list[10];
char *mongoDb_uristr=NULL, *mongoDb_policies_collection=NULL, *mongoDb_name=NULL;
char *mongoDb_mudfile_coll=NULL;
char *mongoDb_macaddr_coll=NULL;
int num_manu = 0;

#define GETSTR_JSONOBJ(j,v) cJSON_GetObjectItem(j,v) ? cJSON_GetObjectItem(j, v)->valuestring: NULL
#define GETSTR_JSONARRAY(j,i) cJSON_GetArrayItem(defacl_json, i)->valuestring
#define GETINT_JSONOBJ(j,v) cJSON_GetObjectItem(j,v) ? cJSON_GetObjectItem(j, v)->valueint: 0

static void send_mudfs_request(struct mg_connection *nc, const char *base_uri,
                               const char *requested_uri, const char* mac_addr, 
                               const char* nas, const char* sess_id, int flag,
                               bool send_client_response);

static void send_error_result(struct mg_connection *nc, int status, const char *msg) 
{
    int response_len = 0;

    if (nc == NULL || msg == NULL) {
        MUDC_LOG_ERR("invalid parameters");
        return;
    }
    response_len = strlen(msg);
    mg_send_head(nc, status, response_len, NULL);
    mg_printf(nc, "%.*s", response_len, msg);
    nc->flags |= MG_F_SEND_AND_CLOSE;
}

static void send_error_for_context(request_context *ctx, int status, 
				   const char *msg)
{
    if (ctx == NULL || msg == NULL) {
        MUDC_LOG_ERR("invalid parameters");
        return;
    }

    if (ctx->send_client_response == false) {
        return;
    }

    send_error_result(ctx->in, status, msg);
}

static int cmp_sk_ak(X509_EXTENSION *sk, X509_EXTENSION *ak) 
{
    int ret=-1;
    BIO *sk_bio=NULL, *ak_bio=NULL;
    BUF_MEM *sk_bptr=NULL, *ak_bptr=NULL;
    char *sk_buf=NULL, *ak_buf=NULL;

    if((ak==NULL)||(sk==NULL)) {
        goto err;
    } else {
        sk_bio = BIO_new(BIO_s_mem());
        ak_bio = BIO_new(BIO_s_mem());

        if(!X509V3_EXT_print(sk_bio, sk, 0, 0)){
            // error handling...
            MUDC_LOG_ERR("Error copying SK in BIO");
            goto err;
        }
        BIO_get_mem_ptr(sk_bio, &sk_bptr);
        if(!X509V3_EXT_print(ak_bio, ak, 0, 0)){
            // error handling...
            MUDC_LOG_ERR("Error copying AK in BIO");
            goto err;
        }
        BIO_get_mem_ptr(ak_bio, &ak_bptr);

        if (sk_bptr == NULL || ak_bptr == NULL) {
            MUDC_LOG_ERR("BIO error");
            goto err;
        }

        sk_buf = (char *)calloc( (sk_bptr->length + 1),sizeof(char) );
        ak_buf = (char *)calloc( (ak_bptr->length + 1),sizeof(char) );

        if (sk_buf == NULL || ak_buf == NULL) {
            MUDC_LOG_ERR("malloc err");
            goto err;
        }
        memcpy(sk_buf, sk_bptr->data, sk_bptr->length);
        memcpy(ak_buf, ak_bptr->data+6, ak_bptr->length-7);

        sk_buf[sk_bptr->length] = '\0';
        ak_buf[ak_bptr->length-7] = '\0';

        // Now you can printf it or parse it, the way you want...
        MUDC_LOG_INFO("SK:[%s]\nAK:[%s]", sk_buf, ak_buf);
        ret = strcmp(sk_buf, ak_buf);
    }
err:
    if (sk_bio) {
        BIO_free_all(sk_bio);
    }
    if (ak_bio) {
        BIO_free_all(ak_bio);
    }
    if (sk_buf) {
        free(sk_buf);
    }
    if (ak_buf) {
        free(ak_buf);
    }
    return ret;
}


static int read_mudmgr_config (char* filename) 
{
    BIO *conf_file=NULL, *certin=NULL;
    char jsondata[MAX_BUF+1];
    char *acl_list_type_str=NULL;
    cJSON *json=NULL, *manuf_json=NULL, *tmp_json=NULL, *cacert_json=NULL;
    int ret=-1, i=0;

    if (!filename) {
        MUDC_LOG_ERR("invalid parameters");
        return -1;
    }

    memset(jsondata, 0, sizeof(jsondata)); // make valgrind happy

    conf_file=BIO_new_file(filename, "r");
    BIO_read(conf_file, jsondata, MAX_BUF);
    BIO_free(conf_file);
    json = cJSON_Parse(jsondata);

    if (!json) {
        MUDC_LOG_ERR("Error before: [%s]", cJSON_GetErrorPtr());
        goto err;
    }

    mudmgr_server = GETSTR_JSONOBJ(json, "MUDManagerAPIProtocol");
    if (mudmgr_server == NULL) { 
        mudmgr_server = "http";
    }
    mudmgr_coa_pw = GETSTR_JSONOBJ(json,"COA_Password");
    mudmgr_cert = GETSTR_JSONOBJ(json,"MUDManager_cert");
    mudmgr_key = GETSTR_JSONOBJ(json,"MUDManager_key");
    mudmgr_CAcert = GETSTR_JSONOBJ(json,"Enterprise_CACert");
    acl_list_prefix = GETSTR_JSONOBJ(json, "ACL_Prefix");
    acl_list_type_str = GETSTR_JSONOBJ(json, "ACL_Type");
    if ((acl_list_type_str != NULL) && !strcmp(acl_list_type_str, "dACL-ingress-only")) {
        acl_list_type = INGRESS_ONLY_ACL;
    }

    //MUDC_LOG_INFO("MUDCTRL CA Cert <%s> MUDCTRL Cert <%s> MUDCTRL Key <%s>", mudmgr_CAcert, mudmgr_cert, mudmgr_key);
    {   // moved if (!json) test earlier; skip moving below lines for now...
        manuf_json = cJSON_GetObjectItem(json, "Manufacturers");
        if (manuf_json == NULL) {
            MUDC_LOG_ERR("Error before: [%s]", cJSON_GetErrorPtr());
            goto err;
        } else {
            num_manu = cJSON_GetArraySize(manuf_json);
            if (num_manu <=0) {
                MUDC_LOG_ERR("Missing Manufacturer config") ;
                goto err;
            }
            for(i=0; i < num_manu; i++) {
                tmp_json = cJSON_GetArrayItem(manuf_json, i);
                if (tmp_json != NULL) {
                    cacert_json = cJSON_GetObjectItem(tmp_json, "cert");
                    if (cacert_json != NULL) {
                        manuf_list[i].certfile = GETSTR_JSONOBJ(tmp_json, "cert");
                        if (manuf_list[i].certfile != NULL) {
                            certin = BIO_new_file(manuf_list[i].certfile, "r");
                            if (certin != NULL) {
                                manuf_list[i].cert = PEM_read_bio_X509(certin, NULL, NULL, NULL);
                                BIO_free(certin);
                                if (manuf_list[i].cert != NULL) {
                                    MUDC_LOG_INFO("Successfully read Manufacture %d cert", i);
                                } else {
                                    MUDC_LOG_ERR("Missing CA certificate: Failed reading cert");
                                    goto err;
                                }
                            } else {
                                MUDC_LOG_ERR("Missing CA certificate: Certificate file missing");
                                goto err;
                            }
                        } else {
                            MUDC_LOG_ERR("Missing CA certificate: JSON Entry missing");
                            goto err;
                        }
                    } else {
                        MUDC_LOG_ERR("Missing Manufacturer: JSON Entry missing");
                        goto err;
                    }

                    manuf_list[i].vlan = GETINT_JSONOBJ(tmp_json, "vlan");
                    manuf_list[i].authority= GETSTR_JSONOBJ(tmp_json, "authority");
                    manuf_list[i].https_port = GETSTR_JSONOBJ(tmp_json, "https_port");
                    manuf_list[i].my_ctrl_v4 = GETSTR_JSONOBJ(tmp_json, "my_controller_v4");
                    manuf_list[i].my_ctrl_v6 = GETSTR_JSONOBJ(tmp_json, "my_controller_v6");
                    manuf_list[i].local_nw_v4 = GETSTR_JSONOBJ(tmp_json, "local_networks_v4");
                    manuf_list[i].local_nw_v6 = GETSTR_JSONOBJ(tmp_json, "local_networks_v6");
                } else {
                    MUDC_LOG_ERR("Missing Manufacturer Entries");
                    goto err;
                }
            }
        }

        MUDC_LOG_INFO("Certificate read ok:  Continue reading domain list");
        dnsmap_json = cJSON_GetObjectItem(json, "DNSMapping");
        if (dnsmap_json == NULL) {
            MUDC_LOG_ERR("Error before: [%s]", cJSON_GetErrorPtr());
            goto err;
        } else {
            MUDC_LOG_INFO("JSON is read succesfully");
        } 

        dnsmap_v6_json = cJSON_GetObjectItem(json, "DNSMapping_v6");
        if (dnsmap_v6_json == NULL) {
            MUDC_LOG_INFO("No IPv6 Mapping: [%s]", cJSON_GetErrorPtr());
        }

        ctrlmap_json = cJSON_GetObjectItem(json, "ControllerMapping");
        if (ctrlmap_json == NULL) {
            MUDC_LOG_ERR("Error before: [%s]", cJSON_GetErrorPtr());
            goto err;
        } else {
            MUDC_LOG_INFO("JSON is read succesfully");
        } 
        ctrlmap_v6_json = cJSON_GetObjectItem(json, "ControllerMapping_v6");
        if (ctrlmap_v6_json == NULL) {
            MUDC_LOG_INFO("No IPv6 Mapping: [%s]", cJSON_GetErrorPtr());
        }
        defacl_json = cJSON_GetObjectItem(json, "DefaultACL");
        if (defacl_json == NULL) {
            MUDC_LOG_INFO("No Default ACL configured");
        }
        defacl_v6_json = cJSON_GetObjectItem(json, "DefaultACL_v6");
        if (defacl_v6_json == NULL) {
            MUDC_LOG_INFO("No Default ACL configured");
        }

        mongoDb_name = GETSTR_JSONOBJ(json, "MongoDB_Name");
        if (mongoDb_name == NULL) {
            mongoDb_name = strdup(default_dbname);
        }

        mongoDb_uristr = GETSTR_JSONOBJ(json, "MongoDB_URI");
        if (mongoDb_uristr == NULL) {
            mongoDb_uristr = strdup(default_uri);
        }

        mongoDb_policies_collection = GETSTR_JSONOBJ(json, "MongoDB_Collection");
        if (mongoDb_policies_collection == NULL) {
            mongoDb_policies_collection = strdup(default_policies_coll_name);
        }

        mongoDb_mudfile_coll = GETSTR_JSONOBJ(json, "MongoDB_MUDFile_Collection");
        if (mongoDb_mudfile_coll == NULL) {
            mongoDb_mudfile_coll = strdup(default_mudfile_coll_name);
        }
        
	mongoDb_macaddr_coll = GETSTR_JSONOBJ(json, "MongoDB_MACADDR_Collection");
        if (mongoDb_macaddr_coll == NULL) {
            mongoDb_macaddr_coll = strdup(default_macaddr_coll_name);
        }
    }

    //Everything looks ok.  set ret 0 for success.
    ret = 0;
err:
    return ret;
}

/* For Demo only.  Needs to be changed*/
static char* convert_dns_to_ip(char *dnsname, int flag) 
{
    char* ipaddr = NULL;
    cJSON *map_json = NULL;

    if (dnsname == NULL) {
        MUDC_LOG_ERR("DNS Name NULL");
        return NULL;
    }
    if (flag) {
        map_json = dnsmap_v6_json;
    } else {
        map_json = dnsmap_json;
    }  

    if (map_json == NULL) {
        MUDC_LOG_ERR("Missing mapping table");
        return(NULL);
    }

    ipaddr = GETSTR_JSONOBJ(map_json, dnsname);
    if (ipaddr == NULL) { 
        MUDC_LOG_ERR("Missing DNS Mapping for: %s", dnsname);
    }
    return(ipaddr);
}

static char* convert_controller_to_ip(char *ctrlname, int flag) 
{
    char* ipaddr = NULL;
    cJSON *map_json = NULL;

    if (ctrlname == NULL) {
        MUDC_LOG_ERR("invalid parameters");
        return NULL;
    }

    if (flag) {
        map_json = ctrlmap_v6_json;
    } else {
        map_json = ctrlmap_json;
    }  

    MUDC_LOG_INFO("Controller <%s>", ctrlname);
    if (map_json == NULL) {
        MUDC_LOG_ERR("Missing mapping table");
        return(NULL);
    }
    ipaddr = GETSTR_JSONOBJ(map_json, ctrlname);
    if (ipaddr == NULL) { 
        MUDC_LOG_ERR("Missing %s Controller Mapping for: %s",
                     flag ? "IPV6":"IPV4", ctrlname);
    }
    MUDC_LOG_INFO("ipaddr: %s", ipaddr);
    return(ipaddr);
}


static bool check_required_fields (request_context* ctx, cJSON *mud_json) 
{
    cJSON *tmp_json = NULL;
    char *tmp_strvalue=NULL;

    /*
     * Validate that the version is correct. (mandatory)
     */
    tmp_json = cJSON_GetObjectItem(mud_json, "mud-version");
    if (!tmp_json) {
        MUDC_LOG_ERR("JSON file is missing 'mud-version'.");
        goto err;
    } else if (tmp_json->valueint != 1) {
        MUDC_LOG_ERR("Unsupported MUD file version: %d", tmp_json->valueint);
        goto err;
    }
    /* 
     * Validate that the MUD URL is in the file (mandatory), adn
     * that it matches the given URI.
     */

    tmp_json = cJSON_GetObjectItem(mud_json, "mud-url");
    if (!tmp_json) {
        MUDC_LOG_ERR("JSON file is missing 'mud-url'.");
        goto err;
    } else {
	tmp_strvalue = GETSTR_JSONOBJ(mud_json, "mud-url");
	if (strcmp(tmp_strvalue,ctx->uri)) {
       	    MUDC_LOG_ERR("MUD URL in MUD file does not match given MUD URL.");
	    MUDC_LOG_ERR("     URL in MUD file: %s", tmp_strvalue);
	    MUDC_LOG_ERR("     URL provided:    %s", ctx->uri);
            goto err;
	}
    }

    /*
     * Validate that some mandatory attributes are present that we don't
     * use. Just issue a warning for now.
     */
    tmp_json = cJSON_GetObjectItem(mud_json, "last-update");
    if (!tmp_json) {
        MUDC_LOG_ERR("Warning: JSON file is missing 'last-update");
    }
    tmp_json = cJSON_GetObjectItem(mud_json, "is-supported");
    if (!tmp_json) {
        MUDC_LOG_ERR("Warning: JSON file is missing 'is-supported");
    }
    return true;
err:
    return false;
}

static cJSON *extract_masa_uri (request_context* ctx, char *mudcontent)
{
    cJSON *mud_json=NULL, *meta_json=NULL, *response_json=NULL;
    cJSON *tmp_json=NULL;
    char *masa_uri=NULL;
    int index=0;
    bool found_extension = false;

    mud_json = cJSON_Parse(mudcontent);
    if (mud_json == NULL) {
        MUDC_LOG_ERR("Unable to parse file contents");
        return NULL;
    }
    meta_json = cJSON_GetObjectItem(mud_json, "ietf-mud:mud");
    if (meta_json == NULL) {
        MUDC_LOG_ERR("JSON file is missing 'ietf-mud:mud'");
        goto err;
    }

    if (check_required_fields(ctx, meta_json) == false) {
        MUDC_LOG_ERR("Missing required field");
        goto err;
    }

    // When specifying masa-server, need to add "masa" to extensions
    tmp_json = cJSON_GetObjectItem(meta_json, "extensions");
    if (!tmp_json) {
        MUDC_LOG_ERR("No extensions list");
        goto err;
    }
    for (index=0; index<cJSON_GetArraySize(tmp_json); index++) {
        cJSON *t = NULL;
        char *tmp = NULL;


        t = cJSON_GetArrayItem(tmp_json, index);
        tmp = (t != NULL) ? t->valuestring : NULL;

        if (tmp == NULL) {
            continue;
        }
        
        if (!strcmp(tmp, "masa")) {
            found_extension = true;
            break;
        }
    }
    if (found_extension == false) {
        MUDC_LOG_ERR("'masa' missing from extensions list");
        goto err;
    }

    masa_uri = GETSTR_JSONOBJ(meta_json, "ietf-mud-brski-masa:masa-server");
    if (masa_uri == NULL) {
        MUDC_LOG_ERR("File missing 'masa-server'");
        goto err;
    }
    response_json = cJSON_CreateObject();
    cJSON_AddItemToObject(response_json, "MASA-URI",cJSON_CreateString(masa_uri));
err:
    cJSON_Delete(mud_json);
    return (response_json);
}

static cJSON *get_mudfile_uri(char *uri) 
{
    const bson_t *record=NULL;
    mongoc_cursor_t *cursor=NULL;
    bson_t *filter=NULL;
    cJSON *found_json = NULL;
    char *found_str = NULL;
    

    filter = BCON_NEW("URI", BCON_UTF8(uri));
    cursor = mongoc_collection_find_with_opts(mudfile_collection, filter,
	    				      NULL, NULL);

    while (mongoc_cursor_next(cursor, &record)) {
        found_str = bson_as_json(record, NULL);
        if (found_str!=NULL) {
            found_json = cJSON_Parse(found_str);
            bson_free(found_str);
            if (!found_json) {
                MUDC_LOG_ERR("Error Before: [%s]\n", cJSON_GetErrorPtr());
            } else {
                break;
            }
        }
    }
    mongoc_cursor_destroy (cursor);
    bson_destroy(filter);

    return(found_json);
}

static bool update_mudfile_database(request_context *ctx, cJSON* full_json,
                                    time_t *exptime) 
{
    bson_error_t error;
    bson_t *query=NULL, *update=NULL;
    cJSON *mud_json=NULL;
    char *muduri=NULL, *lastupd=NULL, *sysinfo=NULL;
    int cachevalidity=0;
    char *full_str=NULL;
    cJSON *tmp_json = NULL;

    if (ctx == NULL || full_json == NULL) {
        MUDC_LOG_ERR("invalid parameters");
        return false;
    }

    memset(&error, 0, sizeof(error)); 
    mud_json = cJSON_GetObjectItem(full_json, "ietf-mud:mud");
    muduri = GETSTR_JSONOBJ(mud_json,"mud-url");
    lastupd = GETSTR_JSONOBJ(mud_json,"last-update");
    sysinfo = GETSTR_JSONOBJ(mud_json,"systeminfo");

    tmp_json = cJSON_GetObjectItem(mud_json, "cache-validity");
    if (tmp_json == NULL) {
        cachevalidity = 48; // default from I-D
    } else {
        cachevalidity = tmp_json->valueint;
    }

    MUDC_LOG_INFO("MUD URI <%s> Last Update <%s> System Info <%s> Cache-Validity <%d> expiration: <%s>", 
         muduri, lastupd, sysinfo, cachevalidity, ctime(exptime));

    if (ctx->mac_addr == NULL) {
        ctx->mac_addr = strdup("NA");
    }
    if (muduri == NULL && lastupd == NULL && sysinfo == NULL && cachevalidity == 0) {
        MUDC_LOG_ERR("Invalid file contents");
        return false;
    }

    full_str = cJSON_PrintUnformatted(full_json);

    update = BCON_NEW( "$set", "{", 
                "URI", BCON_UTF8(muduri),
                "Last-update", BCON_UTF8(lastupd),
                "Systeminfo", BCON_UTF8(sysinfo),
                "Cache-Validity", BCON_INT32(cachevalidity),
                "Expiry-Time", BCON_DATE_TIME(*exptime), 
                "MUD_Content", BCON_UTF8(full_str),"}");
    free(full_str);

    query =  BCON_NEW("URI", muduri);
    if (!mongoc_collection_find_and_modify(mudfile_collection, query, NULL, update, NULL, false, true, false, NULL,&error)) {
        MUDC_LOG_ERR("mongoc find_and_modify failed: %s", error.message);
        bson_destroy(query);
        bson_destroy(update);
        return(false);
    }
    bson_destroy(query);
    bson_destroy(update);
    return(true);
}

static int find_index(ACL *acllist, int acl_count, char* acl_name) 
{
    int index=0, ret= -1;
    
    if (acllist == NULL || acl_name == NULL) {
        MUDC_LOG_ERR("invalid parameters");
        return -1;
    }

    for (index=0; index < acl_count; index++) {
        MUDC_LOG_INFO("Index %d <Acl Name: %s>, <ACL List: %s> %d \n", index, acl_name, acllist[index].acl_name, acllist[index].pak_direction);
        if (strcmp(acllist[index].acl_name, acl_name) == 0) {
            ret=index;
            break;
        }
    }
    return ret;
}

static int parse_device_policy(cJSON *m_json, char* policy, ACL *acllist, int start_cnt, int direction)
{
    cJSON *lists_json=NULL, *acllist_json=NULL; 
    cJSON *aclitem_json=NULL, *policy_json=NULL;
    int ret_count=0, index=0;

    if (m_json == NULL || policy == NULL || acllist == NULL) {
        MUDC_LOG_ERR("invalid parameters");
        return -1;
    }

    policy_json = cJSON_GetObjectItem(m_json, policy);
    if (!policy_json) {
        MUDC_LOG_ERR("JSON file is missing '%s'", policy);
        goto err;
    }

    lists_json = cJSON_GetObjectItem(policy_json, "access-lists");
    if (!lists_json) {
        MUDC_LOG_ERR("JSON file is missing 'access-lists'from ietf-mud:device");
        goto err;
    }
    acllist_json = cJSON_GetObjectItem(lists_json, "access-list");
    if (!acllist_json) {
        MUDC_LOG_ERR("JSON file is missing 'access-list' from ietf-mud:device");
        goto err;
    }
    for (index=0;index < cJSON_GetArraySize(acllist_json); index++) {
        aclitem_json = cJSON_GetArrayItem(acllist_json, index);
        if (aclitem_json) {
            acllist[index+start_cnt].acl_name = GETSTR_JSONOBJ(aclitem_json, "name");
            if (acllist[index+start_cnt].acl_name == NULL) {
                MUDC_LOG_ERR("Missing 'acl name'");
                goto err;
            }
            acllist[index+start_cnt].pak_direction = direction;
        }
    }
    ret_count = start_cnt+index++;
    return(ret_count);
err:
    return(-1);
}

static bool parse_mud_port(cJSON *port_json, ACE *ace, int direction)
{
    char *op=NULL;
    int port=0;

    if (port_json == NULL || ace == NULL) {
        MUDC_LOG_ERR("invalid parameters");
        return false;
    }

    /*
     * One of the following sets of policy can be given:
     *    "port,operator"
     *    "lower-port,operator"cJSON *port_json (unsupported for now)
     *    "range","lower-port","upper-port"
     */
    if (cJSON_GetObjectItem(port_json, "port")) {
        /*
         * Make sure we have an "operator". But we can only 
         * realistically support "eq" as an operator.
         */
        if (cJSON_GetObjectItem(port_json, "operator")) {
            op = GETSTR_JSONOBJ(port_json, "operator");
            if (strcmp(op, "eq")) {
            	MUDC_LOG_ERR(
    		"Unsupported operator for 'port': %s\n", op);
       	    	return(false);
            }
            /*
 	     * The lone port goes in both lower and upper.
             */
            if (!GETSTR_JSONOBJ(port_json, "port")) {
    	    	MUDC_LOG_ERR("Port missing\n");
    	    	return(false);
            }
    	    port = GETINT_JSONOBJ(port_json, "port");
    	    if (direction == SRCPORT) {
                ace->matches.src_lower_port = port;
    	    	ace->matches.src_upper_port = port;
    	    } else {
                ace->matches.dst_lower_port = port;
    	    	ace->matches.dst_upper_port = port;
    	    }
        }

    } else if (cJSON_GetObjectItem(port_json, "lower-port")) {
        if (cJSON_GetObjectItem(port_json, "operator")) {
            MUDC_LOG_ERR(
	       "'operator' is legal with 'lower-port' but not supported\n'");
            return(false);
        }
        if (!cJSON_GetObjectItem(port_json, "upper-port")) {
            MUDC_LOG_ERR("'upper-port' is missing\n");
            return(false);
        }
        port = GETINT_JSONOBJ(port_json, "port");
        if (direction == SRCPORT) {
            ace->matches.src_lower_port =
    	    	GETINT_JSONOBJ(port_json, "lower-port");
            ace->matches.src_upper_port = 
    		GETINT_JSONOBJ(port_json, "upper-port");
        } else {
            ace->matches.dst_lower_port =
    		GETINT_JSONOBJ(port_json, "lower-port");
            ace->matches.dst_upper_port = 
    		GETINT_JSONOBJ(port_json, "upper-port");
        }

    } else {
       	MUDC_LOG_ERR("Missing 'port' or 'lower-port' in ACL\n");
       	return(false);
    }

    return(true);
}

static cJSON* parse_mud_content (request_context* ctx, int manuf_index)
{
    cJSON *full_json=NULL, *mud_json=NULL, *lists_json=NULL; 
    cJSON *acllist_json=NULL, *aclitem_json=NULL, *ace_json=NULL;
    cJSON *aceitem_json=NULL, *action_json=NULL, *matches_json=NULL;
    cJSON *port_json=NULL, *response_json=NULL;
    cJSON *tmp_json=NULL, *tmp_2_json=NULL, *ctrl_json=NULL;
    int index=0, ace_index=0, acl_index=0, acl_count=0, is_v6=0, is_vlan=0;
    ACL *acllist=NULL;
    char *type=NULL;
    int cache_in_hours = 0;
    time_t timer;
    time_t exptime;

    MUDC_LOG_INFO("In parse_mud_content");

    if (ctx == NULL) {
        MUDC_LOG_ERR("invalid parameters");
        return NULL;
    }

    full_json = cJSON_Parse((char*)ctx->orig_mud);
    if (!full_json) {
        MUDC_LOG_ERR("JSON file parsing failed: %s", cJSON_GetErrorPtr());
        return (NULL);
    }
   
    /*
     * Make sure it's a MUD file.
     */
    mud_json = cJSON_GetObjectItem(full_json, "ietf-mud:mud");
    if (!mud_json) {
        MUDC_LOG_ERR("JSON file is missing 'ietf-mud:mud'");
        goto err;
    }

    if (check_required_fields(ctx, mud_json) == false) {
        MUDC_LOG_ERR("Missing required field");
        goto err;
    }

    tmp_json = cJSON_GetObjectItem(mud_json, "cache-validity");
    if (!tmp_json) {
        cache_in_hours = 48;  // default from I-D
    } else {
        cache_in_hours = tmp_json->valueint;
    }
    MUDC_LOG_INFO("cache-validity: %d", cache_in_hours);
    if (cache_in_hours <= 1 || cache_in_hours >= 168) {
        MUDC_LOG_ERR("Invalid 'cache-validity' value");
        goto err;
    }
    time(&timer);    // get current time in seconds
    MUDC_LOG_INFO("currtime: %s", ctime(&timer));
    exptime = timer + (cache_in_hours * 3600);
    //exptime = timer + (3* 60);
    MUDC_LOG_INFO("exptime: %s", ctime(&exptime));
    

    /*
     * Validate that "from-device-policy" and "to-device-policy" sections are 
     * present (mandatory?). This is done while stuffng away their names 
     * in the "acllist" structure, and returning a count of how many total
     * ACLs we have.
     */
    acllist = (ACL*) calloc(MAX_ACL_STATEMENTS, sizeof(ACL));
    acl_count = parse_device_policy(mud_json, "from-device-policy", acllist, 
		    					    0, INGRESS);
    if (acl_count == -1) {
        MUDC_LOG_ERR("JSON device policy error");
        goto err;
    }

    acl_count = parse_device_policy(mud_json, "to-device-policy", acllist, 
		    					    acl_count, EGRESS);
    if (acl_count == -1) {
        MUDC_LOG_ERR("JSON device policy error");
        goto err;
    }

    /*
     * Find the "ietf-access-control-list:acls" section in the 
     * MUD file.
     */
    if ((lists_json=cJSON_GetObjectItem(full_json, 
		"ietf-access-control-list:acls")) == NULL) {  
        MUDC_LOG_ERR("JSON file is missing 'ietf-acl:access-lists'");
        goto err;
    }
    acllist_json = cJSON_GetObjectItem(lists_json, "acl");
    if (!acllist_json) {
        MUDC_LOG_ERR("JSON file is missing 'acl'");
        goto err;
    }

    /*
     * Loop through each of the ACLs in "acllist".
     */
    for (index=0;index < cJSON_GetArraySize(acllist_json); index++) {
        aclitem_json = cJSON_GetArrayItem(acllist_json, index);
        if (!aclitem_json) {
            MUDC_LOG_ERR("'MUD file inconsistent: no ACL");
            goto err;
        }
	/*
	 * Find the name in acllist, and return its index. acllist holds
	 * the ACL names disovered in the earlier from-device-policy and
	 * to-device-policy sections of the file.
	 */
        acl_index = find_index(acllist, acl_count, 
		    	   GETSTR_JSONOBJ(aclitem_json, "name"));
        if (acl_index == -1) {
            MUDC_LOG_ERR("MUD file inconsistent: ACL name %s not found",
		    GETSTR_JSONOBJ(aclitem_json, "name"));
            goto err;
        }

        /*
	 * Find and store the ACL "type", and find the first "ace".
	 * Note: Beginning with "aces", the Yang model definition
	 *       is described in draft-ietf-netmod-acl-model-19.
	 *       However, the DNS name extensions to the ACL model
	 *       are defined in the MUD specification.
	 *
	 * TBD: The ACL Yang model does not require the "type"
	 *      to be present. We should not depend upon it 
	 *      here. It seems that you have to wait until you
	 *      parse the ACE "matches" statement to find out
	 *      what kind of ACE this is. (Is it required
	 *      that all ACEs be of the same type?)
	 */
        type = GETSTR_JSONOBJ(aclitem_json, "type");
        is_v6 = (strcmp(type, "ipv4-acl-type") == 0) ? 0 : 1;
        acllist[acl_index].acl_type = is_v6 ? "ipv6" : "ipv4";

        ace_json = cJSON_GetObjectItem(cJSON_GetObjectItem(aclitem_json, 
							   "aces"), "ace");
        if (!ace_json) {
	    MUDC_LOG_ERR("ACE statements are missing");
	    goto err;
        }
        acllist[acl_index].ace = (ACE*)calloc(MAX_ACE_STATEMENTS, sizeof(ACE));
        acllist[acl_index].ace_count = 0;
	/*
	 * Loop through "ace" statements in this ACL.
	 */
	if (cJSON_GetArraySize(ace_json) > MAX_ACE_STATEMENTS) {
	    MUDC_LOG_ERR("Too many ACE statements: %d", cJSON_GetArraySize(ace_json));
	    goto err;
	}
        for (ace_index = 0; ace_index < cJSON_GetArraySize(ace_json); 
		ace_index++) {

            aceitem_json = cJSON_GetArrayItem(ace_json, ace_index); 
            if (!aceitem_json) {
	    	MUDC_LOG_ERR("ACE list is corrupted");
		goto err;
	    }
	    /*
	     * Find "name" and "matches" (required)
	     */
	    acllist[acl_index].ace[ace_index].num_ace = 1;
            acllist[acl_index].ace[ace_index].rule_name = 
		    GETSTR_JSONOBJ(aceitem_json, "name");
            if (acllist[acl_index].ace[ace_index].rule_name == NULL) {
                MUDC_LOG_ERR("Missing ACE 'name'");
                goto err;
            }

            matches_json = cJSON_GetObjectItem(aceitem_json, "matches");
            if (!matches_json) {
		MUDC_LOG_ERR("ACE statement is missing 'matches'");
	        goto err;
	    }

	    /*
	     * Parse the "matches" list of protocols.
	     *
	     * Several ACL types are supported. Look for each in turn
	     */

	    /*
	     * ipv4
	     */
	    if ((tmp_json=cJSON_GetObjectItem(matches_json, "ipv4"))) {
		if (is_v6) {
		    MUDC_LOG_ERR("Got an ipv4 protocol in an ipv6 ACL\n");
		    goto err;
		} else {
		    MUDC_LOG_ERR("Processing an ipv4 protocol\n");
		}

		/* Look for "protocol" (required) */
                acllist[acl_index].ace[ace_index].matches.protocol = 
		    GETINT_JSONOBJ(tmp_json, "protocol");
		if (acllist[acl_index].ace[ace_index].matches.protocol == 0) {
		    MUDC_LOG_ERR("Protocol not found in ACE.\n");
		    goto err;
		} 

		/* Check for MUD DNS name extensions */
                if ((tmp_2_json=cJSON_GetObjectItem(tmp_json, 
			    "ietf-acldns:src-dnsname"))) {
                    acllist[acl_index].ace[ace_index].matches.dnsname = 
			convert_dns_to_ip(tmp_2_json->valuestring, is_v6);
                } else if ((tmp_2_json=cJSON_GetObjectItem(tmp_json, 
			    "ietf-acldns:dst-dnsname"))) {
                    acllist[acl_index].ace[ace_index].matches.dnsname = 
			convert_dns_to_ip(tmp_2_json->valuestring, is_v6);
                } else {
                    acllist[acl_index].ace[ace_index].matches.dnsname = "any";
                }

	    }

	    /*
	     * ipv6
	     */
	    if ((tmp_json=cJSON_GetObjectItem(matches_json, "ipv6"))) {
		if (!is_v6) {
		    MUDC_LOG_ERR("Got an ipv6 protocl in an ipv4 ACL\n");
		    goto err;
		} else {
		    MUDC_LOG_ERR("Processing an ipv6 protocol\n");
		}
		
		/* Look for "protocol" (required) */
                acllist[acl_index].ace[ace_index].matches.protocol = 
		    GETINT_JSONOBJ(tmp_json, "protocol");

		/* Check for MUD DNS name extensions */
                if ((tmp_2_json=cJSON_GetObjectItem(tmp_json, 
			    "ietf-acldns:src-dnsname"))) {
                    acllist[acl_index].ace[ace_index].matches.dnsname = 
			convert_dns_to_ip(tmp_2_json->valuestring, is_v6);
                } else if ((tmp_2_json=cJSON_GetObjectItem(tmp_json, 
			    "ietf-acldns:dst-dnsname"))) {
                    acllist[acl_index].ace[ace_index].matches.dnsname = 
			convert_dns_to_ip(tmp_2_json->valuestring, is_v6);
                } else {
                    acllist[acl_index].ace[ace_index].matches.dnsname = "any";
                }
	    }

	    /*
	     * tcp
	     */
            acllist[acl_index].ace[ace_index].matches.dir_initiated = -1;
	    if ((tmp_json=cJSON_GetObjectItem(matches_json, "tcp"))) {
	        MUDC_LOG_ERR("Processing an tcp protocol\n");

		acllist[acl_index].ace[ace_index].matches.protocol = 6;

		/*
		 * Handle any MUD "direction-initiated policy.
		 */
                if ((cJSON_GetObjectItem(tmp_json, 
			    "ietf-mud:direction-initiated"))) {
                    if (strcmp(cJSON_GetObjectItem(tmp_json, 
			    "ietf-mud:direction-initiated")->valuestring, 
			    "from-device")) {
                        acllist[acl_index].ace[ace_index].matches.dir_initiated
			    = FROM_DEVICE;
	   	    } else if (strcmp(cJSON_GetObjectItem(tmp_json, 
			    "ietf-mud:direction-initiated")->valuestring, 
			    "to-device")) {
                        acllist[acl_index].ace[ace_index].matches.dir_initiated
			    = TO_DEVICE;
                    }
                    if (acllist[acl_index].pak_direction == 
			acllist[acl_index].ace[ace_index].
				matches.dir_initiated) {
			    acllist[acl_index].ace[ace_index].num_ace++;
		    }
	         }

	    	/*
	     	 * Look for "source-port" or "destination-port".
	     	 *
	     	 * TBD: Verify that only one of these is included.
	     	 */
            	port_json = cJSON_GetObjectItem(tmp_json, "source-port");
            	if (port_json) {
		    if (!parse_mud_port(port_json, 
			    	        &acllist[acl_index].ace[ace_index],
				        SRCPORT)) {
		    	MUDC_LOG_ERR("Error in 'source-port'\n");
		    	goto err;
		    }
	    	}
            
	    	port_json = cJSON_GetObjectItem(tmp_json, "destination-port");
            	if (port_json) {
		    if (!parse_mud_port(port_json, 
			    	   	&acllist[acl_index].ace[ace_index],
				   	DSTPORT)) {
		    	MUDC_LOG_ERR("Error in 'destination-port'\n");
		    	goto err;
		    }
	    	}
            }
            
	    /*
	     * udp
	     */
	    if ((tmp_json=cJSON_GetObjectItem(matches_json, "udp"))) {
	        MUDC_LOG_ERR("Processing an udp protocol\n");

		acllist[acl_index].ace[ace_index].matches.protocol = 17;

	    	/*
	     	 * Look for "source-port" or "destination-port".
	     	 *
	     	 * TBD: Verify that only one of these is included.
	     	 */
            	port_json = cJSON_GetObjectItem(tmp_json, "source-port");
            	if (port_json) {
		    if (!parse_mud_port(port_json, 
			    	        &acllist[acl_index].ace[ace_index],
				        SRCPORT)) {
		    	MUDC_LOG_ERR("Error in 'source-port'\n");
		    	goto err;
		    }
	    	}
            
	    	port_json = cJSON_GetObjectItem(tmp_json, "destination-port");
            	if (port_json) {
		    if (!parse_mud_port(port_json, 
			    	   	&acllist[acl_index].ace[ace_index],
				   	DSTPORT)) {
		    	MUDC_LOG_ERR("Error in 'destination-port'\n");
		    	goto err;
		    }
	    	}
	    }

	    /*
	     * ietf-mud:mud
	     */
	    if ((tmp_json=cJSON_GetObjectItem(matches_json, "ietf-mud:mud"))) {
	        MUDC_LOG_ERR("Processing a ietf-mud:mud protocol\n");
                if ((ctrl_json=cJSON_GetObjectItem(tmp_json, "controller"))) {
                    acllist[acl_index].ace[ace_index].matches.dnsname = 
		       convert_controller_to_ip(ctrl_json->valuestring, is_v6);
                 } 

		if ((ctrl_json=cJSON_GetObjectItem(tmp_json, "local-networks"))){
                     MUDC_LOG_INFO("local-network  is V4 <%d>\n", is_v6);
                     if (is_v6) {
                         acllist[acl_index].ace[ace_index].matches.dnsname = 
			     manuf_list[manuf_index].local_nw_v6;
                     } else {
                         acllist[acl_index].ace[ace_index].matches.dnsname = 
			     manuf_list[manuf_index].local_nw_v4;
                     }
                } 
		
		if ((ctrl_json=cJSON_GetObjectItem(tmp_json, "my-controller"))) {
                    MUDC_LOG_INFO("My controller is V4 <%d>\n", is_v6);
                    if (is_v6) {
                        acllist[acl_index].ace[ace_index].matches.dnsname = 
			      manuf_list[manuf_index].my_ctrl_v6;
                    } else {
                        acllist[acl_index].ace[ace_index].matches.dnsname = 
			      manuf_list[manuf_index].my_ctrl_v4;
                    }
		}

                if (cJSON_GetObjectItem(tmp_json, "same-manufacturer")) {
                    if (manuf_list[manuf_index].vlan == 0) {
                   	 MUDC_LOG_INFO("VLAN is required but not configured for this Manufacturer\n");
                         goto err;
                    }
                    acllist[acl_index].ace[ace_index].matches.dnsname = "any";
                    is_vlan = 1;
                }
	    }

	    /*
	     * Sanity checks.
	     */
            if ((acllist[acl_index].ace[ace_index].matches.dnsname == NULL) 
		    && !is_vlan) {
                 MUDC_LOG_ERR("Missing Host or Controller name \n");
                 goto err;
             }

	    /*
	     * Check the "actions"
	     */
             action_json = cJSON_GetObjectItem(aceitem_json, "actions"); 
             if (cJSON_GetObjectItem(action_json, "forwarding")) {
                 if (strcmp(cJSON_GetObjectItem(action_json, 
			    "forwarding")->valuestring, "accept") == 0) {
                     acllist[acl_index].ace[ace_index].action = 1;
                  }
             }
             acllist[acl_index].ace_count++;
	}
    }
    MUDC_LOG_INFO("Calling Create response\n");
    response_json = create_policy_from_acllist(CISCO_DACL, acllist, acl_count,
	    				       acl_list_type);
   
    /*
     * Now that we've fully verified that the MUD file is properly formed 
     * and we can use it, save it in the DB.
     */
    if (!update_mudfile_database(ctx, full_json, &exptime)) {
        MUDC_LOG_ERR("Failed to save the MUD URL.");
        goto err;
    }

    goto end;
err:
    cJSON_Delete(response_json);
    response_json = NULL;
end:
    if (acllist) {
    	for (acl_index = 0; acl_index < 10; acl_index++) {
            if (acllist[acl_index].ace != NULL) {
            	free(acllist[acl_index].ace);
            }
    	}
    	free(acllist);
    }
    cJSON_Delete(full_json);
    return(response_json);
}

// Return manufacturer index
static int find_manufacturer(char* muduri) 
{
    int j=0, ret=-1;

    if (muduri == NULL) {
        MUDC_LOG_ERR("invalid parameters");
        return -1;
    }

    for (j=0; j < num_manu; j++) {
        if (strstr(muduri, manuf_list[j].authority) != NULL) {
            MUDC_LOG_INFO("Found Manufacturer index <%d>\n", j);
            ret = j;
            break;
        }
    }
    return ret;
}

static bool query_policies_by_uri(struct mg_connection *nc, const char* uri, bool query_only, bool *cache_expired) 
{
    const bson_t *record=NULL;
    mongoc_cursor_t *cursor=NULL;
    bson_t *filter=NULL;
    char *found_str=NULL, *response_str=NULL, *reply_type=NULL;
    cJSON *found_json=NULL, *name_json=NULL,*response_json=NULL, *dacl_name=NULL;
    int response_len=0, vlan=0, ret=0; 
    bool found_uri=false;
    bool found_acl=false;
    cJSON *tmp_json=NULL, *dt=NULL;
    time_t *expired_time=NULL;
    time_t curr_time;
    cJSON *mud_json=NULL;

    if (nc == NULL || uri == NULL || cache_expired == NULL) {
        MUDC_LOG_ERR("Invalid parameters");
        return false;
    }

    memset(&curr_time, 0, sizeof(curr_time));

    *cache_expired = false;

    mud_json = get_mudfile_uri((char *)uri);
    if (!mud_json) {
        MUDC_LOG_ERR("No mudfile policy");
        return false;
    }
    tmp_json = cJSON_GetObjectItem(mud_json, "Expiry-Time");
    if (tmp_json) {
        dt = cJSON_GetObjectItem(tmp_json, "$date");
        if (dt) {
            expired_time = (time_t *)&(dt->valueint);
            time(&curr_time);
            //MUDC_LOG_INFO("curr_time: %s, expiry time: %s", 
            //       ctime(&curr_time), ctime(expired_time));
            if (difftime(curr_time, *expired_time) >= 0) {
                MUDC_LOG_INFO("Cache has expired");
                *cache_expired = true;
            }
        }
    }
    cJSON_Delete(mud_json);

    response_json = cJSON_CreateObject();

    /*
     * Find all of the policy records that contain this MUD URL, and place each
     * found "DACL_Name" in a JSON array.
     */
    filter = BCON_NEW("URI", BCON_UTF8(uri));
    cursor = mongoc_collection_find_with_opts(policies_collection, filter,
	    				      NULL, NULL);
    dacl_name = cJSON_CreateArray();
    while (mongoc_cursor_next(cursor, &record)) {
        found_str = bson_as_json(record, NULL);
        if (found_str!=NULL) {
            MUDC_LOG_INFO("found the record <%s>\n", found_str);
            found_json = cJSON_Parse(found_str);
            if (!found_json) {
                MUDC_LOG_ERR("Error Before: [%s]\n", cJSON_GetErrorPtr());
            } else {
                found_uri = true;
                name_json = cJSON_GetObjectItem(found_json, "DACL_Name");
                if (name_json != NULL) {
                    cJSON_AddItemToArray(dacl_name, 
			    cJSON_Duplicate(cJSON_GetObjectItem(found_json, "DACL_Name"), true));
                    vlan = GETINT_JSONOBJ(found_json, "VLAN");
                }
                cJSON_Delete(found_json);
            }
            bson_free(found_str);
        }
    }
    if (cJSON_GetArraySize(dacl_name) > 0) {
        found_acl = true;
        if (query_only) {
            goto end;
        }
	/*
	 * This precedes the JSON array of ACL names with a type of
	 * "Cisco-AVPair". When FreeRADIUS receives this array, it 
	 * generates a set of Cisco-AVPair RADIUS attributes, each one having
	 * a single ACL name.
	 */
        cJSON_AddItemToObject(response_json, "Cisco-AVPair", dacl_name);
        dacl_name = NULL;  // we don't want to nuke this
        if (vlan) {
            cJSON_AddStringToObject(response_json, "Tunnel-Type", "VLAN");
            cJSON_AddStringToObject(response_json, "Tunnel-Media-Type", 
		    				   "IEEE-802");
            cJSON_AddNumberToObject(response_json, "Tunnel-Private-Group-Id", 
		    				   vlan);
        }

        ret = 200;
        reply_type = "Content-Type: application/aclname";
        response_str = cJSON_Print(response_json);
        response_len = strlen(response_str);
        MUDC_LOG_INFO("Response <%s>\n", response_str);

        mg_send_head(nc, ret, response_len, reply_type);
        mg_printf(nc, "%.*s", response_len, response_str);
        free(response_str);
        nc->flags |= MG_F_SEND_AND_CLOSE;
    } else if (query_only) {
        goto end;
    } else if (found_uri) {
        // uri in database w/o ACLs
        // return success so that FR does not reject auth
        ret = 204;
        reply_type = "Content-Type: application/aclname";
        response_str = "{\"MSG\":\"No ACL for this MUD URL\"}";
        response_len = strlen(response_str);
        mg_send_head(nc, ret, response_len, reply_type);
        mg_printf(nc, "%.*s", response_len, response_str);
        nc->flags |= MG_F_SEND_AND_CLOSE;
    }

end:
    mongoc_cursor_destroy (cursor);
    bson_destroy(filter);
    cJSON_Delete(response_json);
    cJSON_Delete(dacl_name);

    return found_acl;
}

static void start_session (struct mg_connection *nc,
                                      const char *requested_uri,
                               	      const char* mac_addr, 
                               	      const char* nas, const char* sess_id)
{
    int rc = 0;
  
    /*
     * The sessions database is used to keep track of RADIUS Accounting
     * sessions, in case we need to issue a Change of Authorization (CoA)
     * to the NAS handling the device. So for now, only attempt to add
     * a session if we have everything it needs.
     */
    if ((mac_addr == NULL) || (sess_id == NULL) || (nas == NULL)) {
	MUDC_LOG_INFO("Not enough data to add a session.\n");
	return;
    }

    /*
     * Attempt to add the session in the database.
     */
    rc = add_session(mac_addr, sess_id, nas, requested_uri);
    if (rc == SESS_EXISTS) {
        /* Nothing else to do. */
        return;
    } else if (rc == SESS_ERROR) {
        MUDC_LOG_ERR("Error in adding session");
        return;
    }

    if (nc == NULL) {
        MUDC_LOG_ERR("Invalid parameters");
        return;
    }

    /*
     * If other events need to be triggered on a new session,
     * add those triggers here.
     */

    return;
}

static int verify_mud_content(char* smud, int slen, char* omud, int olen) 
{
    BIO *smud_bio=NULL, *omud_bio=NULL, *out=NULL;
    X509_STORE *st = NULL;
    X509 *cacert = NULL, *cert=NULL;
    X509_EXTENSION *ak_ext=NULL, *sk_ext=NULL;
    PKCS7 *p7 = NULL;
    STACK_OF(PKCS7_SIGNER_INFO) *sinfos=NULL;
    PKCS7_SIGNER_INFO *sitmp=NULL;
    CMS_ContentInfo *cms = NULL;
    int i=0, j=0, loc=0, found_ca = -1, ret = 0;

    if (smud == NULL || slen <= 0 || omud == NULL || olen <= 0) {
        MUDC_LOG_ERR("invalid parameters");
        return -1;
    }

    smud_bio=BIO_new_mem_buf(smud, slen);
    omud_bio=BIO_new_mem_buf(omud, olen);

    p7 = d2i_PKCS7_bio(smud_bio, NULL);
    if (!p7) {
        MUDC_LOG_ERR("Error reading PKCS7 format\n");
        goto err;
    }
    
    sinfos = PKCS7_get_signer_info(p7);
    for(i=0; i < sk_PKCS7_SIGNER_INFO_num(sinfos); i++) {
        sitmp = sk_PKCS7_SIGNER_INFO_value(sinfos, i);
        cert = PKCS7_cert_from_signer_info(p7, sitmp);
        loc = X509_get_ext_by_NID(cert, NID_authority_key_identifier, -1);
        ak_ext = X509_get_ext(cert, loc);
        if (ak_ext) {
            for (j=0; j < num_manu; j++) {
                loc = X509_get_ext_by_NID(manuf_list[j].cert, NID_subject_key_identifier,-1);
                sk_ext = X509_get_ext(manuf_list[j].cert, loc);
                if (!cmp_sk_ak(sk_ext, ak_ext)) {
                    if (found_ca == -1) {
                        found_ca = j;
                        MUDC_LOG_INFO("Found Manufaturer CA.  Manufacturer id <%d>\n", found_ca);
                    } else if (found_ca != j) {
                        MUDC_LOG_ERR("Error in finding the Manufacturer certificate\n");
                        goto err;
                    }
                }
            }
            if (found_ca == -1) {
                MUDC_LOG_ERR("No matching Manufacturer certificate\n");
                goto err;
            }
        } else {
            MUDC_LOG_ERR("Missing Authority Key Identifier\n");
            goto err;
        }
    }
    if (p7) {
        PKCS7_free(p7);
        p7 = NULL;
    }

    /* Set up trusted CA certificate store */
    st = X509_STORE_new();

    if (!X509_STORE_add_cert(st, manuf_list[found_ca].cert))
        goto err;

    int tmp=BIO_reset(smud_bio);
    MUDC_LOG_INFO("BIO_reset <%d>\n", tmp);

    cms = d2i_CMS_bio(smud_bio, NULL);
    if (!cms) {
        MUDC_LOG_ERR("Error in d2i_CMS_bio\n");
        goto err;
    }

    if (!CMS_verify(cms, NULL, st, omud_bio, out, CMS_BINARY|CMS_DETACHED)) {
        MUDC_LOG_ERR("Verification Failure\n");
        goto err;
    }

    MUDC_LOG_INFO("Verification Successful\n");
    ret = 1;
err:
    if (!ret) {
        MUDC_LOG_ERR("Error Verifying Data");
        ERR_print_errors_fp(stdout);
    }
    if (p7) {
        PKCS7_free(p7);
    }
    CMS_ContentInfo_free(cms);
    X509_free(cacert);
    X509_STORE_free(st);
    BIO_free(out);
    BIO_free(smud_bio);
    BIO_free(omud_bio);
    return found_ca;
}


static bool update_policy_database(request_context *ctx, cJSON* parsed_json)
{
    bson_error_t error;
    bson_t *query=NULL, *update=NULL;
    char* acl_name=NULL;
    int index=0, vlan=0;
    cJSON* acl_json=NULL, *dacl=NULL;
    char *dacl_str=NULL;
    bool rc = true;

    if (ctx == NULL || parsed_json == NULL) {
        MUDC_LOG_ERR("invalid parameters");
        return false;
    }

    for (index=0;index < cJSON_GetArraySize(parsed_json); index++) {
        acl_json = cJSON_GetArrayItem(parsed_json, index);
        acl_name = GETSTR_JSONOBJ(acl_json, "DACL_Name");
        dacl = cJSON_GetObjectItem(acl_json, "DACL");
        dacl_str = cJSON_Print(dacl);
        if (ctx->mac_addr == NULL) {
            ctx->mac_addr = strdup("NA");
        }
        if (cJSON_GetObjectItem(acl_json, "VLAN")) {
            vlan = GETINT_JSONOBJ(acl_json, "VLAN");
            update = BCON_NEW( "$set", "{", 
                        "URI", BCON_UTF8(ctx->uri),
                        "DACL_Name", BCON_UTF8(acl_name),
                        "DACL", BCON_UTF8(dacl_str), "VLAN", BCON_INT32(vlan),"}");
        } else {
            update = BCON_NEW( "$set", "{", 
                        "URI", BCON_UTF8(ctx->uri),
                        "DACL_Name", BCON_UTF8(acl_name),
                        "DACL", BCON_UTF8(dacl_str),"}");
        }
        query =  BCON_NEW("DACL_Name", acl_name);
        if (!mongoc_collection_find_and_modify(policies_collection, query, NULL, update, NULL, false, true, false, NULL,&error)) {
            MUDC_LOG_ERR("mongoc find_and_modify failed: %s \n", error.message);
            rc = false;
        }
        bson_destroy(query);
        bson_destroy(update);
        free(dacl_str);
        if (!rc) {
            break;
        }
    }
    return(rc);
}

char *fetch_uri_from_macaddr(char *mac_addr)
{
    mongoc_cursor_t *cursor=NULL;
    bson_t *filter=NULL, *opts=NULL;
    const bson_t *doc=NULL;
    char *uri=NULL;
    char *found_str=NULL;
    cJSON *found_json=NULL;

    if (mac_addr == NULL) {
        MUDC_LOG_ERR("Invalid parameters");
        return NULL;
    }

    filter = BCON_NEW("MAC_Addr", BCON_UTF8(mac_addr));
    opts = BCON_NEW( "projection", "{", "URI", BCON_INT32(1), "}");
    cursor = mongoc_collection_find_with_opts (macaddr_collection, filter, 
	    				       opts, NULL);

    /*
     * Look for URI
     */
    while (mongoc_cursor_next (cursor, &doc)) {
        found_str = bson_as_json(doc, NULL);
        if (found_str!=NULL) {
            MUDC_LOG_INFO("found the fields <%s>\n", found_str);
            found_json = cJSON_Parse(found_str);
            if (!found_json) {
                MUDC_LOG_ERR("Error Before: [%s]\n", cJSON_GetErrorPtr());
            } else {
                char *tmp = GETSTR_JSONOBJ(found_json, "URI");
                if (tmp) {
    		    uri = strdup(tmp);
                }
                cJSON_Delete(found_json);
            }
            bson_free(found_str);
        } 
    } 

    mongoc_cursor_destroy (cursor);
    bson_destroy(filter);
    bson_destroy(opts);

    MUDC_LOG_INFO("============= Returning URI:%s\n", uri);

    return(uri);
}

int put_uri_into_macaddr(char *mac_addr, char *uri)
{
    bson_error_t error;
    bson_t *query=NULL, *update=NULL;

    /*
     * Verify that there really is a MAC address here. If not,
     * return "true" as it isn't an error -- there just isn't
     * anything to do.
     */
    if ((mac_addr == NULL) || !strcmp(mac_addr, "NA")) {
	return(true);
    }

    update = BCON_NEW( "$set", "{", 
	    	"URI", BCON_UTF8(uri), "}");

    query =  BCON_NEW("MAC_Addr", mac_addr);

    MUDC_LOG_ERR("Attempting to insert URI into MAC address record");
    if (!mongoc_collection_find_and_modify(macaddr_collection, query, NULL, update, NULL, false, true, false, NULL,&error)) {
        MUDC_LOG_ERR("mongoc find_and_modify failed: %s", error.message);
        return(false);
    }

    bson_destroy(query);
    bson_destroy(update);

    return(true);
}

static void send_masauri_response(struct mg_connection *nc, cJSON *response_json)
{
    int response_len=0;
    char* response_str=NULL;

    response_str = cJSON_Print(response_json);
    response_len = strlen(response_str);
    MUDC_LOG_INFO("Response <%s>\n", response_str);
    mg_send_head(nc, 200, response_len, "Content-Type: application/masauri");
    mg_printf(nc, "%.*s", response_len, response_str);
    nc->flags |= MG_F_SEND_AND_CLOSE;
    free(response_str);
}

static void send_response(struct mg_connection *nc, cJSON *parsed_json)
{
    int index=0, response_len=0, vlan=0;
    char *response_str=NULL;
    cJSON* acl_json=NULL,*response_json=NULL, *dacl_name=NULL;

    response_json = cJSON_CreateObject();
    if (nc == NULL) { // what about parsed_json?
        MUDC_LOG_ERR("invalid parameters");
        return;
    }

    cJSON_AddItemToObject(response_json, "Cisco-AVPair", 
	    		  dacl_name = cJSON_CreateArray());
    for (index=0;index < cJSON_GetArraySize(parsed_json); index++) {
        acl_json = cJSON_GetArrayItem(parsed_json, index);
        cJSON_AddItemToArray(dacl_name, 
		cJSON_Duplicate(cJSON_GetObjectItem(acl_json, "DACL_Name"), 
		true));
        vlan = GETINT_JSONOBJ(acl_json, "VLAN");
    }
    if (vlan) {
        cJSON_AddStringToObject(response_json, "Tunnel-Type", "VLAN");
        cJSON_AddStringToObject(response_json, "Tunnel-Media-Type", "IEEE-802");
        cJSON_AddNumberToObject(response_json, "Tunnel-Private-Group-Id", vlan);
    }
    response_str = cJSON_Print(response_json);
    response_len = strlen(response_str);
    MUDC_LOG_INFO("Response <%s> <%d>\n", response_str, response_len);
    mg_send_head(nc, 200, response_len, "Content-Type: application/aclname");
    mg_printf(nc, "%s", response_str);

    if (response_str) {
        free(response_str);
    }
    cJSON_Delete(response_json);
    nc->flags |= MG_F_SEND_AND_CLOSE;
}

bool get_mudfs_signed_uri (char *msg, char *uri, char *requri, int requri_len)
{
    cJSON *json=NULL;
    char *rq=NULL;

    //MUDC_LOG_INFO("\nget_mudfs_signed_uri(%s, %s)\n", msg, uri);

    if (!uri || !msg || !requri || requri_len == 0) {
        MUDC_LOG_ERR("Bad parameters\n");
        return false;
    }
    
    json = cJSON_Parse(msg);
    if (!json) {
	MUDC_LOG_ERR("Parsing of .json file failed\n");
        return false;
    }
    
    rq = GETSTR_JSONOBJ(json, "mud-signature");
    if (rq) {
        snprintf(requri, requri_len, "%s", rq);
    } else {
        snprintf(requri, requri_len, "%s.p7s", uri);
    }
    cJSON_Delete(json);
    return true;
}

static void free_request_context (request_context *ctx) 
{
    if (ctx == NULL) {
        return;
    }
    if (ctx->uri) {
        free(ctx->uri);
    }
    if (ctx->mac_addr) {
        free(ctx->mac_addr);
    }
    if (ctx->sess_id) {
        free(ctx->sess_id);
    }
    if (ctx->nas) {
        free(ctx->nas);
    }
    if (ctx->orig_mud) {
        free(ctx->orig_mud);
    }
    if (ctx->signed_mud) {
        free(ctx->signed_mud);
    }
    free(ctx);
}

void attempt_coa(sessions_info *sess)
{
    char coa_command[1024];

    MUDC_LOG_INFO("Checking if COA is required\n");
    if (sess->mac_addr != NULL && strcmp(sess->mac_addr, "NA")) {
        MUDC_LOG_INFO("COA could be performed for MAC Address <%s>\n", 
		      sess->mac_addr);
        if (sess->sessid == NULL) {
            MUDC_LOG_INFO("... but cannot do CoA: Session ID is NULL\n");
	} else if (sess->nas == NULL) {
	    MUDC_LOG_INFO("... but cannot do CoA: NAS is NULL\n");
	} else if (mudmgr_coa_pw == NULL) {
   	    MUDC_LOG_INFO("... but cannot do CoA: CoA password is not found\n");
	} else {
	    /* 
	     * system(3) blocks, which can cause problems if it takes
	     * too long. Other messages for the this session 
	     * (such as the an Access-Request) may block and we 
	     * falsely return an Acesss-Reject because the rest 
	     * module times out. So we avoid this by fork(2)ing off a 
	     * child proecess to do the CoA asynchronously.
	     *
	     * WARNING: Don't put any code here that updates the
	     * session database, or otherwise changes the state
	     * of the program.
	     */
	    MUDC_LOG_INFO("Initiating CoA for Acct-Session-Id: %s\n", 
		          sess->sessid);
	    if (fork() == 0) { /* child */
                sprintf(coa_command, "echo 'Acct-Session-Id=%s,Message-Authenticator=0x00,Cisco-AVPair=\"subscriber:command=reauthenticate\"' |  radclient -s %s:1700 coa %s", 
			sess->sessid, sess->nas, mudmgr_coa_pw);
                MUDC_LOG_INFO("COA command: %s\n", coa_command);
                int sysret = system(coa_command);
                MUDC_LOG_INFO("sysret: %d", sysret);
		exit(0);
            }
        }
    }
}

/* MUD File Server client handler */
static void mudfs_handler(struct mg_connection *nc, int ev, void *ev_data) 
{
    int ret=0;
    cJSON *parsed_json=NULL, *masa_json=NULL;
    unsigned int i=0;
    bool found=false;
    int connect_status;

    struct http_message *hm = (struct http_message *) ev_data;
    request_context *ctx = (request_context*)nc->user_data;

    if (nc == NULL) { 
        MUDC_LOG_ERR("mudfs_handler: invalid parameters");
        return;
    }

    switch (ev) {
        case MG_EV_CONNECT:
            connect_status = *(int *)ev_data;
            if (connect_status == 0) {
                MUDC_LOG_INFO("mudFS connection successful");
            } else {
                MUDC_LOG_ERR("mudFS connection failed");
                if (ctx != NULL) {
                    send_error_for_context(ctx, 404, "Connect error");
                    free_request_context(ctx);
                    nc->user_data = NULL;
                }
                nc->flags |= MG_F_CLOSE_IMMEDIATELY;
            }
            mg_set_timer(nc, 0); // clear connect timer 
            break;
        case MG_EV_TIMER:
            MUDC_LOG_ERR("Connection timed out");
            if (ctx != NULL) {
                send_error_for_context(ctx, 404, "Connect error");
                free_request_context(ctx);
            }
            nc->flags |= MG_F_CLOSE_IMMEDIATELY;
            nc->user_data = NULL;
            break;
        case MG_EV_HTTP_REPLY:
            if (hm == NULL || ctx == NULL) { 
                MUDC_LOG_ERR("mudfs_handler: invalid parameters");
                if (ctx != NULL) {
                    send_error_for_context(ctx, 500, "internal error FS");
                    free_request_context(ctx);
                }
                return;
            }

            MUDC_LOG_INFO("Got reply:\n%.*s\n", (int) hm->body.len, hm->body.p);
            MUDC_LOG_INFO("\nctx->uri: %s\n", ctx->uri);

            MUDC_LOG_INFO("response code: %d", hm->resp_code);
            if (hm->resp_code != 200) {
                MUDC_LOG_ERR("Error response from FS: %d", hm->resp_code);
                MUDC_LOG_ERR("message: %.*s", hm->body.len, hm->body.p);
                send_error_for_context(ctx, 404, "error from FS\n");
                free_request_context(ctx);
                MUDC_LOG_INFO("exit");
                return;
            }

            for (i=0; i<hm->body.len-1; i++) {
                if (hm->body.p[i] == '\n' && hm->body.p[i+1] == '\n') {
                    if ((hm->body.len - i) > 2) {
                        found = true;
                        i+=2;
                        break;
                    }
                }
            }
            if (!found) {
                MUDC_LOG_ERR("Failed to strip off MIME header");
                send_error_for_context(ctx, 500, "error from FS\n");
                free_request_context(ctx);
                return;
            }

            
            if (ctx->status == REQUEST_MUD_JSON_FILE) {
                char requri[255];
                memset(requri, 0, sizeof(requri));

                ctx->orig_mud = calloc((int)hm->body.len, sizeof(char));
                memcpy(ctx->orig_mud, hm->body.p+i, (int)hm->body.len-i);
                ctx->orig_mud_len = hm->body.len-i;
                if (!get_mudfs_signed_uri(ctx->orig_mud, ctx->uri, 
                        requri, sizeof(requri)) ||
                        strlen(requri) == 0) {
                    MUDC_LOG_ERR("Unable to request signature file");
                    send_error_for_context(ctx, 500, "error from FS\n");
                } else {
		    // send_client_response value ignored here
                    send_mudfs_request(nc, ctx->uri, requri, ctx->mac_addr, 
				       ctx->nas, ctx->sess_id, 0, true); 
                }
            } else if (ctx->status == REQUEST_MUD_SIGNATURE_FILE) {
                ctx->signed_mud = calloc((int)hm->body.len, sizeof(char));
                memcpy(ctx->signed_mud, hm->body.p+i, (int)hm->body.len-i);
                ctx->signed_mud_len = hm->body.len-i;
                ret = verify_mud_content(ctx->signed_mud, ctx->signed_mud_len, ctx->orig_mud, ctx->orig_mud_len);
                if (ret != -1) {
                    MUDC_LOG_INFO("Verification successful. Manufacturer Index <%d>\n", ret);
                    if (ctx->masaurirequest == 1) {
                        masa_json = extract_masa_uri(ctx, (char*)ctx->orig_mud);
                        if (masa_json == NULL) {
                            MUDC_LOG_ERR("Error in extracting MASA uri");
                            send_error_for_context(ctx, 500, "missing masa uri");
                        } else {
                            send_masauri_response(ctx->in, masa_json);
                            cJSON_Delete(masa_json);
                        }
                    } else {
                        parsed_json = parse_mud_content(ctx, ret);
                        if (!parsed_json) {
                            MUDC_LOG_ERR("Error in parsing MUD file\n");
                            send_error_for_context(ctx, 500, "error from FS\n");
                        } else {
			    /*
			     * Update the MAC address and policy datbases with 
			     * the newly downloaded and accepted MUD URI.
			     *
			     * Then, if we have a MAC address update the NAS
			     * that has the RADIUS session by sending them a
			     * Change of Authorization (COA), which causes 
			     * them to re-authenticate the MAC address and in
			     * the process they'll be given the policies.
			     * (If a COA isn't done, the NAS won't know to come
			     * back and fetch them, and the device will not
			     * have the correct access.)
			     */
			    if (!put_uri_into_macaddr(ctx->mac_addr, ctx->uri)) {
                                MUDC_LOG_INFO("MAC address database is NOT updated with its URL\n");
			    }
                            if(update_policy_database(ctx, parsed_json)) {
				sessions_info *sess = NULL;

                                MUDC_LOG_INFO("Policy database is updated successfully\n");
                                if (ctx->send_client_response == false) {
                                    goto jump; 
                                }
                                send_response(ctx->in, parsed_json);
    				start_session(nc, ctx->uri, ctx->mac_addr, 
					      ctx->nas, ctx->sess_id);

                                /*
				 * Check if COA is required and has sufficient 
				 * info 
				 */
				sess = find_session(ctx->mac_addr);
				if (sess) {
				    attempt_coa(sess);
				} else {
				    MUDC_LOG_ERR("Could not do CoA: no session found for MAC address %s", ctx->mac_addr);
				}
                            } else {
                                MUDC_LOG_ERR("Database update failed\n");
                                send_error_for_context(ctx, 500, 
					               "internal error\n");
                            }
                        }
                    jump:
                        cJSON_Delete(parsed_json);
                    }
                } else {
                    MUDC_LOG_ERR("Verification failed\n");
                    send_error_for_context(ctx, 500, "verification failed\n");
                }
                free_request_context(ctx);
            }
            break;
        case MG_EV_CLOSE:
            break;
        default:
            break;
    }
}

static void send_mudfs_request(struct mg_connection *nc, const char *base_uri, 
                               const char *requested_uri, 
                               const char* mac_addr, 
                               const char* nas, const char* sess_id, int flag,
                               bool send_client_response) 
{
    struct mg_connection *mudfs_conn=NULL;
    struct mg_connect_opts connect_opts;
    int manuf_idx=0;
    request_context *ctx=NULL;
    char requri[255], tmp_uri[255];
    char *extra_headers=NULL;

    if (nc == NULL || base_uri == NULL) {
        MUDC_LOG_ERR("invalid parameters");
        return;
    }
    
    memset(requri, 0, sizeof(requri));
    memset(tmp_uri, 0, sizeof(tmp_uri));

    if (flag == 1 || flag == 2) {
        /*request for json file */
        ctx = (request_context*)calloc(1, sizeof(request_context));
        ctx->in = nc;
        ctx->uri = strdup(base_uri);
        if (mac_addr) {
            ctx->mac_addr = strdup(mac_addr); 
        }
        if (nas) {
           ctx->nas = strdup(nas);
        }
        if (sess_id) {
            ctx->sess_id = strdup(sess_id);
        }
        ctx->status = REQUEST_MUD_JSON_FILE;
        ctx->masaurirequest = (flag == 2) ? 1 : 0;
        ctx->send_client_response = send_client_response;
        snprintf(requri, sizeof(requri), "%s", requested_uri);
        extra_headers = "Content-Type: application/mud+json\r\n" 
                        "Accept: application/mud+json\r\n"
                        "Accept-Language: en\r\n"
                        "User-Agent: prototype-mud-manager\r\n";
    } else {
        ctx = (request_context*)nc->user_data;
        ctx->status = REQUEST_MUD_SIGNATURE_FILE;
        snprintf(requri, sizeof(requri), "%s", requested_uri);
        extra_headers = "Content-Type: application/mud+json\r\n" 
                        "Accept: application/pkcs7-signed\r\n"
                        "Accept-Language: en\r\n"
                        "User-Agent: prototype-mud-manager\r\n";
    }

    manuf_idx = find_manufacturer(requri);
    if (manuf_idx == -1) {
        MUDC_LOG_ERR("Manufacturer not found: URI %s\n", requri);
        goto err;
    }

    if (manuf_list[manuf_idx].https_port != NULL) {
        char *tmp = strstr(requri, manuf_list[manuf_idx].authority);

        strncpy(tmp_uri, requri, tmp - requri);
        tmp_uri[tmp-requri] = '\0';

        sprintf(tmp_uri+(tmp-requri),"%s:%s%s", manuf_list[manuf_idx].authority, manuf_list[manuf_idx].https_port, tmp+strlen(manuf_list[manuf_idx].authority));
        MUDC_LOG_INFO("NEW URI <%s> \n", tmp_uri);
        strncpy(requri, tmp_uri, sizeof(requri));
    }

    MUDC_LOG_INFO("Request URI <%s> <%s>\n", requri, manuf_list[manuf_idx].certfile);
    memset(&connect_opts, 0, sizeof(connect_opts));
    connect_opts.ssl_ca_cert = manuf_list[manuf_idx].certfile;
    connect_opts.ssl_server_name ="*";
    mudfs_conn = mg_connect_http_opt(nc->mgr, mudfs_handler, connect_opts, requri, extra_headers, NULL);
    if (mudfs_conn == NULL) {
        goto err;
    } else {
        mudfs_conn->user_data = (void*)ctx;
        mg_set_timer(mudfs_conn, mg_time() + 5);
        MUDC_LOG_INFO("sending request <%s>\n", requri);
        return;
    }

err:
    MUDC_LOG_ERR("mudfs_conn failed\n");
    send_error_for_context(ctx, 404, "mudfs connection failed\n");
    free_request_context(ctx);
}

/*
 * This code responds to a REST API of /getaclpolicy.
 */
static void handle_ace_call(struct mg_connection *nc, struct http_message *hm) 
{
    bson_t *filter=NULL;
    const bson_t *record=NULL;
    mongoc_cursor_t *cursor=NULL;
    char *found_str=NULL, *response_str=NULL, *dacl_str = NULL, *acl_name=NULL;
    cJSON *json=NULL, *jsonResponse=NULL, *dacl_req=NULL, *dacl=NULL; 
    cJSON *dacl_list;
    int response_len=0, index=0;
    char policy_name[64];

    if (nc == NULL || hm == NULL || strlen(hm->body.p) == 0) {
        MUDC_LOG_ERR("invalid parameters\n");
        return;
    }

    /*
     * Find the ACLs with the requested name.
     * 
     * NOTE: The database should really have just the base ACL name,
     *       and here we lookup the base ACL name and then give it to
     *       the ACL type specific code (e.g., CISCO_DACL) to expand the name
     *       and do all of the ACL type processsing in the appropriate file.
     */
    switch (acl_response) {
	case CISCO_DACL:
    	    dacl_req = cJSON_Parse((char*)hm->body.p);
    	    acl_name = GETSTR_JSONOBJ(dacl_req, "ACL_NAME");
    	    sprintf(policy_name, "%sCiscoSecure-Defined-ACL=%s", 
		    acl_list_prefix, acl_name); 
    	    MUDC_LOG_INFO("ACL Name <%s>\n", acl_name);

    	    filter = BCON_NEW("DACL_Name", BCON_UTF8(policy_name));
    	    cursor = mongoc_collection_find_with_opts(policies_collection, 
		    	filter, NULL, NULL);

    	    jsonResponse = cJSON_CreateObject();
    	    cJSON_AddItemToObject(jsonResponse, "User-Name", 
			      	  cJSON_CreateString(acl_name));
    	    cJSON_AddItemToObject(jsonResponse, "Cisco-AVPair", 
			          dacl_list = cJSON_CreateArray());
	    break;
	default:
	    MUDC_LOG_ERR("Unknown ACL type: %d\n", acl_response);
	    dacl_list = NULL;
	    break;
    }
	    
    MUDC_LOG_INFO("Create Array \n");
    while (mongoc_cursor_next(cursor, &record)) {
        found_str = bson_as_json(record, NULL);
        if (found_str!=NULL) {
            MUDC_LOG_INFO("found the record <%s>\n", found_str);
            json = cJSON_Parse(found_str);
            if (!json) {
                MUDC_LOG_ERR("Error Before: [%s]\n", cJSON_GetErrorPtr());
            } else {
                int size = 0;
                dacl_str = GETSTR_JSONOBJ(json,"DACL");
                dacl = cJSON_Parse(dacl_str);
                size = cJSON_GetArraySize(dacl);
                for (index=0;index < size; index++) {
                    cJSON_AddItemToArray(dacl_list, 
			    cJSON_Duplicate(cJSON_GetArrayItem(dacl,index), 
			    true));
                }
                cJSON_Delete(json);
                cJSON_Delete(dacl);
            }
            bson_free(found_str);
        }
    }
    if (cJSON_GetArraySize(dacl_list) <= 0) {
        send_error_result(nc, 500, "Internal Error");
        goto err;
    }
    response_str = cJSON_Print(jsonResponse);
    MUDC_LOG_INFO("\nResponse: %s\n", response_str);
    response_len = strlen(response_str);
    mg_send_head(nc, 200, response_len, "Content-Type: application/dacl");
    mg_printf(nc, "%.*s", response_len, response_str);
    nc->flags |= MG_F_SEND_AND_CLOSE;
    free(response_str);
err:
    cJSON_Delete(jsonResponse);
    cJSON_Delete(dacl_req);
    mongoc_cursor_destroy(cursor);
    bson_destroy(filter);
}

static void handle_coa_alert(struct mg_connection *nc, struct http_message *hm) 
{
    char *mac=NULL;
    char coa_command[255];
    cJSON *request_json=NULL;
    sessions_info *sess=NULL;
    int sysret=0;

    MUDC_LOG_INFO("Received COA Alert\n");
    
    if (nc == NULL || hm == NULL || strlen(hm->body.p) == 0) {
        MUDC_LOG_ERR("invalid parameters\n");
        return;
    }


    request_json = cJSON_Parse((char*)hm->body.p);
    if (request_json == NULL) {
        MUDC_LOG_ERR("unable to parse message");
        send_error_result(nc, 500, "bad input");
        return;
    }

    mac = GETSTR_JSONOBJ(request_json, "MAC_ADDR"); 
    if (mac == NULL) {
        MUDC_LOG_ERR("bad input");
        send_error_result(nc, 500, "bad input");
        cJSON_Delete(request_json);
	return;
    }

    if (mac[0] == '\0') {
        MUDC_LOG_ERR("bad input");
        send_error_result(nc, 500, "bad input");
        cJSON_Delete(request_json);
	return;
    } else {
    	MUDC_LOG_INFO("Attempting to initiate CoA Alert for MAC Address: <%s>\n", mac);
        sess = find_session(mac);    
        if (sess ==  NULL) {
	    MUDC_LOG_INFO("... but cannot not find the session\n");
	} else if (sess->sessid == NULL) {
	    MUDC_LOG_INFO("... but Session ID is NULL\n");
	} else if (sess->nas == NULL) {
   	    MUDC_LOG_INFO("... but NAS is NULL\n");
	} else if (mudmgr_coa_pw == NULL) {
   	    MUDC_LOG_INFO("... but no CoA password is not found\n");
	} else {
    	    MUDC_LOG_INFO("Initiating CoA Alert\n");
	    /*
	     * Note: Because we need to remove the session, we should not do a 
	     * fork() here. Or if a fork() is needed, then remove_session 
	     * should be called first, after extracting whatever information 
	     * that the CoA needs.
	     */
            sprintf(coa_command, "echo 'Acct-Session-Id=%s,Message-Authenticator=0x00,Cisco-AVPair=\"subscriber:command=reauthenticate\"' |  radclient -s %s:1700 disconnect %s", sess->sessid, sess->nas, mudmgr_coa_pw);
            MUDC_LOG_INFO("COA command: %s\n", coa_command);
            sysret = system(coa_command);
            MUDC_LOG_INFO("sysret: %d", sysret);
	    remove_session(mac);
        }
	mg_send_response_line(nc, 200, "Content-Type: application/alertcoa");
    	nc->flags |= MG_F_SEND_AND_CLOSE;
    }
    cJSON_Delete(request_json);
}

static bool validate_muduri (struct mg_connection *nc, char *uri) 
{
    char *buf = NULL;
    char *b = NULL;
    char *ip = NULL;
    char *filename = NULL;

    if (nc == NULL) {
        MUDC_LOG_ERR("invalid parameters");
        // no context to send notification
        return false;
    }

MUDC_LOG_INFO("uri: %s", uri);

    if ((uri == NULL) || (uri[0] == '\0')) {
        MUDC_LOG_ERR("missing uri");
        send_error_result(nc, 500, "bad input");
        return false;
    }

    if (strncmp(uri, "https://", 8)) {
        MUDC_LOG_ERR("URI must be HTTPS");
        send_error_result(nc, 401, "invalid uri");
        return false;
    } 

    if (uri[8] == '/') {
        MUDC_LOG_ERR("URI missing host");
        send_error_result(nc, 404, "invalid uri");
        return false;
    }

    buf = strdup(uri);

    b = buf + 8;
    ip = strtok(b, "/");
    filename = strtok(NULL, "");

MUDC_LOG_INFO("ip: %s, filename: %s", ip, filename);

    if (ip == NULL || strlen(ip) <= 0 || filename == NULL || strlen(filename) <= 0) {
        MUDC_LOG_ERR("invalid uri");
        send_error_result(nc, 404, "bad input");
        free(buf);
        return false;
    }

    free(buf);
    return true;
}

/*
 * This code responds to a REST API of /getmasauri.
 */
static void handle_get_masa_uri(struct mg_connection *nc, struct http_message *hm) 
{
    char *uri=NULL;
    cJSON *request_json=NULL;
    char requri[255];

    if (nc == NULL || hm == NULL || strlen(hm->body.p) == 0) {
        MUDC_LOG_ERR("handle_get_masa_uri: invalid parameters\n");
        return;
    }

    memset(requri, 0, sizeof(requri)); // make valgrind happy

    request_json = cJSON_Parse((char*)hm->body.p);
    uri = GETSTR_JSONOBJ(request_json, "MUD_URI"); 

    if (validate_muduri(nc, uri) == false) {
        // function sends error-specific responses
    } else {
    	MUDC_LOG_INFO("Got URI <%s>\n", uri);
        snprintf(requri, sizeof(requri), "%s.json", uri);
        send_mudfs_request(nc, uri, requri, NULL, NULL, NULL, 2, true);
    }
    cJSON_Delete(request_json);
}

/*
 * This code responds to a REST API of /getaclname.
 *
 * We're looking for one or more ACL names to return. We might be given a
 * MAC Address and/or a MUD URL as the key for the lookup.
 * MAC Address:
 * -- Look up the MAC Address in the macaddress table. If there, look for
 *    a set of ACL names and return them.
 * -- Otherwise resort to looking up by MUD URL (as below).
 * -- But if no MUD URL was provided with the MAC address, return 
 *    without policies.
 * MUD URL
 * -- Look for entries in the policies table for this MUD URL. If there,
 *    return them
 * -- If not there, fetch the mud file and validate it, then create 
 *    policies, install them, and return their names. Note the the
 *    fetched MUD file is evaluated in a callback function, not here.
 *
 * Other args includes the Session ID and NAS. These are used in case
 *   a COA is needed.
 */
static void handle_get_aclname(struct mg_connection *nc, struct http_message *hm) 
{
    char *uri=NULL, *mac_addr=NULL, *nas=NULL, *session_id=NULL;
    cJSON *request_json=NULL;
    char *requri=NULL;
    int foundacls = 0;
    char *found_uri=NULL;
    int can_store_valid_uri = 0;
    int requri_len= 0;
    bool cache_expired = false;

    if (nc == NULL || hm == NULL || strlen(hm->body.p) == 0) {
        MUDC_LOG_ERR("invalid parameters");
        return;
    }

    MUDC_LOG_INFO("http message: %.*s", hm->body.len, hm->body.p);

    request_json = cJSON_Parse((char*)hm->body.p);
    if (request_json == NULL) {
        MUDC_LOG_INFO("unable to decode message");
        return; 
    }
    uri = GETSTR_JSONOBJ(request_json, "MUD_URI"); 
    mac_addr = GETSTR_JSONOBJ(request_json, "MAC_ADDR");
    nas = GETSTR_JSONOBJ(request_json, "NAS");
    session_id = GETSTR_JSONOBJ(request_json, "SESS_ID");

    /*
     * We need one or the other to proceed.
     */
    if ((uri == NULL) && (mac_addr == NULL)) {
        send_error_result(nc, 500, "bad input");
	return;
    }

    /*
     * Check for policies by MAC address first.
     */
    if (mac_addr != NULL) {
        MUDC_LOG_INFO("Mac address <%s> \n", mac_addr);
	/* 
	 * Look for URI associated with the MAC address.
	 */
	found_uri = fetch_uri_from_macaddr(mac_addr);
	if (found_uri) {
	    MUDC_LOG_INFO("Found URI %s for MAC address %s\n", found_uri, 
		    	  mac_addr);
	    if (uri == NULL) {
	    	/*
	     	* TBD: Check if found_uri != uri and issue a warning.
	     	*/
	    	uri = found_uri;
	    }
	} else {
	    MUDC_LOG_INFO("No URL found in macaddr db for MAC address %s\n", 
		    	  mac_addr);
	    /*
	     * If we later find a valid URI associated with this
	     * MAC address, we can stuff it away in the
	     * macaddr database.
	     *
	     * We also should add a session to the sessions database too if
	     * it turns out that we find a URL for this MAC address.
	     */
	    can_store_valid_uri = 1;
	}
    }

    /*
     * uri was either passed in from the message, or we discovered it
     * above. But if it wasn't found in either palce, we're done.
     */
    if (uri == NULL) {
	/*
	 * We don't have a either a uri from the message, or a uri
	 * from the macaddr collection, so we have to return nothing.
	 *
         * return success so that FR does not reject auth
	 *
	 * TBD: Put in a function.
	 */
        int ret = 204;
        char *reply_type = "Content-Type: application/aclname";
        char *response_str = "{\"MSG\":\"No ACL for this device MAC Address\"}";
        int response_len = strlen(response_str);
        mg_send_head(nc, ret, response_len, reply_type);
        mg_printf(nc, "%.*s", response_len, response_str);

        MUDC_LOG_INFO("No URL found for Mac address <%s> \n", mac_addr);
        MUDC_LOG_INFO("    and no MUD URL was provided.");
        nc->flags |= MG_F_SEND_AND_CLOSE;
        goto end;
    }

    if (validate_muduri(nc, uri) == false) {
        // function sends error-specific responses to client
        goto err;
    } else {
    	MUDC_LOG_INFO("Got URL from message <%s>\n", uri);
    }

    /*
     * Look to see if policies have alrady been generated for this MUD URL.
     * If they are found, put them into the return buffer.
     */

    foundacls = query_policies_by_uri(nc, uri, false, &cache_expired);
    if (foundacls == true) {
    	MUDC_LOG_INFO("Got ACLs from the MUD URL\n");
	if (can_store_valid_uri == 1) {
	    (void) put_uri_into_macaddr(mac_addr, uri);
	}
	start_session(nc, uri, mac_addr, nas, session_id);

	/*
	 * Now, if we stored a URI for this MAC Address, we shoud also send 
	 * a COA if possible. But first, we have to find the session context 
	 * that was just created.
	 */
	if (can_store_valid_uri) {
    	    sessions_info *sess=NULL;

	    sess = find_session(mac_addr);
	    if (sess) {
	    	attempt_coa(sess);
	    } else {
	    	MUDC_LOG_ERR("Could not do CoA for MAC addr %s", mac_addr);
	    }
	}
        if (cache_expired == false) {
            goto end;
        }
        MUDC_LOG_INFO("Cache expired");
    }

    /*
     * Now check to see if the MUD URL happens to be in the database,
     * but no policies have been generated yet.
     *
     * Can that happen?!?
     *
     * TBD
     */

    /*
     * We have a URL, but no polcies. We need to fetch the URL
     * from the MUD file server, generate policies, and return them.
     * 
     * The MUD URL needs to be made into a "filename" for the MUD
     * file server. Allocate room for URI, ".json", and optional 
     * port (":nnnn")
     */
    requri_len = strlen(uri) + 10;
    requri = (char *)calloc(1, requri_len);
    snprintf(requri, requri_len, "%s.json", uri);
    send_mudfs_request(nc, uri, requri, mac_addr, nas, session_id, 1, 
                       cache_expired ? false:true);

err:
end:
    if (found_uri != NULL) {
        free(found_uri);
    }
    if (requri != NULL) {
	free(requri);
    }
    cJSON_Delete(request_json);
}

/* Server handler */
static void ev_handler(struct mg_connection *nc, int ev, void *ev_data) 
{
    if (nc == NULL) {
        MUDC_LOG_ERR("Invalid parameters");
        return;
    }

    struct http_message *hm = (struct http_message *) ev_data;

    switch (ev) {
        case MG_EV_HTTP_REQUEST:
            if (hm == NULL) {
                MUDC_LOG_ERR("Invalid parameters");
                return;
            }
            MUDC_LOG_INFO("==================");
            MUDC_LOG_INFO("Got HTTP request\n");
            if (mg_vcmp(&hm->uri, "/getaclname") == 0) {
                handle_get_aclname(nc, hm); 
            } else if (mg_vcmp(&hm->uri, "/getaclpolicy") == 0) {
                handle_ace_call(nc, hm);
            } else if (mg_vcmp(&hm->uri, "/getmasauri") == 0) {
                handle_get_masa_uri(nc, hm);
            } else if (mg_vcmp(&hm->uri, "/alertcoa") == 0) {
                handle_coa_alert(nc, hm);
            } else {
                mg_serve_http(nc, hm, s_http_server_opts); /* Serve static content */
            }
            break;
        case MG_EV_CLOSE:
            break;
        default:
            break;
    }
}

void initialize_MongoDB() 
{
    mongoc_init();
    client = mongoc_client_new (mongoDb_uristr);
    if (!client) {
        MUDC_LOG_ERR("Failed to parse URI.\n");
        return;
    }
    mongoc_client_set_error_api (client, 2);
    policies_collection = mongoc_client_get_collection (client, mongoDb_name, mongoDb_policies_collection);
    mudfile_collection = mongoc_client_get_collection (client, mongoDb_name, mongoDb_mudfile_coll);
    macaddr_collection = mongoc_client_get_collection (client, mongoDb_name, mongoDb_macaddr_coll);
}


int main(int argc, char *argv[]) 
{
    struct mg_mgr mgr;
    struct mg_connection *nc=NULL;
    struct mg_bind_opts bind_opts;
    int i=0;
    char *cp=NULL,*port=NULL;
    int opt;
    char *default_config_filename = "/usr/local/etc/mud_manager_conf.json";
    char *config_filename = NULL;


    signal(SIGCHLD, SIG_IGN);

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    while ((opt = getopt(argc, argv, "f:l:")) != -1) {
	switch (opt) {
	case 'f':
	    config_filename = optarg;
	    break;
	case 'l':
	    log_level = atoi(optarg);
	    if (log_level > LOG_LEVEL_ALL) {
		fprintf(stderr, "Invalid log level. Must be <= %d\n", 
				LOG_LEVEL_ALL);
		return 1;
	    }
	    break;
	default:
	    fprintf(stderr, 
		    "Usage: %s [ -f config_filename ] -l [log_level]\n", 
		    argv[0]);
	    return 1;
	}
    }

    if (config_filename == NULL) {
	config_filename = default_config_filename;
    }
    MUDC_LOG_INFO("Using configuration file: %s\n", config_filename);
    if (read_mudmgr_config(config_filename) == -1) {
        MUDC_LOG_ERR("Error reading config file\n");
        return 1;
    }
    mg_mgr_init(&mgr, NULL);

    if (strcmp(mudmgr_server, "https") == 0 ) {
        MUDC_LOG_INFO("Cert %s, %s,  %s\n", mudmgr_cert, mudmgr_key, mudmgr_CAcert);
        memset (&bind_opts, 0, sizeof(bind_opts));

        bind_opts.ssl_cert = mudmgr_cert;
        bind_opts.ssl_key = mudmgr_key;
        bind_opts.ssl_ca_cert = mudmgr_CAcert;
        bind_opts.ssl_cipher_suites = "ALL:!aNULL:!eNULL:!SSLv2:!EXPORT:!SRP";

        nc = mg_bind_opt(&mgr, s_https_port, ev_handler, bind_opts);
        port = (char*)s_https_port;
    } else {
        nc = mg_bind(&mgr, s_http_port, ev_handler);
        port = (char*)s_http_port;
    }

    if (!nc) {
        MUDC_LOG_ERR("Bind failed.\n");
        return 1;
    }


    mg_set_protocol_http_websocket(nc);
    s_http_server_opts.document_root = ".";
    s_http_server_opts.enable_directory_listing = "yes";

    initialize_MongoDB();

    /* Use current binary directory as document root */
    if (argc > 0 && ((cp = strrchr(argv[0], '/')) != NULL ||
               (cp = strrchr(argv[0], '/')) != NULL)) {
        *cp = '\0';
        s_http_server_opts.document_root = argv[0];
    }

    /* Process command line options to customize HTTP server */
    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-D") == 0 && i + 1 < argc) {
            mgr.hexdump_file = argv[++i];
        } else if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
            s_http_port = argv[++i];
        }
    }

    MUDC_LOG_INFO("Starting RESTful server on port %s\n", port);
    for (;;) {
     mg_mgr_poll(&mgr, 1000);
    }
    mg_mgr_free(&mgr);
    mongoc_collection_destroy (policies_collection);
    mongoc_collection_destroy (mudfile_collection);
    mongoc_collection_destroy (macaddr_collection);
    mongoc_client_destroy (client);
    mongoc_cleanup ();
    return 0;
}
