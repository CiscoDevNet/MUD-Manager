/*
 * Copyright (c) 2017-2019 Cisco and/or its affiliates.
 * All rights reserved.
 */

#ifndef _MUD_MANAGER_H

#include <signal.h>
#include <civetweb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>
#include <openssl/asn1.h>
#include <openssl/cms.h>
#include <openssl/pem.h>
#include <openssl/pkcs7.h>
#include <openssl/ssl.h>
#include "openssl/dh.h"
#include "openssl/ec.h"
#include "openssl/evp.h"
#include "openssl/ecdsa.h"

#pragma GCC diagnostic push // suppress specific warning from 3rd-party code
#pragma GCC diagnostic ignored "-Wexpansion-to-defined"
#include <mongoc.h>
#pragma GCC diagnostic pop
#include <cJSON.h>
#include <curl/curl.h>
#include "acl.h"
#include "log.h"
#include "sessions.h"
#include "acl_types.h"
#include "mud_fs_client.h"

#define DACL_INGRESS_EGRESS 0
#define DACL_INGRESS_ONLY 1
#define MAX_BUF 4096
#define MAX_ACL_STATEMENTS 50
#define INITIAL_ACE_STATEMENTS 50
#define MAX_ACE_STATEMENTS 300

#define FROM_DEVICE 0
#define TO_DEVICE 1

#define SRCPORT 1
#define DSTPORT 2

#define MAXREQURI 255


#define IS_AUTHORITY 0
#define IS_URL 1


typedef struct _vlan_info {
  int vlan;
  char *mud_url;
  char *v4_nw;
  char *v6_nw;
} vlan_info;

typedef struct _addrlist {
  char *address;
  struct _addrlist *next;
} addrlist;

typedef struct _request_context {
    struct mg_connection *in;
    char *uri;
    char *mac_addr;
    char *sess_id;
    char *nas;
    char *signed_mud;
    int signed_mud_len;
    char *orig_mud;
    int orig_mud_len;
    int masaurirequest;
    bool send_client_response;
    bool needs_mycontroller;
} request_context;

typedef struct _manufacturer_list {
    char* authority;
    char* uri;
    char* https_port;
    char* certfile;
    char* web_certfile;
    X509 *cert;
    X509 *web_cert;
    int vlan;
    char* vlan_nw_v4;
    char* vlan_nw_v6;
    char* my_ctrl_v4;
    char* my_ctrl_v6;
    char* local_nw_v4;
    char* local_nw_v6;
} manufacturer_list;

#define _MUD_MANAGER_H 1
#endif	/* _MUD_MANAGER_H */
