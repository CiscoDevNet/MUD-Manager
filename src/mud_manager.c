/*
 * Copyright (c) 2017-2019 Cisco and/or its affiliates.
 * All rights reserved.
 */
#include "mud_manager.h"

static const char *s_http_port = "8000";
static const char *s_https_port = "8443s";
static const char *default_dbname = "mud_manager";
static const char *default_policies_coll_name = "mud_policies";
static const char *default_mudfile_coll_name = "mudfile";
static const char *default_macaddr_coll_name = "macaddr";
static const char *mongoDb_vlan_coll="vlans";
static const char *default_uri = "mongodb://127.0.0.1:27017";
//static struct mg_serve_http_opts s_http_server_opts;
static struct mg_context *mg_server_ctx=NULL;

static const char *mudmgr_cert=NULL;
static const char *mudmgr_CAcert=NULL;
static const char *mudmgr_key=NULL;
static const char *mudmgr_server=NULL;
static const char *mudmgr_coa_pw=NULL;
static char *default_localv4=NULL;
static char *default_localv6=NULL;
static int default_vlan=0;
static int manager_version=0;
static int acl_list_type = INGRESS_EGRESS_ACLS;
static enum acl_policy_type acl_type = CISCO_DACL;
static mongoc_client_t *client=NULL;
static mongoc_collection_t *mudfile_collection=NULL;
static mongoc_collection_t *macaddr_collection=NULL;
static mongoc_collection_t *vlan_collection=NULL;

// referenced externally
mongoc_collection_t *policies_collection=NULL;
const char *acl_list_prefix = NULL;


// used externally
cJSON *defacl_json=NULL;
cJSON *defacl_v6_json=NULL;

// static
static cJSON *config_json=NULL;
static cJSON *dnsmap_json=NULL;
static cJSON *ctrlmap_json=NULL;
static cJSON *dnsmap_v6_json=NULL;
static cJSON *ctrlmap_v6_json=NULL;
#define MAX_MANUF 10
static manufacturer_list manuf_list[MAX_MANUF];
static vlan_info vlan_list[MAX_MANUF];	/* these two 10s go together */
static int num_vlans=0;
static char *mongoDb_uristr=NULL, *mongoDb_policies_collection=NULL, *mongoDb_name=NULL;
static char *mongoDb_mudfile_coll=NULL;
static char *mongoDb_macaddr_coll=NULL;
static int num_manu = 0;

static bool mudc_construct_head(struct mg_connection *nc, int status_code,
                                int content_len, const char *extra_headers)
{
    char *buf = NULL;
MUDC_LOG_INFO("status_code: %d, content_len: %d, extra_headers: %s",
status_code, content_len, extra_headers);

    buf = calloc(200 + (extra_headers?strlen(extra_headers):0), sizeof(char));
    if (!buf) {
        MUDC_LOG_ERR("malloc failed");
        return false;
    }

    sprintf(buf, "HTTP/1.1 %d %s\r\n", status_code,
              mg_get_response_code_text(nc, status_code));
    if (extra_headers) {
        sprintf(&buf[strlen(buf)], "%.*s\r\n", (int)strlen(extra_headers), extra_headers);
    }
    if (content_len >= 0) {
        sprintf(&buf[strlen(buf)], "Content-Length: %d\r\n", content_len);
    }
    sprintf(&buf[strlen(buf)], "\r\n");
    MUDC_LOG_INFO("HTTP header: %s", buf);
    mg_printf(nc, "%s", buf);
    free(buf);

    return true;
}

static void send_error_result(struct mg_connection *nc, int status, const char *msg)
{
    int response_len = 0;

    if (nc == NULL || (msg == NULL && status != 500)) {
        MUDC_LOG_ERR("invalid parameters");
        return;
    }

    if (status == 500) {
        // override any supplied text; we don't want to provide
        // additional info here
        msg = "Internal error";
    }

    response_len = strlen(msg);
    mudc_construct_head(nc, status, response_len, NULL);
    MUDC_LOG_WRITE_DATA(nc, "%.*s", response_len, msg);
}

static void send_error_for_context(request_context *ctx, int status,
				   const char *msg)
{
    if (ctx == NULL) {
        MUDC_LOG_ERR("invalid parameters");
        return;
    }

    if (ctx->send_client_response == false) {
        return;
    }

    send_error_result(ctx->in, status, msg);
}

/* build a netmask out of a prefix.  Only for IPv4.
 * Inputs: (char *) mask string and int mask #
 * Returns: true (success) or false (failure)
 * Side effects: mask string is filled in on succes.
 */

static bool makemask(char * maskstr,int mask) {
  if (mask > 32 || mask < 4)  { // silly mask
    MUDC_LOG_ERR("Silly mask: %d", mask);
    return false;
  }

  if ( mask >= 24 ) {
    sprintf(maskstr,"0.0.0.%d",(1<<(32-mask)) - 1);
    return true;
  }

  if ( mask >= 16) {
    sprintf(maskstr,"0.0.%d.255", (1<<(24-mask)) - 1);
    return true;
  }

  if ( mask >= 8 ) {
    sprintf(maskstr,"0.%d.255.255", (1<<(16-mask)) - 1);
    return true;
  }

  sprintf(maskstr,"%d.255.255.255", (1<<(8-mask)) - 1);
  return true;
}



/*
 * This routine checks each VLAN and adds them to a pool.  They may
 * be assigned in this pool.
 */

static void add_vlans_to_pool() {
    bson_t *filter,*update, result;
    bson_error_t error;
    mongoc_cursor_t *cursor=NULL;
    int i=0;


  /* outer loop: go through the vlan_list[] to see if each exists
   * in the mongodb collection.  If not, add one.
   */

  for (i=0; i< num_vlans; i++) {
    const bson_t *record;

    filter = BCON_NEW("VLAN_ID", BCON_INT32(vlan_list[i].vlan));
    cursor = mongoc_collection_find_with_opts(vlan_collection, filter,
	    				      NULL, NULL);
    if (mongoc_cursor_next(cursor, &record)) {
      continue;
    }
    /* here we found a new one. upsert it */

    update = BCON_NEW(
			"VLAN_ID", BCON_INT32(vlan_list[i].vlan),
			"v4addrmask", BCON_UTF8(vlan_list[i].v4_nw),
			"v6addrmask", BCON_UTF8(vlan_list[i].v6_nw),
			"Owner","[","]");

    if (!mongoc_collection_find_and_modify(vlan_collection, filter, NULL, update,
                                 NULL, false, true, false, &result,&error)) {
      MUDC_LOG_ERR("Update: %s", error.message);
    }
    bson_destroy(filter);
  }

  if ( cursor != NULL)
    mongoc_cursor_destroy (cursor);
}


/* The authoritative DB source for VLANs is the vlans collection.
 * Search it to see if an assignment is available.  Take as a
 * parameter a parameter a manuf .  This can either be an authority
 * (same-manufacturer) or a URL (model), as passed by is_url.
 * Search array for one or the other.
 */

static int find_vlan(manufacturer_list *manuf, int is_url,int getnew) {
  bson_t *filter, *update=NULL, result;
  const bson_t *record;
  mongoc_cursor_t *cursor=NULL;
  bson_error_t error;
  char *found_str, *search_for;
  cJSON *found_json=NULL,*value_json=NULL;

  if ( is_url )
    search_for=manuf->uri;
  else
    search_for=manuf->authority;
  
      

  if ( search_for == NULL ) {
    MUDC_LOG_ERR("find_vlan called with null search parameter");
    return -1;
  }

  filter=BCON_NEW("Owner","{","$in", "[" , BCON_UTF8(search_for),"]", "}");
  cursor = mongoc_collection_find_with_opts(vlan_collection, filter,
					    NULL, NULL);
  if (mongoc_cursor_next(cursor, &record)) { /* found one */
    found_str = bson_as_json(record, NULL);
    found_json = cJSON_Parse(found_str);
    bson_free(found_str);
    if ((manuf->vlan=GETINT_JSONOBJ(found_json,"VLAN_ID")) < 1) {
      MUDC_LOG_ERR("Bad value for VLAN_ID returned.");
      goto errret;
    }
    manuf->vlan_nw_v4=GETSTR_JSONOBJ(found_json,"v4addrmask");
    manuf->vlan_nw_v6=GETSTR_JSONOBJ(found_json,"v6addrmask");

    mongoc_cursor_destroy(cursor);
    bson_destroy(filter);
    /* don't be so quick to destroy allocated memory here cJSON_Delete(found_json) */;
    return manuf->vlan;
  }

  bson_destroy(filter);
  mongoc_cursor_destroy(cursor);

  if ( getnew == false ) {	/* don't allocate a new VLAN */
    return false;
  }
  /* if we got here, that means no VLANs were found.  Find the first free
   * one and use it.
   */
  
      
    
  filter=BCON_NEW("Owner","{","$size", BCON_INT32(0),"}");
  update=BCON_NEW("$push","{","Owner",BCON_UTF8(search_for),"}");
  if (!mongoc_collection_find_and_modify(vlan_collection, filter, NULL, update,
				 NULL, false, false, true, &result,&error)) {
    MUDC_LOG_ERR("Update: %s", error.message);
    goto errret;
  }
  if ( update == NULL ) { 	/* no free entries */
    goto errret;
  }
  found_str = bson_as_json(&result, NULL);
  found_json = cJSON_Parse(found_str);

  if ((value_json=cJSON_GetObjectItem(found_json,"value"))== NULL ) {
      MUDC_LOG_ERR("Dude: database update failed.");
      goto errret;
  }
  if ((manuf->vlan=GETINT_JSONOBJ(value_json,"VLAN_ID")) == 0) {
      MUDC_LOG_ERR("Dude: database update failed.");
      goto errret;
  }

  manuf->vlan_nw_v4=GETSTR_JSONOBJ(value_json,"v4addrmask");
  manuf->vlan_nw_v6=GETSTR_JSONOBJ(value_json,"v6addrmask");

  bson_destroy(update);
  bson_destroy(&result);
  bson_destroy(filter);
  return manuf->vlan;

 errret:
  if (found_json != NULL)
    cJSON_Delete(found_json);
  bson_destroy(filter);
  bson_destroy(update);
  bson_destroy(&result);
  return -1;
}

/*
 * make more space for ACEs when needed.  Return -1 if we fail.
 */

int make_room(ACE **ace,size_t  oldsize,size_t newsize) {
  if ((*ace=realloc(ace,newsize)) == NULL)
    return -1;
  memset(ace+oldsize,0,newsize-oldsize);
  return 0;
}


static int read_mudmgr_config (char* filename)
{
    BIO *conf_file=NULL, *certin=NULL;
    char jsondata[MAX_BUF+1];
    char *acl_list_type_str=NULL;
    cJSON *manuf_json=NULL, *tmp_json=NULL, *cacert_json=NULL;
    cJSON *vlan_json;

    int ret=-1, i=0;

    if (!filename) {
        MUDC_LOG_ERR("invalid parameters");
        return -1;
    }

    memset(jsondata, 0, sizeof(jsondata)); // make valgrind happy

    conf_file=BIO_new_file(filename, "r");
    BIO_read(conf_file, jsondata, MAX_BUF);
    BIO_free(conf_file);
    config_json = cJSON_Parse(jsondata);

    if (!config_json) {
        MUDC_LOG_ERR("Error before: [%s]", cJSON_GetErrorPtr());
        goto err;
    }

    mudmgr_server = GETSTR_JSONOBJ(config_json, "MUDManagerAPIProtocol");
    if (mudmgr_server == NULL) {
        mudmgr_server = "http";
    }
    mudmgr_coa_pw = GETSTR_JSONOBJ(config_json,"COA_Password");
    mudmgr_cert = GETSTR_JSONOBJ(config_json,"MUDManager_cert");
    mudmgr_key = GETSTR_JSONOBJ(config_json,"MUDManager_key");
    mudmgr_CAcert = GETSTR_JSONOBJ(config_json,"Enterprise_CACert");
    acl_list_prefix = GETSTR_JSONOBJ(config_json, "ACL_Prefix");
    acl_list_type_str = GETSTR_JSONOBJ(config_json, "ACL_Type");
    manager_version= GETINT_JSONOBJ(config_json,"MUD_Manager_Version");
    default_vlan = GETINT_JSONOBJ(config_json, "Default_VLAN");
    default_localv4=GETSTR_JSONOBJ(config_json, "Default_Localv4");
    default_localv6=GETSTR_JSONOBJ(config_json, "Default_Localv6");
    if ((acl_list_type_str != NULL) && !strcmp(acl_list_type_str, "dACL-ingress-only")) {
        acl_list_type = INGRESS_ONLY_ACL;
    }

    if ( manager_version < 2 ) {
      MUDC_LOG_ERR("MUD Config file version is either not set or not compatible");
      goto err;
    }

    {   // moved if (!config_json) test earlier; skip moving below lines for now...
      if ((vlan_json = cJSON_GetObjectItem(config_json, "VLANs")) != NULL) {
	for (i=0;i< cJSON_GetArraySize(vlan_json);i++) {
	  tmp_json=cJSON_GetArrayItem(vlan_json,i); /* fill out the pool */
	  vlan_list[i].vlan=GETINT_JSONOBJ(tmp_json,"VLAN_ID");
	  vlan_list[i].v4_nw=GETSTR_JSONOBJ(tmp_json,"v4addrmask");
	  vlan_list[i].v6_nw=GETSTR_JSONOBJ(tmp_json,"v6addrmask");
	  /* Sanity check */
	  if (vlan_list[i].vlan == 0 ) { // no vlan entry should be 0
	    MUDC_LOG_ERR("Illegal VLAN value.");
	    goto err;
	  }
	  if ( vlan_list[i].vlan == default_vlan ) { // not the default
	    MUDC_LOG_ERR("Warning: VLAN value is the same as the default.");
	  }
	  if (vlan_list[i].v4_nw == NULL && vlan_list[i].v6_nw == NULL) {
	    MUDC_LOG_ERR("VLANs MUST have at least an IPv4 *or* IPv6 net and mask.");
	    goto err;
	  }
	}
	num_vlans=i;
      }

        manuf_json = cJSON_GetObjectItem(config_json, "Manufacturers");
        if (manuf_json == NULL) {
            MUDC_LOG_INFO("No Manufacturers.  Will add them dynamically, but my-controller will not work");
        } else {
            num_manu = cJSON_GetArraySize(manuf_json);
            for(i=0; i < num_manu; i++) {
                tmp_json = cJSON_GetArrayItem(manuf_json, i);
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
		  }
		    /*
		     * There may be a different CA certification for the web
		     * server. This is optional.
		     */
		  cacert_json = cJSON_GetObjectItem(tmp_json, "web_cert");
		  if (cacert_json != NULL) {
		    manuf_list[i].web_certfile = GETSTR_JSONOBJ(tmp_json, "web_cert");
		    certin = BIO_new_file(manuf_list[i].web_certfile, "r");
		    if (certin != NULL) {
			manuf_list[i].web_cert = PEM_read_bio_X509(certin, NULL, NULL, NULL);
			BIO_free(certin);
			if (manuf_list[i].web_cert != NULL) {
			  MUDC_LOG_INFO("Successfully read Manufacture web %d cert", i);
			} else {
			  MUDC_LOG_ERR("Missing Web CA certificate: Failed reading cert");
			  goto err;
			}
		      } else {
			MUDC_LOG_ERR("Missing Web CA certificate: Certificate file missing");
			goto err;
		      }
		    }
                }

		manuf_list[i].vlan = GETINT_JSONOBJ(tmp_json, "vlan");
		manuf_list[i].vlan_nw_v4 = GETSTR_JSONOBJ(tmp_json, "vlan_nw_v4");
		manuf_list[i].vlan_nw_v6 = GETSTR_JSONOBJ(tmp_json, "vlan_nw_v4");
		manuf_list[i].uri= GETSTR_JSONOBJ(tmp_json, "mud-url");
		manuf_list[i].authority= GETSTR_JSONOBJ(tmp_json, "authority");
		manuf_list[i].https_port = GETSTR_JSONOBJ(tmp_json, "https_port");
		manuf_list[i].my_ctrl_v4 = GETSTR_JSONOBJ(tmp_json, "my_controller_v4");
		manuf_list[i].my_ctrl_v6 = GETSTR_JSONOBJ(tmp_json, "my_controller_v6");
		manuf_list[i].local_nw_v4 = GETSTR_JSONOBJ(tmp_json, "local_networks_v4");
		manuf_list[i].local_nw_v6 = GETSTR_JSONOBJ(tmp_json, "local_networks_v6");
            }
        }

        MUDC_LOG_INFO("Certificate read ok:  Continue reading domain list");
        dnsmap_json = cJSON_GetObjectItem(config_json, "DNSMapping");
        if (dnsmap_json == NULL) {
            MUDC_LOG_ERR("Error before: [%s]", cJSON_GetErrorPtr());
            goto err;
        } else {
            MUDC_LOG_INFO("JSON is read succesfully");
        }

        dnsmap_v6_json = cJSON_GetObjectItem(config_json, "DNSMapping_v6");
        if (dnsmap_v6_json == NULL) {
            MUDC_LOG_INFO("No IPv6 Mapping: [%s]", cJSON_GetErrorPtr());
        }

        ctrlmap_json = cJSON_GetObjectItem(config_json, "ControllerMapping");
        if (ctrlmap_json == NULL) {
            MUDC_LOG_ERR("Error before: [%s]", cJSON_GetErrorPtr());
            goto err;
        } else {
            MUDC_LOG_INFO("JSON is read succesfully");
        }
        ctrlmap_v6_json = cJSON_GetObjectItem(config_json, "ControllerMapping_v6");
        if (ctrlmap_v6_json == NULL) {
            MUDC_LOG_INFO("No IPv6 Mapping: [%s]", cJSON_GetErrorPtr());
        }
        defacl_json = cJSON_GetObjectItem(config_json, "DefaultACL");
        if (defacl_json == NULL) {
            MUDC_LOG_INFO("No Default IPv4 ACL configured");
        }
        defacl_v6_json = cJSON_GetObjectItem(config_json, "DefaultACL_v6");
        if (defacl_v6_json == NULL) {
            MUDC_LOG_INFO("No Default IPv6 ACL configured");
        }

        mongoDb_name = GETSTR_JSONOBJ(config_json, "MongoDB_Name");
        if (mongoDb_name == NULL) {
            mongoDb_name = strdup(default_dbname);
        }

        mongoDb_uristr = GETSTR_JSONOBJ(config_json, "MongoDB_URI");
        if (mongoDb_uristr == NULL) {
            mongoDb_uristr = strdup(default_uri);
        }

        mongoDb_policies_collection = GETSTR_JSONOBJ(config_json, "MongoDB_Collection");
        if (mongoDb_policies_collection == NULL) {
            mongoDb_policies_collection = strdup(default_policies_coll_name);
        }

        mongoDb_mudfile_coll = GETSTR_JSONOBJ(config_json, "MongoDB_MUDFile_Collection");
        if (mongoDb_mudfile_coll == NULL) {
            mongoDb_mudfile_coll = strdup(default_mudfile_coll_name);
        }

	mongoDb_macaddr_coll = GETSTR_JSONOBJ(config_json, "MongoDB_MACADDR_Collection");
        if (mongoDb_macaddr_coll == NULL) {
            mongoDb_macaddr_coll = strdup(default_macaddr_coll_name);
        }
    }

    //Everything looks ok.  set ret 0 for success.
    ret = 0;
err:
    return ret;
}

/*
 * Use getaddrinfo() to get the IP address of a domain name.  This
 * is imperfect because that map may change (perhaps quickly).  As
 * a backstop, use the map in the JSON file.
 *
 */

static addrlist* convert_dns_to_ip(char *dnsname, int flag)
{
    char* ipaddr = NULL;
    char *result = NULL;
    cJSON *map_json = NULL;
    struct addrinfo hints,*res, *rtmp;
    addrlist *addrs=NULL,*a;
    void *ptr=NULL;
    int r;

    if (dnsname == NULL) {
        MUDC_LOG_ERR("DNS Name NULL");
        return NULL;
    }
    if (flag) {
      flag=AF_INET6;
      map_json = dnsmap_v6_json;
    } else {
      flag=AF_INET;
      map_json = dnsmap_json;
    }

    if ((result=(char *)malloc(sizeof(char)*INET6_ADDRSTRLEN)) == NULL) {
      MUDC_LOG_ERR("malloc");
      return(NULL);
    }
    if (map_json == NULL) {
        MUDC_LOG_INFO("Missing mapping table");
    } else {
      ipaddr = GETSTR_JSONOBJ(map_json, dnsname);
      if (ipaddr != NULL) {
	strncpy(result,ipaddr,INET6_ADDRSTRLEN);

	/* return a list of one.  No support for multiple addresses
	 * this way yet
	 */
	if ( (addrs=calloc(sizeof(addrlist),1)) == NULL) {
	  MUDC_LOG_ERR("convert_dns_to_ip: calloc");
	  free(result);
	  return NULL;
	}
	addrs->address=result;
	return(addrs);
      }
    }

    /* for simplicity, free result here. */
    free(result);
    /* do a lookup here. */
    memset(&hints,0,sizeof(struct addrinfo));
    hints.ai_family=flag;
    hints.ai_socktype=SOCK_STREAM; /* whatever.  just want one */
    if ((r=getaddrinfo(dnsname,NULL,&hints,&res)) != 0) {
      MUDC_LOG_ERR("Error retrieving IP address for %s: %s",dnsname,
		   gai_strerror(r));
      return(NULL);
    }
    /* hostname(s) found.  Create a linked list of addresses.
     */

    /* allocate the first member ; we have at least one */

    if ( (addrs=calloc(sizeof(addrlist),1)) == NULL) {
	  MUDC_LOG_ERR("convert_dns_to_ip: calloc");
	  return NULL;
    }
    for (rtmp=res,a=addrs; rtmp !=NULL; rtmp=rtmp->ai_next) {

      /* get some space for the name. */

      if ((a->address=(char *)malloc(sizeof(char)*INET6_ADDRSTRLEN)) == NULL) {
	MUDC_LOG_ERR("malloc");
	freeaddrinfo(res);
	return(NULL);
      }

      /* get the name */
      switch(rtmp->ai_family)
	{
	case AF_INET:
	  ptr=&((struct sockaddr_in *) rtmp->ai_addr)->sin_addr;
	  break;
	case AF_INET6:
	  ptr = &((struct sockaddr_in6 *) rtmp->ai_addr)->sin6_addr;
	  break;
	}
      if ( inet_ntop(flag, ptr,a->address,
		     INET6_ADDRSTRLEN) == NULL) {
	freeaddrinfo(res);
	MUDC_LOG_ERR("inet_ntop");
	return(NULL);
      }
      /* if there's another, get another addrlist entry */

      if ((rtmp->ai_next != NULL) &&
	     (a->next=calloc(sizeof(addrlist),1)) == NULL) {
	  MUDC_LOG_ERR("convert_dns_to_ip: calloc");
	  return NULL;
      }
      a=a->next;
    }
    freeaddrinfo(res);
    return(addrs);
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
	  /* blow chunks */

       	    MUDC_LOG_ERR("MUD URL in MUD file does not match given MUD URL.");
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

cJSON *extract_masa_uri (request_context* ctx, char *mudcontent)
{
    cJSON *mud_json=NULL, *meta_json=NULL, *response_json=NULL;
    cJSON *tmp_json=NULL;
    char *masa_uri=NULL;
    int indval=0;
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
    for (indval=0; indval<cJSON_GetArraySize(tmp_json); indval++) {
        cJSON *t = NULL;
        char *tmp = NULL;


        t = cJSON_GetArrayItem(tmp_json, indval);
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
    cJSON *found_json=NULL;
    char *found_str=NULL;

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
    bson_t *query=NULL, up_par, *up_child;
    cJSON *mud_json=NULL;
    char *muduri=NULL, *lastupd=NULL, *sysinfo=NULL,*mfgr=NULL,*model=NULL,
      *doc=NULL;
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
    mfgr = GETSTR_JSONOBJ(mud_json,"mfg-name");
    model = GETSTR_JSONOBJ(mud_json,"model-name");
    doc = GETSTR_JSONOBJ(mud_json,"documentation");

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

    bson_init(&up_par);
    up_child = BCON_NEW(
                "URI", BCON_UTF8(muduri),
                "Last-update", BCON_UTF8(lastupd),
                "Systeminfo", BCON_UTF8(sysinfo),
                "Cache-Validity", BCON_INT32(cachevalidity),
                "Expiry-Time", BCON_DATE_TIME(*exptime),
                "MUD_Content", BCON_UTF8(full_str));

    if ( mfgr != NULL)
      BSON_APPEND_UTF8(up_child,"Manufacturer-Label",mfgr);
    if (model != NULL)
      BSON_APPEND_UTF8(up_child,"Manufacturer-Model",model);
    if (doc != NULL)
      BSON_APPEND_UTF8(up_child,"Manufacturer-Doc",doc);
    if ( ctx->needs_mycontroller ) {
      BSON_APPEND_UTF8(up_child,"Needs-my-controller","yes");
    }

    BSON_APPEND_DOCUMENT(&up_par, "$set", up_child);

    free(full_str);

    query =  BCON_NEW("URI", muduri);
    if (!mongoc_collection_find_and_modify(mudfile_collection, query, NULL, &up_par, NULL, false, true, false, NULL,&error)) {
        MUDC_LOG_ERR("mongoc find_and_modify failed: %s", error.message);
        bson_destroy(query);
        return(false);
    }
    bson_destroy(query);
    bson_destroy(&up_par);
    return(true);
}


static int parse_device_policy(cJSON *m_json, char* policy, ACL *acllist, int start_cnt, int direction,int alloced_acls)
{
    cJSON *lists_json=NULL, *acllist_json=NULL;
    cJSON *aclitem_json=NULL, *policy_json=NULL;
    int ret_count=0, indval=0;

    if (m_json == NULL || policy == NULL || acllist == NULL) {
        MUDC_LOG_ERR("invalid parameters");
        return 0;
    }

    policy_json = cJSON_GetObjectItem(m_json, policy);
    if (!policy_json) {
        MUDC_LOG_ERR("JSON file is missing '%s'", policy);
	return 0;
    }

    lists_json = cJSON_GetObjectItem(policy_json, "access-lists");
    if (!lists_json) {
        MUDC_LOG_ERR("JSON file is missing 'access-lists'from ietf-mud:device");
	return 0;
    }
    acllist_json = cJSON_GetObjectItem(lists_json, "access-list");
    if (!acllist_json) {
        MUDC_LOG_ERR("JSON file is missing 'access-list' from ietf-mud:device");
	return 0;
    }
    for (indval=0;indval < cJSON_GetArraySize(acllist_json); indval++) {
        aclitem_json = cJSON_GetArrayItem(acllist_json, indval);
	if (indval+start_cnt > alloced_acls) {
	  MUDC_LOG_ERR("WAY too many ACLs.  Number should never exceed 4.");
	  return 0;
	}
        if (aclitem_json) {
            acllist[indval+start_cnt].acl_name = GETSTR_JSONOBJ(aclitem_json, "name");
            if (acllist[indval+start_cnt].acl_name == NULL) {
                MUDC_LOG_ERR("Missing 'acl name'");
		return 0;
            }
            acllist[indval+start_cnt].pak_direction = direction;
        }
    }
    ret_count = indval++;
    return(ret_count);
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

cJSON* parse_mud_content (request_context* ctx, int manuf_index, int newdev)
{
    cJSON *full_json=NULL, *mud_json=NULL, *lists_json=NULL;
    cJSON *acllist_json=NULL, *aclitem_json=NULL, *ace_json=NULL;
    cJSON *aceitem_json=NULL, *action_json=NULL, *matches_json=NULL;
    cJSON *port_json=NULL, *response_json=NULL;
    cJSON *tmp_json=NULL, *tmp_2_json=NULL, *ctrl_json=NULL;
    int indval=0, ace_index=0, acl_index=0, acl_count=0, is_v6=0, vlan=0;
    ACL *acllist=NULL;
    int alloced_aces,alloced_acls;
    char *type=NULL;
    int cache_in_hours = 0;
    int ignore_ace=0, ace_loc=0, no_mud=0;
    time_t timer;
    time_t exptime;

    MUDC_LOG_INFO("In parse_mud_content");

    if (ctx == NULL) {
        MUDC_LOG_ERR("invalid parameters");
        return NULL;
    }

    /* Establish the device's VLAN.  On first time connect, prefer authority.
     * Otherwise, prefer URI.
     */

    if ( newdev == true ) {
	
      if ((vlan=find_vlan(&manuf_list[manuf_index],IS_AUTHORITY,false)) == false)
	if ( (vlan=find_vlan(&manuf_list[manuf_index],IS_URL,false)) == false)
	  vlan=default_vlan;
    } else {
      vlan=manuf_list[manuf_index].vlan;
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
    alloced_acls=MAX_ACL_STATEMENTS;
    acl_count += parse_device_policy(mud_json, "from-device-policy", acllist,
				     0, INGRESS,alloced_acls);

    acl_count += parse_device_policy(mud_json, "to-device-policy", acllist,
				     acl_count, EGRESS,alloced_acls);

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

    /* Here's the score: at this point we have zero or more ACLs
     * in acllist, and a total number of entries found in acl_count.
     * These are all from to- or from-device-policy entries in the
     * MUD file.  Now we need to match ACLs with each of those entries.
     * ONLY populate acllist for referenced ACLs.
     */

    for (acl_index=0;acl_index< acl_count; acl_index++) {
      int k;
      char *aclname;
      int is_mfgr=0;

      for (k=0;k < cJSON_GetArraySize(acllist_json); k++) {
        aclitem_json = cJSON_GetArrayItem(acllist_json, k);
	/*
	 * Find the name in acllist, and return its index. acllist holds
	 * the ACL names disovered in the earlier from-device-policy and
	 * to-device-policy sections of the file.
	 */
	if ((aclname=GETSTR_JSONOBJ(aclitem_json,"name")) == NULL) {
	  MUDC_LOG_ERR("ACL missing name.");
	  goto err;
	}
	if (strcmp(aclname,acllist[indval].acl_name))
	  continue;

	acllist[acl_index].matched=1; /* this signals that we don't have a
				       *  dangling reference
				       */

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

	/* We'll start with a reasonable allocation.  Note that the number of
	 * ACEs in the config may exceed that of the number in the mud file.
	 */

        acllist[acl_index].ace_count = 0;
        acllist[acl_index].ace = (ACE*) calloc(INITIAL_ACE_STATEMENTS, sizeof(ACE));
	alloced_aces=INITIAL_ACE_STATEMENTS;
	/*
	 * Loop through "ace" statements in this ACL.
	 */
	if (cJSON_GetArraySize(ace_json) > MAX_ACE_STATEMENTS) {
	    MUDC_LOG_ERR("A silly amount of ACE statements: %d", cJSON_GetArraySize(ace_json));
	    goto err;
	    }
        for (ace_loc = 0; ace_loc < cJSON_GetArraySize(ace_json);
		ace_loc++) {
	  int found_v6=0;
            aceitem_json = cJSON_GetArrayItem(ace_json, ace_loc);
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

	    /*
	     * Check the "actions"
	     */
	    /* we need to handle "actions" first because the matches code may
	     * cause use to duplicate an ACE.
	     */
             action_json = cJSON_GetObjectItem(aceitem_json, "actions"); 
             if (cJSON_GetObjectItem(action_json, "forwarding")) {
                 if (strcmp(cJSON_GetObjectItem(action_json, 
			    "forwarding")->valuestring, "accept") == 0) {
                     acllist[acl_index].ace[ace_index].action = 1;
                  }
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
	     * tcp
	     */
            acllist[acl_index].ace[ace_index].matches.dir_initiated = -1;
	    if ((tmp_json=cJSON_GetObjectItem(matches_json, "tcp"))) {
	        MUDC_LOG_INFO("Processing an tcp protocol\n");

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
	        MUDC_LOG_INFO("Processing an udp protocol\n");

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
	     * ipv4 or ipv6
	     */
	    tmp_json=cJSON_GetObjectItem(matches_json, "ipv6");
	    if ( tmp_json != NULL )
	      found_v6++;
	    else
	      tmp_json=cJSON_GetObjectItem(matches_json, "ipv4");

	    if ( tmp_json != NULL ) {
	      addrlist *r=NULL;
	      int addrtype = false;
	      
	      if ((found_v6 && ! is_v6) || (!found_v6 && is_v6)) {
		    MUDC_LOG_ERR("Got mixed ipv4/6 ACEs in ACL\n");
		    goto err;
	      }
	      MUDC_LOG_INFO("Processing an %s protocol\n", is_v6? "v6" : "v4");
	      /* Look for "protocol" filed */
	      acllist[acl_index].ace[ace_index].matches.protocol =
		GETINT_JSONOBJ(tmp_json, "protocol");

	      /* IP address entries.  Multicast only for now. */

	      if ((tmp_2_json=cJSON_GetObjectItem(tmp_json,
				       "destination-ipv4-network")))
		addrtype=AF_INET;
	      else {
		  if ((tmp_2_json=cJSON_GetObjectItem(tmp_json,
			      "destination-ipv6-network"))) {
		    addrtype=AF_INET6;
		  } else {
		    if ((tmp_2_json=cJSON_GetObjectItem(tmp_json,
                              "source-ipv6-network"))) {
		      addrtype=AF_INET6;
		    } else {
			if ((tmp_2_json=cJSON_GetObjectItem(tmp_json,
                              "source-ipv4-network"))) {
			  addrtype=AF_INET;
			}
		    }
		  }
	      }
	      if (addrtype == AF_INET || addrtype == AF_INET6) {
		char *prefix_str=NULL;
		char *ipaddr_str=strdup(tmp_2_json->valuestring);
		struct in6_addr sin6;
		struct in_addr sin;
		int prefix,pmax;
		char mask[30];

		/* search for the "/" and separate. */
		if ( (prefix_str=index(ipaddr_str,'/')) == NULL) 
		  {
		    MUDC_LOG_ERR("Malformed Prefix (no /): %s", ipaddr_str);
		    free(ipaddr_str);
		    goto err;
		  }
		*(prefix_str++)='\0';

		if ( found_v6 )  {
		  if ( inet_pton(AF_INET6, ipaddr_str, &sin6) == false ) {
		    MUDC_LOG_ERR("Malformed IPv6 address: %s", ipaddr_str);
		    free(ipaddr_str);
		    goto err;
		  }
		  if ( sin6.s6_addr[0] != 0xFF ) { /* not multicast */
		    MUDC_LOG_ERR("Not processing non-multicast addresses");
		    free(ipaddr_str);
		    goto err;
		  }
		  pmax=64;
		} else {
                  if ( inet_pton(AF_INET, ipaddr_str, &sin) == false ) {
                    MUDC_LOG_ERR("Malformed IPv4 address: %s", ipaddr_str);
                    free(ipaddr_str);
                    goto err;
		  }
		  /* do ipv4 multicast check */
		  if ((htonl(sin.s_addr) & 0xf0000000) != 0xe0000000) {
                    MUDC_LOG_ERR("Not processing non-multicast addresses");
                    free(ipaddr_str);
                    goto err;
		  }
		  pmax=32;
		}
		  /* check numeric value of prefix */
		  if ((sscanf(prefix_str,"%d",&prefix) != 1) || (prefix > pmax)) {
		    MUDC_LOG_ERR("Invalid prefix %s", prefix_str);
                    free(ipaddr_str);
		    goto err;
		  }
		  /* fill in the blanks in our acl/ace struct, for
		     IPv4 we need to build a mask. */
		  if ( found_v6 )  { /* just use the value */
		    *(--prefix_str)='/';
		  } else {

		    if ( ! makemask(mask,prefix) )
		      goto err;	/* makemask already produces an error */
		    strcat(ipaddr_str," ");
		    strcat(ipaddr_str,mask);
		  }
		  acllist[acl_index].ace[ace_index].matches.addrmask=
		    ipaddr_str;
		  no_mud++;
	      }

	      /* Check for MUD DNS name extensions */
	      if (  ( ! no_mud) && (tmp_2_json=cJSON_GetObjectItem(tmp_json,
				   "ietf-acldns:src-dnsname"))) {
		no_mud++;
		r=convert_dns_to_ip(tmp_2_json->valuestring, is_v6);
		if ( r == NULL ) {
		  MUDC_LOG_ERR("Unable to get IP address of %s",
			       tmp_2_json->valuestring);
		  goto err;
		}
	      } else if ((!no_mud) && (tmp_2_json=cJSON_GetObjectItem(tmp_json,
			    "ietf-acldns:dst-dnsname"))) {
		no_mud++;
		r=convert_dns_to_ip(tmp_2_json->valuestring, is_v6);
		if ( r == NULL ) {
		  MUDC_LOG_ERR("Unable to get IP address of %s",
			       tmp_2_json->valuestring);
		  goto err;
		}
	      }
	      while (r != NULL) { /* copy ace entries as necessary
				   * be sure to not do mud entries.
				   */
		acllist[acl_index].ace[ace_index].matches.dnsname =
		  r->address;
		if (r->next != NULL) {
		  /* check space */
		  ace_index++;
		  if ( alloced_aces<=ace_index ) {
		    ACE *tmpace=acllist[acl_index].ace;
		    if ( make_room(&tmpace,
				   alloced_aces*sizeof(ACE),
				   (alloced_aces+10)*sizeof(ACE)) == -1 ) {
		      MUDC_LOG_ERR("Not enough memory to realloc");
		      goto err;
		    }
		    alloced_aces+=10;
		  }
		  /* now bcopy previous entry to capture
		   * UDP/TCP properties.
		   */
		  bcopy(&(acllist[acl_index].ace[ace_index-1]),
			&(acllist[acl_index].ace[ace_index]),
			sizeof(ACE));
		}
		r=r->next;
	      }
	    }

	    /*
	     * ietf-mud:mud
	     */
	    if ( (!no_mud)
		 && (tmp_json=cJSON_GetObjectItem(matches_json, "ietf-mud:mud"))) {
	        MUDC_LOG_INFO("Processing a ietf-mud:mud protocol\n");
                if ((ctrl_json=cJSON_GetObjectItem(tmp_json, "controller"))) {
                    acllist[acl_index].ace[ace_index].matches.dnsname =
		       convert_controller_to_ip(ctrl_json->valuestring, is_v6);
                 }

		if ((ctrl_json=cJSON_GetObjectItem(tmp_json, "local-networks"))){
                     MUDC_LOG_INFO("local-network  is V4 <%d>\n", is_v6);
                     if (is_v6) {
		       if (manuf_list[manuf_index].local_nw_v6 == NULL) {
			   
			 if (default_localv6 == NULL) {// no general default
			   if ( manuf_list[manuf_index].vlan_nw_v6 != NULL)
			     acllist[acl_index].ace[ace_index].matches.addrmask=
			       manuf_list[manuf_index].vlan_nw_v6;
			   else { // no local network information
			     MUDC_LOG_ERR("local-networks used with no available definition");
			     ignore_ace++;
			   }
			 } else  // we have a default.  Use it.
			   acllist[acl_index].ace[ace_index].matches.addrmask=
			     default_localv6;
		       } else // we have a specific value for this nw
			   acllist[acl_index].ace[ace_index].matches.addrmask =
			     manuf_list[manuf_index].local_nw_v6;
		     } else {
		       if (manuf_list[manuf_index].local_nw_v4 == NULL) {
			 if (default_localv4 == NULL) {
			   if ( manuf_list[manuf_index].vlan_nw_v4 != NULL)
			     acllist[acl_index].ace[ace_index].matches.addrmask=
			     manuf_list[manuf_index].vlan_nw_v4;
			   else {
			     MUDC_LOG_ERR("local-networks used with no available definition");
			     ignore_ace++;
			   }
			 } else
			   acllist[acl_index].ace[ace_index].matches.addrmask=
			     default_localv4;
		       } else
			   acllist[acl_index].ace[ace_index].matches.addrmask =
			     manuf_list[manuf_index].local_nw_v4;
		     }
                }
		
		if ((ctrl_json=cJSON_GetObjectItem(tmp_json, "my-controller"))) {
                    MUDC_LOG_INFO("My controller is V4 <%d>\n", is_v6);
                    if (is_v6) {
		      if (manuf_list[manuf_index].my_ctrl_v6 != NULL) {
                        acllist[acl_index].ace[ace_index].matches.dnsname =
			  manuf_list[manuf_index].my_ctrl_v6;
		      } else
			ignore_ace++;
                    } else {
		      if (manuf_list[manuf_index].my_ctrl_v4 != NULL) {
                        acllist[acl_index].ace[ace_index].matches.dnsname =
			      manuf_list[manuf_index].my_ctrl_v4;
		      } else
			ignore_ace++;
                    }
		    if (ignore_ace) { /* hint in the database that we need
				       * my controller.
				       */
		      ctx->needs_mycontroller=true;
		      MUDC_LOG_INFO("my-controller is requested for %s, but not listed in config.  Ignoring this ACE",manuf_list[manuf_index].authority);
		    }
		}
		/* do a check for same-manufacturer first because that
		 * might get us into a particular VLAN.
		 */
                if (cJSON_GetObjectItem(tmp_json, "same-manufacturer")) {
		  if (manuf_list[manuf_index].vlan == 0 ||
		      manuf_list[manuf_index].vlan == default_vlan ) {
		    
		      /* see if we can allocate a VLAN.
		       */
		    /* XXX we now have newdev variable.  Maybe we can
		     * do something smarter with find_vlan?
		     */

		      if ((vlan=find_vlan(&manuf_list[manuf_index],IS_AUTHORITY, true)) == -1 ) {
                   	 MUDC_LOG_INFO("VLAN is required but not configured for this Manufacturer\n");
                         goto err;
		      }
                    }
		    /* we need either a vlan_nw_v4 or vlan_nw_v6 */
		    if (! (manuf_list[manuf_index].vlan_nw_v4 ||
			   manuf_list[manuf_index].vlan_nw_v6) ) {
		      MUDC_LOG_ERR("VLAN assigned but no network / mask.");
		      goto err;
		    }
		    if ( is_v6 && manuf_list[manuf_index].vlan_nw_v6)
		      acllist[acl_index].ace[ace_index].matches.addrmask =
			manuf_list[manuf_index].vlan_nw_v6;
		    else if ( manuf_list[manuf_index].vlan_nw_v4 )
		      acllist[acl_index].ace[ace_index].matches.addrmask =
			manuf_list[manuf_index].vlan_nw_v4;
		     else // we have a VLAN but no mask for this IP- ignore
		       {
			 ignore_ace++;
			 continue;
		       }
		    if ( vlan && (vlan == default_vlan) ) {
		      MUDC_LOG_INFO(
		    "More than one VLAN requested.  VLAN %d will be ignored.",
		      vlan);
		    }
		    vlan= manuf_list[manuf_index].vlan;
                }
		if (!ignore_ace) {
		  ctrl_json=cJSON_GetObjectItem(tmp_json, "manufacturer");
		  if ( ctrl_json == NULL )  { /* no manufacturer statement */
		    ctrl_json=cJSON_GetObjectItem(tmp_json, "model");
		    is_mfgr=0; /* treat as model */
		  } else
		    is_mfgr=1; /* treat as manufacturer */
		}
		if ( ctrl_json != NULL ) { /* if it's one or the other */
		 char *mfgr=ctrl_json->valuestring;
		 int i;
		 /* we need to loop through manuf_list, figure out the VLAN
		  * go through the VLAN list, and then add the ACL.  If it
		  * is not in VLAN list, report that but move on.
		  */

		 for (i=0;i<MAX_MANUF; i++) {
		   char *compare;
		   if ( is_mfgr )
		     compare=manuf_list[i].authority;
		   else
		     compare=manuf_list[i].uri;
		   if ( (compare)) {
		     if (! strcmp(mfgr,compare)) {/* win! */
		       if (is_v6 && manuf_list[i].vlan_nw_v6)
			 acllist[acl_index].ace[ace_index].matches.addrmask=
			   manuf_list[i].vlan_nw_v6;
		       else if (manuf_list[i].vlan_nw_v4)
			 acllist[acl_index].ace[ace_index].matches.addrmask=
			   manuf_list[i].vlan_nw_v4;
		       else // we have a VLAN but no mask for this IP- ignore
			 ignore_ace=1;

		       /* If we're a new device and we are only in
			* the default VLAN, then let's go into this other
			* VLAN.  This will only work once (we can only be
			* in one VLAN.  This will allow broadcast to work.
			* It is **overpermissive** because the other MUD
			* file may not have granted that permission.
			*/

		       if ( ! ignore_ace && newdev && vlan == default_vlan )
			 vlan=manuf_list[i].vlan;
		   }
		 }
		}
		if (! ((acllist[acl_index].ace[ace_index].matches.addrmask)
		       || (acllist[acl_index].ace[ace_index].matches.addrmask))) {
		   MUDC_LOG_INFO("Manufacturer %s not found.  Moving on.",
				 mfgr);
		   ignore_ace=1;
		 }
	       }
	    }
	    
	    /*
	     * Sanity checks.
	     */
            if (!ignore_ace &&
		(acllist[acl_index].ace[ace_index].matches.dnsname == NULL) &&
		(acllist[acl_index].ace[ace_index].matches.addrmask == NULL))
	      {
                 MUDC_LOG_ERR("ACL: %d, ACE: %d\n", acl_index, ace_index);
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
             if ( ! ignore_ace ) { /* if not set, we're good */
	       acllist[acl_index].ace_count++;
	       ace_index++;
	       if ( ace_index >= alloced_aces) {
		 ACE *tmpace=acllist[acl_index].ace;
		 if ( make_room(&tmpace,
			       alloced_aces*sizeof(ACE),
			       (alloced_aces+10)*sizeof(ACE)) == -1 ) {
		   MUDC_LOG_ERR("Not enough memory to realloc");
		   goto err;
		 }
		 acllist[acl_index].ace=tmpace;
		 alloced_aces+=10;
	       }
	     } else { 		/* otherwise we clear and reuse next time */
	       acllist[acl_index].ace[ace_index].action = 0;
	       acllist[acl_index].ace[ace_index].matches.addrmask = NULL;
	       acllist[acl_index].ace[ace_index].matches.dnsname = NULL;
	       acllist[acl_index].ace[ace_index].matches.dir_initiated= 0;
	       ignore_ace=0;
	     }
	     no_mud=0;
	}
	break; 			/* we don't need to continue the inner
				 * loop once we've matched an ACL name
				 */
      }
      /* now check to see if we found a match at all.  if not
       * blow chunks
       */
      if (! acllist[acl_index].matched ) {
	MUDC_LOG_ERR("Missing ACL entry for %s",acllist[acl_index].acl_name);
	goto err;
      }	
    } /* close policy acl loop */
    MUDC_LOG_INFO("Calling Create response\n");
    response_json = create_policy_from_acllist(acl_type, acllist, acl_count,
					       acl_list_type,vlan);
   
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


/* add_mfgrs_to_List
 * pulls entries from mudfile_collection.
 *
 */


void add_mfgrs_to_list() {
  bson_t *query;
  mongoc_cursor_t *cursor=NULL;
  const bson_t *record=NULL;

  query=bson_new();

  cursor=mongoc_collection_find_with_opts(mudfile_collection, query,
					  NULL, NULL);

  while (mongoc_cursor_next(cursor,&record))  {
    /* there will always be a URL.  See if it compares to anyone we've got.
     */
    bson_error_t error;
    char *found_str=NULL;
    cJSON *found_json;
    char *the_uri=NULL;
    int found_uri=false;
    int i;

    if ( mongoc_cursor_error(cursor,&error) )
      {
	MUDC_LOG_ERR("mongo search error: %s\n",error.message);
	return;
      }

    found_str = bson_as_json(record, NULL);
    found_json = cJSON_Parse(found_str);

    the_uri= GETSTR_JSONOBJ(found_json, "URI");
    /* now check to see if the_uri is already in the list */

    for (i=0;i<num_manu;i++) {
      if (manuf_list[i].uri && !strcmp(the_uri,manuf_list[i].uri)) {
	found_uri=true;
	break;
      }
    }
    if ( ! found_uri )  { 	/* add the URI */
      char *newname,*end;

      memset(&manuf_list[num_manu],0,sizeof(manufacturer_list));
      manuf_list[num_manu].uri=strdup(the_uri);

      /* we also want the authority in URL.. skip to 2nd / */
      if ((( newname=index(the_uri,'/')) == NULL) || (*(++newname) != '/')) {
	MUDC_LOG_ERR("This ain\'t no stinking URL: %s",the_uri);
	break;
      }
      /* skip past that slash and find the end of authority */
      if ((end=index(++newname,'/'))== NULL) { /* no file? */
	MUDC_LOG_ERR("This ain\'t no stinking URL: %s",the_uri);
	break;
      }
      manuf_list[num_manu].authority=strndup(newname,end-newname);
      manuf_list[num_manu++].my_ctrl_v4=GETSTR_JSONOBJ(found_json, "Controller");
    }
  }
  return;
}




// Return manufacturer index
// input is a string that can be either a URI or a hostname.

int find_manufacturer(char* lookfor)
{
  int j=0;

  if (lookfor == NULL) {
    MUDC_LOG_ERR("invalid parameters");
    return -1;
  }

  for (j=0; j < num_manu; j++) {
    if ( manuf_list[j].uri != NULL &&
	 (! strcmp(lookfor,manuf_list[j].uri)))
      return j;
    if (manuf_list[j].authority != NULL &&
	strstr(lookfor, manuf_list[j].authority) != NULL)
      return j;
  }
    MUDC_LOG_INFO("find_manufacturer: none found");
    return -1;
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
        MUDC_LOG_INFO("No mudfile policy found for this URI");
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
            cJSON_AddStringToObject(response_json, "Tunnel-Medium-Type", 
		    				   "IEEE-802");
            cJSON_AddNumberToObject(response_json, "Tunnel-Private-Group-Id", 
		    				   vlan);
        }

        ret = 200;
        reply_type = "Content-Type: application/aclname";
        response_str = cJSON_Print(response_json);
        response_len = strlen(response_str);
        MUDC_LOG_INFO("Response <%s>\n", response_str);

        mudc_construct_head(nc, ret, response_len, reply_type);
        MUDC_LOG_WRITE_DATA(nc, "%.*s", response_len, response_str);
        free(response_str);
    } else if (query_only) {
        goto end;
    } else if (found_uri) {
        // uri in database w/o ACLs
        // return success so that FR does not reject auth
        send_error_result(nc, 204, "{\"MSG\":\"No ACL for this MUD URL\"}");
        MUDC_LOG_WRITE_DATA(nc, "%.*s", response_len, response_str);
    }

end:
    mongoc_cursor_destroy (cursor);
    bson_destroy(filter);
    cJSON_Delete(response_json);
    cJSON_Delete(dacl_name);

    return found_acl;
}

void start_session (struct mg_connection *nc,
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

int verify_mud_content(char* smud, int slen, char* omud, int olen,
		       int manuf_index) 
{
    BIO *smud_bio=NULL, *omud_bio=NULL, *out=NULL;
    X509_STORE *st = NULL;
    X509 *cacert = NULL;
    PKCS7 *p7 = NULL;
    CMS_ContentInfo *cms = NULL;
    int ret = -1;
    X509_LOOKUP *lookup;

    if (smud == NULL || slen <= 0 || omud == NULL || olen <= 0) {
        MUDC_LOG_ERR("invalid parameters");
        return ret;
    }

    MUDC_LOG_DEBUG_HEX("MUD signature file", smud, slen);

    smud_bio=BIO_new_mem_buf(smud, slen);
    omud_bio=BIO_new_mem_buf(omud, olen);

    /*
     * Validate that we have a correctly formed PKC7 object.
     */
    p7 = d2i_PKCS7_bio(smud_bio, NULL);
    if (!p7) {
        MUDC_LOG_ERR("Error reading PKCS7 format\n");
        goto err;
    } else {
        PKCS7_free(p7);
        p7 = NULL;
    }
   
    /*
     * We need to make sure we have the right CA certificate. We assume that
     * any additional certificates needing verification  (e.g., intermediate 
     * CAs) will be included in the CMS structure, or are in a lookup path.
     */

    /* 
     * Set up trusted CA certificate store. Populate it with the given CA
     * certificate, and the standard OpenSSL "lookup" directory. The latter
     * seems to be needed when the CA is not a self-signed CA.
     */
    st = X509_STORE_new();

    lookup = X509_STORE_add_lookup(st, X509_LOOKUP_file());
    if (lookup == NULL) {
	MUDC_LOG_ERR("Could not setup lookup file");
        ERR_print_errors_fp(stdout);
	goto err;
    }
    if ( (manuf_list[manuf_index].certfile != NULL) && 
	 (!X509_LOOKUP_load_file(lookup, manuf_list[manuf_index].certfile, 
				 X509_FILETYPE_PEM))) {
	MUDC_LOG_INFO("X509_LOOKUP failed. Aborting.");
        ERR_print_errors_fp(stdout);
	goto err;
     }
    lookup = X509_STORE_add_lookup(st, X509_LOOKUP_hash_dir());
    if (lookup == NULL) {
	MUDC_LOG_ERR("Could not setup lookup path");
        ERR_print_errors_fp(stdout);
	goto err;
    }
    X509_LOOKUP_add_dir(lookup, NULL, X509_FILETYPE_DEFAULT);

    int tmp=BIO_reset(smud_bio);
    MUDC_LOG_INFO("BIO_reset <%d>\n", tmp);

    cms = d2i_CMS_bio(smud_bio, NULL);
    if (!cms) {
        MUDC_LOG_ERR("Error in d2i_CMS_bio\n");
        ERR_print_errors_fp(stdout);
        goto err;
    }

    if (!CMS_verify(cms, NULL, st, omud_bio, out, CMS_BINARY|CMS_DETACHED)) {
      MUDC_LOG_ERR("Verification Failure\n");
      ERR_print_errors_fp(stdout);
      goto err;
    }

    MUDC_LOG_INFO("Verification Successful\n");
    ret = 1;
err:
    if (!ret) {
        MUDC_LOG_ERR("Error Verifying Data");
        ERR_print_errors_fp(stdout);
    }
    
    CMS_ContentInfo_free(cms);
    X509_free(cacert);
    X509_STORE_free(st);
    BIO_free(out);
    BIO_free(smud_bio);
    BIO_free(omud_bio);
    return ret;
}


bool update_policy_database(request_context *ctx, cJSON* parsed_json)
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

static bool fetch_uri_from_macaddr(char *mac_addr, char *ret_uri)
{
    mongoc_cursor_t *cursor=NULL;
    bson_t *filter=NULL, *opts=NULL;
    const bson_t *doc=NULL;
    char *found_str=NULL;
    cJSON *found_json=NULL;
    bool ret = false;

    if ((mac_addr == NULL) || (ret_uri == NULL)){
        MUDC_LOG_ERR("Invalid parameters");
        return ret;
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
        	    strncpy(ret_uri, tmp, MAXREQURI);
    		    MUDC_LOG_INFO("============= Returning URI:%s\n", 
			    	  ret_uri);
		    ret = true;
                }
                cJSON_Delete(found_json);
            }
            bson_free(found_str);
        } 
    } 

    mongoc_cursor_destroy (cursor);
    bson_destroy(filter);
    bson_destroy(opts);


    return ret;
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

    MUDC_LOG_INFO("Attempting to insert URI into MAC address record");
    if (!mongoc_collection_find_and_modify(macaddr_collection, query, NULL, update, NULL, false, true, false, NULL,&error)) {
        MUDC_LOG_ERR("mongoc find_and_modify failed: %s", error.message);
        return(false);
    }

    bson_destroy(query);
    bson_destroy(update);

    return(true);
}

void send_masauri_response(struct mg_connection *nc, cJSON *response_json)
{
    int response_len=0;
    char* response_str=NULL;

    response_str = cJSON_Print(response_json);
    response_len = strlen(response_str);
    MUDC_LOG_INFO("Response <%s>\n", response_str);
    mudc_construct_head(nc, 200, response_len, "Content-Type: application/masauri");
    MUDC_LOG_WRITE_DATA(nc, "%.*s", response_len, response_str);
    free(response_str);
}

void send_response(struct mg_connection *nc, cJSON *parsed_json)
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
        cJSON_AddStringToObject(response_json, "Tunnel-Medium-Type", "IEEE-802");
        cJSON_AddNumberToObject(response_json, "Tunnel-Private-Group-Id", vlan);
    }
    response_str = cJSON_Print(response_json);
    response_len = strlen(response_str);
    MUDC_LOG_INFO("Response <%s> <%d>\n", response_str, response_len);
    mudc_construct_head(nc, 200, response_len, "Content-Type: application/aclname");
    MUDC_LOG_WRITE_DATA(nc, "%s", response_str);

    if (response_str) {
        free(response_str);
    }
    cJSON_Delete(response_json);
}

/*
 * The MUD draft allows for "mud-signature" to be included in the MUD file,
 * pointing to the singature file. If it is not present, then the signature
 * URL is assumed to be the same as the MUD URL, but with a .p7s file type
 * rather than .json.
 *
 * The input is uri, and the resulting signature file URL is i requri.
 */
static bool get_mudfs_signed_uri (char *msg, char *uri, char *requri)
{
    cJSON *json=NULL;
    cJSON *mudarry=NULL;
    char *rq=NULL;

    if (!uri || !msg || !requri) {
        MUDC_LOG_ERR("Bad parameters\n");
        return false;
    }
    json = cJSON_Parse(msg);
    if (!json) {
	MUDC_LOG_ERR("Parsing of .json file failed\n");
        return false;
    }
    

    if ( (mudarry=cJSON_GetObjectItem(json,"ietf-mud:mud")) != NULL ) {
      rq = GETSTR_JSONOBJ(mudarry, "mud-signature");
      if (rq) {
	snprintf(requri, MAXREQURI, "%s", rq);
	cJSON_Delete(json);
	return true;
      }
    }
    /* chissel off .json and try again */
    char *dotjson= strstr(uri,".json");
    if ( dotjson != NULL ) {
      snprintf(requri,MAXREQURI,"%*.*s.p7s",0,(int)(dotjson-uri),uri);
    } else {
      snprintf(requri,MAXREQURI,"%s.p7s",uri);
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

static void attempt_coa(sessions_info *sess)
{
    char coa_command[1024];
 
    memset(coa_command, 0, sizeof(coa_command));
    if (sess == NULL) {
        MUDC_LOG_ERR("Invalid parameters");
        return;
    }

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
                // be aware that valgrind will complain of supposed "memory leaks"
		exit(0);
            }
        }
    }
}


void send_mudfs_request(struct mg_connection *nc, const char *base_uri, 
                               const char* mac_addr, 
                               const char* nas, const char* sess_id, int flag,
                               bool send_client_response) 
{
    int manuf_idx=0;
    request_context *ctx=NULL;
    char requri[MAXREQURI], defaulturi[MAXREQURI];
    CURL *curl=NULL;
    char *response=NULL;
    int response_len = 0;
    int i=0;
    int ret=0;
    cJSON *parsed_json=NULL, *masa_json=NULL;
    char *webcacert=NULL;

    if (nc == NULL || base_uri == NULL) {
        MUDC_LOG_ERR("invalid parameters");
        return;
    }

    /*
     * Setup session to the MUD FS
     */
    curl = curl_easy_init();
    if (curl == NULL) {
        MUDC_LOG_ERR("Error in connecting to FS");
 	send_error_for_context(ctx, 404, "Internal error\n");
        goto err;
    }
    
    memset(requri, 0, sizeof(requri)); // make valgrind happy

    /* Flag=1 (Want ACL policies) */
    /* Flag=2 (Want MASA URI) */
    /* XXX these should be DEFINEd! */

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
        ctx->masaurirequest = (flag == 2) ? 1 : 0;
        ctx->send_client_response = send_client_response;
    } else {
        MUDC_LOG_ERR("invalid flag");
 	send_error_for_context(ctx, 500, NULL);
        goto err;
    }

    manuf_idx = find_manufacturer(ctx->uri);
    if (manuf_idx == -1) {
      char *newname,*end;
      if (num_manu >= MAX_MANUF) {
	MUDC_LOG_ERR("Unable to dynamically add manufacturer.  Already at max %d",num_manu);
	goto err;
      }
      MUDC_LOG_INFO("Manufacturer URI %s not found.  Adding entry.", ctx->uri);

      /* find authority in URL.. skip to 2nd / */
      if ((( newname=index(base_uri,'/')) == NULL) || (*(++newname) != '/')) {
	MUDC_LOG_ERR("This ain\'t no stinking URL: %s",base_uri);
	goto err;
      }
      /* skip past that slash and find the end of authority */
      if ((end=index(++newname,'/'))== NULL) { /* no file? */
	MUDC_LOG_ERR("This ain\'t no stinking URL: %s",base_uri);
	goto err;
      }
      memset(&manuf_list[num_manu],0,sizeof(manufacturer_list));
      manuf_list[num_manu].authority=strndup(newname,end-newname);
      manuf_list[num_manu].uri=strdup(ctx->uri);
      manuf_idx=num_manu++;
    }

    if (manuf_list[manuf_idx].web_certfile) {
	webcacert = manuf_list[manuf_idx].web_certfile;
    } else if (manuf_list[manuf_idx].certfile) {
	webcacert = manuf_list[manuf_idx].certfile;
    }

    snprintf(requri,MAXREQURI,"%s",ctx->uri);
    /*
     * The message below isn't an error, but it gives context to the libcurl
     * messages and CoA messages, which aren't so easily suppressed.
     */
    MUDC_LOG_STATUS("\nRequest URI <%s>\n", requri);

    response = fetch_file(curl, requri, &response_len, "mud+json",
	    		  webcacert);
    /*
     * Use a new session each time for expediency. This is necessary because
     * if the server is HTTP 1.0, it will close the connection after each
     * request. A more optimal approach would be for the mud_test_client code
     * to notice if the server responsed with HTTP 1.0 or not, and reuse
     * the connection when it's not HTTP 1.0.
     */
    curl_easy_cleanup(curl);
    curl = NULL;
    if (response == NULL) {
        MUDC_LOG_INFO("Unable to reach MUD fileserver to fetch MUD file.  Will try to append .json");
	strcat(requri,".json");
	curl = curl_easy_init();
	response = fetch_file(curl, requri, &response_len, "mud+json",
	    		  webcacert);
	curl_easy_cleanup(curl);
	curl = NULL;
	if (response == NULL) {
	  MUDC_LOG_ERR("Unable to reach MUD fileserver to fetch .json file");
	  send_error_for_context(ctx, 204, "error from FS\n");
	  goto err;
	}
    }

    MUDC_LOG_INFO("MUD file successfully retrieved");

    MUDC_LOG_DEBUG_HEX("MUD file", response, response_len);
    
    ctx->orig_mud_len = response_len;
    ctx->orig_mud = calloc(ctx->orig_mud_len+1, sizeof(char));
    memcpy(ctx->orig_mud, response + i, ctx->orig_mud_len);
    free(response);
    response = NULL;

    /* 
     * Determine the signature file URL. it's returned in requri.
     *
     * Provide the original URI without the .json, in case it has
     * a port number in it that needs to be retained.
     */
    memset(defaulturi, 0, sizeof(defaulturi)); // make valgrind happy

    if (!get_mudfs_signed_uri(ctx->orig_mud, ctx->uri, requri)) {
	MUDC_LOG_ERR("Unable to request signature file");
 	send_error_for_context(ctx, 500, NULL);
        goto err;
    }
    /*
     * The message below isn't an error, but it gives context to the libcurl
     * messages and CoA messages, which aren't so easily suppressed.
     */
    MUDC_LOG_STATUS("\nRequest signature URI <%s> <%s>\n", requri, webcacert);
   
    curl = curl_easy_init();
    if (curl == NULL) {
        MUDC_LOG_ERR("Error in connecting to FS");
 	send_error_for_context(ctx, 404, "Internal error\n");
        goto err;
    }
    /*
     * Fetch the signature file and verify the signature.
     */
    response = fetch_file(curl, requri, &response_len, "pkcs7-signature",
	    		  webcacert);
    curl_easy_cleanup(curl);
    curl = NULL;
    if (response == NULL) {
        MUDC_LOG_ERR("Unable to reach MUD fileserver to fetch signature file");
 	send_error_for_context(ctx, 404, "error from FS\n");
        goto err;
    }
    MUDC_LOG_INFO("MUD signature file successfully retrieved");

    ctx->signed_mud_len = response_len - i;
    ctx->signed_mud = calloc(ctx->signed_mud_len, sizeof(char));
    memcpy(ctx->signed_mud, response + i, ctx->signed_mud_len);
    free(response);
    response = NULL;

    /* Check response */
    ret = verify_mud_content(ctx->signed_mud, ctx->signed_mud_len, 
	    		     ctx->orig_mud, ctx->orig_mud_len, manuf_idx);
    if (ret == -1) {
    	MUDC_LOG_INFO("Verification failed. Manufacturer Index <%d>\n", manuf_idx);
        send_error_for_context(ctx, 401, "Verification failed"); 
        goto err;
    }

    if (flag == 2) {
    	masa_json = extract_masa_uri(ctx, (char*)ctx->orig_mud);
        if (masa_json == NULL) {
            MUDC_LOG_ERR("Error in extracting MASA uri");
            send_error_for_context(ctx, 500, NULL);
        } else {
            send_masauri_response(ctx->in, masa_json);
            cJSON_Delete(masa_json);
        }
    } else {
      parsed_json = parse_mud_content(ctx, manuf_idx, true);
        if (!parsed_json) {
            MUDC_LOG_ERR("Error in parsing MUD file\n");
            send_error_for_context(ctx, 500, NULL);
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
            	MUDC_LOG_INFO(
			"MAC address database is NOT updated with its URL\n");
	    }
            if(update_policy_database(ctx, parsed_json)) {
		sessions_info *sess = NULL;

                MUDC_LOG_INFO("Policy database is updated successfully\n");
                if (ctx->send_client_response == false) {
                    goto jump; 
                }
                send_response(ctx->in, parsed_json);
    		start_session(nc, ctx->uri, ctx->mac_addr, ctx->nas, 
			      ctx->sess_id);

                /*
		 * Check if COA is required and has sufficient 
		 * info 
		 */
		sess = find_session(ctx->mac_addr);
		if (sess) {
		    attempt_coa(sess);
		} else {
		    MUDC_LOG_ERR(
		       "Could not do CoA: no session found for MAC address %s", 
		       ctx->mac_addr);
		}
            } else {
                MUDC_LOG_ERR("Database update failed\n");
                send_error_for_context(ctx, 500, NULL);
            }
       }   
 jump:
        cJSON_Delete(parsed_json);
    }
    if (curl) {
        curl_easy_cleanup(curl);
    }
    free_request_context(ctx);
    if (response) {
        free(response);
    }
    return;

err:
    MUDC_LOG_ERR("mudfs_conn failed\n");
    if (curl) {
        curl_easy_cleanup(curl);
    }
    free_request_context(ctx);
    if (response) {
        free(response);
    }
    return;
}

static void mudc_print_request_info(const struct mg_request_info *ri)
{
    int i;

    MUDC_LOG_INFO("print parsed HTTP request header info");
    MUDC_LOG_INFO("request method: %s", ri->request_method);
    MUDC_LOG_INFO("request uri: %s", ri->request_uri);
    MUDC_LOG_INFO("local uri: %s", ri->local_uri);
    MUDC_LOG_INFO("http version: %s", ri->http_version);
    MUDC_LOG_INFO("query string: %s", ri->query_string);
    MUDC_LOG_INFO("content_length: %d", ri->content_length);
    MUDC_LOG_INFO("remote ip addr: 0x%x", ri->remote_addr);
    MUDC_LOG_INFO("remote port: %d", ri->remote_port);
    MUDC_LOG_INFO("remote_user: %s", ri->remote_user);
    MUDC_LOG_INFO("is ssl: %d", ri->is_ssl);

    for (i=0; i<ri->num_headers; i++) {
        MUDC_LOG_INFO("header(%d): name: <%s>, value: <%s>",
                       i, ri->http_headers[i].name, ri->http_headers[i].value);
    }
}



static cJSON *get_request_json(struct mg_connection *nc)
{
    cJSON *request_json=NULL;
    char buf[MAXREQURI+1];
    const struct mg_request_info *ri = NULL;
    int err_status = 500; // default: internal error
    char *response_str = NULL;

    if (nc == NULL) {
        MUDC_LOG_ERR("invalid parameters\n");
        return NULL;
    }

    ri = mg_get_request_info(nc);
    if (ri == NULL) {
        response_str = "invalid message";
        MUDC_LOG_ERR("%s", response_str);
        err_status = 403;
        goto send_error;
    }
    mudc_print_request_info(ri);

    memset(buf, 0, sizeof(buf)); // make valgrind happy

    mg_read(nc, buf, sizeof(buf)-1);

    request_json = cJSON_Parse(buf);
    if (request_json == NULL) {
        response_str = "invalid message";
        MUDC_LOG_ERR("%s", response_str);
        err_status = 403;
        goto send_error;
    }
    return request_json;

send_error:
    // send error message -- decide on error statuses
    send_error_result(nc, err_status, response_str);
    return NULL;
}


/*
 * This code responds to a REST API of /getaclpolicy.
 */
static int handle_get_acl_policy(struct mg_connection *nc, 
                       void *unused __attribute__((unused)))
{
    cJSON *jsonResponse=NULL, *dacl_req=NULL;
    int response_len=0;
    char *acl_name=NULL,  *response_str=NULL;

    if (nc == NULL) {
        MUDC_LOG_ERR("invalid parameters\n");
        return 1;
    }

    /*
     * Find the ACLs with the requested name.
     */
    dacl_req = get_request_json(nc);
    if (dacl_req == NULL) {
        MUDC_LOG_INFO("unable to decode message");
        // above function already sends specific error messages
        return 1; 
    }
    acl_name = GETSTR_JSONOBJ(dacl_req, "ACL_NAME");
    jsonResponse = get_policy_by_aclname(acl_type, acl_name);
    if (jsonResponse == NULL) {
        send_error_result(nc, 500, NULL);
        goto err;
    }

    response_str = cJSON_Print(jsonResponse);
    MUDC_LOG_INFO("\nResponse: %s\n", response_str);
    response_len = strlen(response_str);
    mudc_construct_head(nc, 200, response_len, "Content-Type: application/dacl");
    MUDC_LOG_WRITE_DATA(nc, "%.*s", response_len, response_str);
    free(response_str);
err:
    cJSON_Delete(jsonResponse);
    cJSON_Delete(dacl_req);

    return 1;
}

/*
 * If we are told that a particular MUD-URL setup has changed, find MAC
 * addresses that are using that MUD-URL and send issue COAs for them.
 *
 * takes JSON as follows:
 *    
 *    {
 *       "Update_URLs" : [
 *                  "URL1 to change", "URL2 to change", ...
 *                ]
 *    }
 *
 *    Whacks policy database for each.
 *
 */

static int handle_cfg_change(struct mg_connection *nc,
			     void *unused __attribute__((unused))) {

  cJSON *request_json=NULL, *Update_URLs=NULL, *Update_URL=NULL;
  request_context *ctx;
  const bson_t *filter=NULL, *record=NULL;
  mongoc_cursor_t *cursor=NULL;
  int mfg_idx;

  if (nc == NULL) {
    MUDC_LOG_ERR("invalid parameters\n");
    return 1;
  }

  request_json = get_request_json(nc);
  if ( request_json == NULL )
    {
      MUDC_LOG_ERR("Invalid JSON\n");
      return 1;
    }

  /* get the top level object */
  if ( (Update_URLs= cJSON_GetObjectItemCaseSensitive(request_json,"Update_URLs")) ==
       NULL)    {
      MUDC_LOG_ERR("No Update_URLs Array\n");
      cJSON_Delete(request_json);
      return 1;
    }

  if ( cJSON_GetArraySize(Update_URLs) < 1 ) {
    MUDC_LOG_ERR("Empty Update_URLs array");
    cJSON_Delete(request_json);
    cJSON_Delete(Update_URLs);
    return 1;
  }

  if ( (ctx=(request_context *) malloc(sizeof(request_context))) == NULL) {
    MUDC_LOG_ERR("Malloc");
  }

  /* now loop through array and update policy.  cJSON_ArrayForEach is a macro */


  cJSON_ArrayForEach(Update_URL,Update_URLs)  {
    memset(ctx,0,sizeof(request_context)); /* clear cruft */

    /* fill in the blanks */
    ctx->uri=cJSON_GetStringValue(Update_URL);
    ctx->send_client_response=false;

    MUDC_LOG_INFO("Beginning processing update of %s",ctx->uri);
    
    /* we need to get the raw mud file for this */
    filter= BCON_NEW( "URI", BCON_UTF8(ctx->uri) );
    cursor = mongoc_collection_find_with_opts (mudfile_collection, filter,
                                               NULL, NULL);
    if (mongoc_cursor_next(cursor, &record)) {
      cJSON *found_json=NULL, *new_policy=NULL;
      char *found_str = bson_as_json(record, NULL);
      char *newname,*end,*my_ctrl_v4, *m;
      char *authority;
      int vlan=0;
      
      found_json = cJSON_Parse(found_str);
      /* and retrieve MUD file */
      m=GETSTR_JSONOBJ(found_json, "MUD_Content");
      if ( m != NULL) {
	ctx->orig_mud = strdup(m);
	ctx->orig_mud_len= strlen(ctx->orig_mud);
      }
      
      /* find authority OR URL.. skip to 2nd / */

      mfg_idx=find_manufacturer(ctx->uri);
      if ( mfg_idx < 0 )
	{			/* no uri, look for authority */
	  if ((( newname=index(ctx->uri,'/')) == NULL) || (*(++newname) != '/')) {
	    MUDC_LOG_ERR("This ain\'t no stinking URL: %s",ctx->uri);
	    return 1;
	  }
	  /* skip past that slash and find the end of authority */
	  if ((end=index(++newname,'/'))== NULL) { /* no file? */
	    MUDC_LOG_ERR("This ain\'t no stinking URL: %s",ctx->uri);
	    return 1;
	  }
	  authority=strndup(newname,end-newname);

	  /* search for manufacturer */
	  MUDC_LOG_INFO("searching for %s",authority);
	  mfg_idx=find_manufacturer(authority);
	  free(authority);
	}

      if ( mfg_idx < 0 ) {
	MUDC_LOG_ERR("no manufacturer idx yet");
	return 1;
      }
      /* the controller element(s) need to be updated here */

      if ((my_ctrl_v4=GETSTR_JSONOBJ(found_json, "Controller")) != NULL) {
	  /* if one exists, nuke it. */
	  if ( manuf_list[mfg_idx].my_ctrl_v4 != NULL ) {
	    free(manuf_list[mfg_idx].my_ctrl_v4);
	  }
	  manuf_list[mfg_idx].my_ctrl_v4=strdup(my_ctrl_v4);
	}
      
      /* now check for new vlan information */
      vlan=find_vlan(&manuf_list[mfg_idx],IS_URL,false);
      if ( vlan == default_vlan )
	vlan=find_vlan(&manuf_list[mfg_idx],IS_AUTHORITY,false);

      if ( vlan == -1 )
	return -1;

      manuf_list[mfg_idx].vlan=vlan;

      /* try calling parse_mud_content */
      MUDC_LOG_INFO("Parsing and regenerating policy for %s\n",ctx->uri);
      
      if ((new_policy=parse_mud_content(ctx,mfg_idx, false)) == NULL) {
	MUDC_LOG_ERR("parse_mud_content failed");
      }

      /* update the policy database */
      if ( update_policy_database(ctx, new_policy) == false) {
	MUDC_LOG_ERR("We didn't udpate the policy database");
      }

      /* cleanup */
      cJSON_Delete(found_json);
      cJSON_Delete(new_policy);
    }
  }
  free(ctx);
  cJSON_Delete(request_json);
  if (cursor != NULL)
    mongoc_cursor_destroy(cursor);
  mg_send_http_ok(nc,"text/html",0);

  return 200;
}




static int handle_coa_alert(struct mg_connection *nc,
                       void *unused __attribute__((unused)))
{
    char *mac=NULL;
    char coa_command[255];
    cJSON *request_json=NULL;
    sessions_info *sess=NULL;
    int sysret=0;

    MUDC_LOG_INFO("Received COA Alert\n");

    if (nc == NULL) {
        MUDC_LOG_ERR("invalid parameters\n");
        return 1;
    }

    request_json = get_request_json(nc);
    if (request_json == NULL) {
        MUDC_LOG_ERR("unable to parse message");
        send_error_result(nc, 500, NULL);
        return 1;
    }

    mac = GETSTR_JSONOBJ(request_json, "MAC_ADDR");
    if (mac == NULL) {
        MUDC_LOG_ERR("bad input");
        send_error_result(nc, 500, NULL);
        cJSON_Delete(request_json);
	return 1;
    }

    if (mac[0] == '\0') {
        MUDC_LOG_ERR("bad input");
        send_error_result(nc, 500, NULL);
        cJSON_Delete(request_json);
	return 1;
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
	mudc_construct_head(nc, 200, 0, "Content-Type: application/alertcoa");
    }
    cJSON_Delete(request_json);
    return 1;
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
        send_error_result(nc, 500, NULL);
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
 *
 * NOTE: This function should check the mudfile collecton for the MUD file
 *       before fetching it from the MUD file server.
 */
static int handle_get_masa_uri(struct mg_connection *nc,
                       void *unused __attribute__((unused)))
{
    char *uri=NULL;
    cJSON *request_json=NULL;

    if (nc == NULL) {
        MUDC_LOG_ERR("handle_get_masa_uri: invalid parameters\n");
        return 1;
    }

    request_json = get_request_json(nc);
    if (request_json == NULL) {
        MUDC_LOG_INFO("unable to decode message");
        send_error_result(nc, 500, NULL);
        return 1;
    }
    uri = GETSTR_JSONOBJ(request_json, "MUD_URI");

    if (validate_muduri(nc, uri) == false) {
        // function sends error-specific responses
    } else {
    	MUDC_LOG_INFO("Got URI <%s>\n", uri);
        send_mudfs_request(nc, uri, NULL, NULL, NULL, 2, true);
    }
    cJSON_Delete(request_json);
    return 1;
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
static int handle_get_aclname(struct mg_connection *nc, 
                       void *unused __attribute__((unused)))
{
    char *uri=NULL, *mac_addr=NULL, *nas=NULL, *session_id=NULL;
    cJSON *request_json=NULL;
    int foundacls = 0;
    char found_uri[MAXREQURI];
    int can_store_valid_uri = 0;
    bool cache_expired = false;

    if (nc == NULL) {
        MUDC_LOG_ERR("invalid parameters");
        return 1;
    }

    request_json = get_request_json(nc);
    if (request_json == NULL) {
        MUDC_LOG_INFO("unable to decode message");
        send_error_result(nc, 500, NULL);
        return 1; 
    }
    uri = GETSTR_JSONOBJ(request_json, "MUD_URI"); 
    mac_addr = GETSTR_JSONOBJ(request_json, "MAC_ADDR");
    nas = GETSTR_JSONOBJ(request_json, "NAS");
    session_id = GETSTR_JSONOBJ(request_json, "SESS_ID");

    /*
     * We need one or the other to proceed.
     */
    if ((uri == NULL) && (mac_addr == NULL)) {
        send_error_result(nc, 500, NULL);
	return 1;
    }

    /*
     * Check for policies by MAC address first.
     */
    if (mac_addr != NULL) {
        MUDC_LOG_INFO("Mac address <%s> \n", mac_addr);
	/* 
	 * Look for URI associated with the MAC address.
	 */
    	memset(found_uri, 0, sizeof(found_uri)); // make valgrind happy
	if (fetch_uri_from_macaddr(mac_addr, found_uri) == true) {
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
        send_error_result(nc, 204, "{\"MSG\":\"No ACL for this device MAC Address\"}");
        MUDC_LOG_INFO("No URL found for Mac address <%s> \n", mac_addr);
        MUDC_LOG_INFO("    and no MUD URL was provided.");
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
    send_mudfs_request(nc, uri, mac_addr, nas, session_id, 1, 
                       cache_expired ? false:true);

err:
end:
    cJSON_Delete(request_json);

    return 1;
}

#if 0 

// Do we want to intercept and reject all other requests? 

static int handle_unknown_request(struct mg_connection *nc,
                   void *cbdata __attribute__((unused)))
{
    // control the response that we're sending back for other messages
    const struct mg_request_info *ri = NULL;

    MUDC_LOG_VERBOSE("start");

    if (nc == NULL) {
        MUDC_LOG_ERR("invalid parameters");
        return 0;
    }

    ri = mg_get_request_info(nc);
    if (ri == NULL) {
        MUDC_LOG_ERR("invalid parameters");
        MUDC_LOG_ERR("Invalid URI");
        return 1;
    } else {
        MUDC_LOG_ERR("Invalid URI: %s", ri->local_uri);
    }


    // 404? 400? something else?
    MUDC_LOG_INFO("Invalid URI: sending response");
    mudc_construct_head(nc, 404, 0, "Content-Type: text/plain");

    return 1;
}
#endif


#if 0
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
                handle_get_acl_policy(nc, hm);
            } else if (mg_vcmp(&hm->uri, "/getmasauri") == 0) {
                handle_get_masa_uri(nc, hm);
            } else if (mg_vcmp(&hm->uri, "/alertcoa") == 0) {
                handle_coa_alert(nc, hm);
	    } else if (mg_vcmp(&hm->uri,"/cfg_change") == 0) {
   	        handle_cfg_change(nc,hm):
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
#endif

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
    vlan_collection = mongoc_client_get_collection (client, mongoDb_name, mongoDb_vlan_coll);
}

DH *get_dh2236()
{
    static unsigned char dh2236_p[] = {
        0x0E, 0x97, 0x6E, 0x6A, 0x88, 0x84, 0xD2, 0xD7, 0x55, 0x6A, 0x17, 0xB7,
        0x81, 0x9A, 0x98, 0xBC, 0x7E, 0xD1, 0x6A, 0x44, 0xB1, 0x18, 0xE6, 0x25,
        0x3A, 0x62, 0x35, 0xF0, 0x41, 0x91, 0xE2, 0x16, 0x43, 0x9D, 0x8F, 0x7D,
        0x5D, 0xDA, 0x85, 0x47, 0x25, 0xC4, 0xBA, 0x68, 0x0A, 0x87, 0xDC, 0x2C,
        0x33, 0xF9, 0x75, 0x65, 0x17, 0xCB, 0x8B, 0x80, 0xFE, 0xE0, 0xA8, 0xAF,
        0xC7, 0x9E, 0x82, 0xBE, 0x6F, 0x1F, 0x00, 0x04, 0xBD, 0x69, 0x50, 0x8D,
        0x9C, 0x3C, 0x41, 0x69, 0x21, 0x4E, 0x86, 0xC8, 0x2B, 0xCC, 0x07, 0x4D,
        0xCF, 0xE4, 0xA2, 0x90, 0x8F, 0x66, 0xA9, 0xEF, 0xF7, 0xFC, 0x6F, 0x5F,
        0x06, 0x22, 0x00, 0xCB, 0xCB, 0xC3, 0x98, 0x3F, 0x06, 0xB9, 0xEC, 0x48,
        0x3B, 0x70, 0x6E, 0x94, 0xE9, 0x16, 0xE1, 0xB7, 0x63, 0x2E, 0xAB, 0xB2,
        0xF3, 0x84, 0xB5, 0x3D, 0xD7, 0x74, 0xF1, 0x6A, 0xD1, 0xEF, 0xE8, 0x04,
        0x18, 0x76, 0xD2, 0xD6, 0xB0, 0xB7, 0x71, 0xB6, 0x12, 0x8F, 0xD1, 0x33,
        0xAB, 0x49, 0xAB, 0x09, 0x97, 0x35, 0x9D, 0x4B, 0xBB, 0x54, 0x22, 0x6E,
        0x1A, 0x33, 0x18, 0x02, 0x8A, 0xF4, 0x7C, 0x0A, 0xCE, 0x89, 0x75, 0x2D,
        0x10, 0x68, 0x25, 0xA9, 0x6E, 0xCD, 0x97, 0x49, 0xED, 0xAE, 0xE6, 0xA7,
        0xB0, 0x07, 0x26, 0x25, 0x60, 0x15, 0x2B, 0x65, 0x88, 0x17, 0xF2, 0x5D,
        0x2C, 0xF6, 0x2A, 0x7A, 0x8C, 0xAD, 0xB6, 0x0A, 0xA2, 0x57, 0xB0, 0xC1,
        0x0E, 0x5C, 0xA8, 0xA1, 0x96, 0x58, 0x9A, 0x2B, 0xD4, 0xC0, 0x8A, 0xCF,
        0x91, 0x25, 0x94, 0xB4, 0x14, 0xA7, 0xE4, 0xE2, 0x1B, 0x64, 0x5F, 0xD2,
        0xCA, 0x70, 0x46, 0xD0, 0x2C, 0x95, 0x6B, 0x9A, 0xFB, 0x83, 0xF9, 0x76,
        0xE6, 0xD4, 0xA4, 0xA1, 0x2B, 0x2F, 0xF5, 0x1D, 0xE4, 0x06, 0xAF, 0x7D,
        0x22, 0xF3, 0x04, 0x30, 0x2E, 0x4C, 0x64, 0x12, 0x5B, 0xB0, 0x55, 0x3E,
        0xC0, 0x5E, 0x56, 0xCB, 0x99, 0xBC, 0xA8, 0xD9, 0x23, 0xF5, 0x57, 0x40,
        0xF0, 0x52, 0x85, 0x9B,
    };
    static unsigned char dh2236_g[] = {
        0x02,
    };
    DH *dh;
#if !(OPENSSL_VERSION_NUMBER < 0x10100000L)
    BIGNUM *p=NULL, *g=NULL;
#endif

    if ((dh = DH_new()) == NULL) {
        return (NULL);
    }
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    dh->p = BN_bin2bn(dh2236_p, sizeof(dh2236_p), NULL);
    dh->g = BN_bin2bn(dh2236_g, sizeof(dh2236_g), NULL);
    if ((dh->p == NULL) || (dh->g == NULL)) {
            DH_free(dh);
            return (NULL);
    }
#else
    p = BN_bin2bn(dh2236_p, sizeof(dh2236_p), NULL);
    g = BN_bin2bn(dh2236_g, sizeof(dh2236_g), NULL);
    if (!DH_set0_pqg(dh, p, NULL, g)) {
	return (NULL);
    }
#endif
    return (dh);
}

static int init_ssl(void *ssl_context, 
                     void *user_data __attribute__((unused)))
{
    // A return code of -1 will cause the SSL server conn. (e.g. mg_start)
    // to fail


    //if (!ssl_context || !user_data) {
    if (!ssl_context) {
        MUDC_LOG_ERR("Invalid parameters");
        return -1;
    }


    /* Add application specific SSL initialization */
    struct ssl_ctx_st *ctx = (struct ssl_ctx_st *)ssl_context;

#if 0
    // save for later use (we may need to override some settings)
    struct server_context *server = (struct server_context *)user_data;
    server->ssl_ctx = ctx;
#endif


    /* example from https://github.com/civetweb/civetweb/issues/347 */
    DH *dh = get_dh2236();
    if (!dh) {
        MUDC_LOG_ERR("DH init failed");
        ERR_print_errors_fp(stderr);
        return -1;
    }
    if (1 != SSL_CTX_set_tmp_dh(ctx, dh)) {
        MUDC_LOG_ERR("DH init failed");
        ERR_print_errors_fp(stderr);
        return -1;
    }
    DH_free(dh);

    EC_KEY *ecdh = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (!ecdh) {
        MUDC_LOG_ERR("DH init failed");
        ERR_print_errors_fp(stderr);
        return -1;
    }
    if (1 != SSL_CTX_set_tmp_ecdh(ctx, ecdh)) {
        MUDC_LOG_ERR("DH init failed");
        ERR_print_errors_fp(stderr);
        return -1;
    }
    EC_KEY_free(ecdh);
    MUDC_LOG_INFO("ECDH ciphers initialized");
    return 0;
}


static void set_options_and_callback(bool use_security, const char *certfile,
                                     const char *cacertfile)
{
    struct mg_callbacks callbacks;
    memset(&callbacks, 0, sizeof(callbacks));

    if (use_security == true) {
        const char *options[] = {
             "listening_ports", s_https_port,
             "ssl_certificate", certfile,
             "ssl_ca_file", cacertfile,
             "ssl_protocol_version", "3", // allow tlsv1.1&v1.2, disallow sslv2&v3
             "ssl_cipher_list", "ALL:!aNULL:!eNULL:!SSLv2:!EXPORT:!SRP",
             "ssl_verify_peer", "no",
             //"error_log_file", "error.log",
             "decode_url", "yes",
             "request_timeout_ms", "10000",
             0};
	callbacks.init_ssl = init_ssl;
        mg_server_ctx = mg_start(&callbacks, NULL, options);
    } else {
        const char *options[] = {
             "listening_ports", s_http_port,
             //"error_log_file", "error.log",
             "decode_url", "yes",
             "request_timeout_ms", "10000",
             0};
        mg_server_ctx = mg_start(&callbacks, NULL, options);
    }
}

static void mud_manager_cleanup(void)
{
    if (mg_server_ctx != NULL) {
        mg_stop(mg_server_ctx);
    }
    if (policies_collection != NULL) {
        mongoc_collection_destroy(policies_collection);
    }
    if (mudfile_collection != NULL) {
        mongoc_collection_destroy(mudfile_collection);
    }
    if (macaddr_collection != NULL) {
        mongoc_collection_destroy(macaddr_collection);
    }
    if (vlan_collection != NULL) {
      mongoc_collection_destroy(vlan_collection);
    }

    if (client != NULL) {
        mongoc_client_destroy(client);
    }
    mongoc_cleanup();
    cJSON_Delete(config_json);
}

void sigintHandler(int sig_num)
{
    MUDC_LOG_ERR("CTRL-C/%d received; shutting down program", sig_num);

    mud_manager_cleanup();

    exit(1);
}


int main(int argc, char *argv[]) 
{
    //struct mg_connection *nc=NULL;
    int i=0;
    char *port=NULL;
    int opt;
    char *default_config_filename = "/usr/local/etc/mud_manager_conf.json";
    char *config_filename = NULL;

    signal(SIGINT, sigintHandler);
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
    /* Process command line options to customize HTTP server */
    for (i = 1; i < argc; i++) {
#if 0
        if (strcmp(argv[i], "-D") == 0 && i + 1 < argc) {
            mgr.hexdump_file = argv[++i];
        } else if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
#endif
        if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
            s_http_port = argv[++i];
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

    curl_global_init(0);

    if (strcmp(mudmgr_server, "https") == 0 ) {
        MUDC_LOG_INFO("Cert %s, %s,  %s\n", mudmgr_cert, mudmgr_key, mudmgr_CAcert);
        port = (char*)s_https_port;
        set_options_and_callback(true, mudmgr_cert, mudmgr_CAcert);
    } else {
        port = (char*)s_http_port;
	set_options_and_callback(false, NULL, NULL);
    }

    if (!mg_server_ctx) {
        MUDC_LOG_ERR("Bind failed.\n");
	ERR_print_errors_fp(stderr);
        exit(1);
    }



    initialize_MongoDB();

    // Get any VLANs that are not listed in the DB into the DB.

    if ( num_vlans > 0 ) {
      add_vlans_to_pool();
    }
    
    // And do the same with manufacturers

    add_mfgrs_to_list();
    

#if 0
    /* Use current binary directory as document root */
    if (argc > 0 && ((cp = strrchr(argv[0], '/')) != NULL ||
               (cp = strrchr(argv[0], '/')) != NULL)) {
        *cp = '\0';
        s_http_server_opts.document_root = argv[0];
    }
#endif

    mg_set_request_handler(mg_server_ctx, "/getmasauri", handle_get_masa_uri, NULL);
    mg_set_request_handler(mg_server_ctx, "/getaclname", handle_get_aclname, NULL);
    mg_set_request_handler(mg_server_ctx, "/getaclpolicy", handle_get_acl_policy, NULL);
    mg_set_request_handler(mg_server_ctx, "/alertcoa", handle_coa_alert, NULL);
    mg_set_request_handler(mg_server_ctx,"/cfg_change",handle_cfg_change, NULL);
    
#if 0
    // do we want to intercept and reject any other messages?
    mg_set_request_handler(mg_server_ctx, "*", handle_unknown_request, NULL);
#endif

    MUDC_LOG_INFO("Starting RESTful server on port %s\n", port);
    for (;;) {
        //mg_mgr_poll(&mgr, 1000);
        sleep(1);
    }

    mud_manager_cleanup();
    return 0;
}

