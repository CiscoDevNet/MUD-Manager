/*
 * Copyright (c) 2017-2018 by Cisco Systems, Inc.
 * All rights reserved.
 */

enum acl_response_type {
    CISCO_DACL,
};

cJSON* create_policy_from_acllist(enum acl_response_type response_type,
				  ACL *acllist, int acl_count, 
			    	  enum acl_direction direction);

/*
 * Definitions used by code manipulating ACLs in the JSON file.
 */
#define GETSTR_JSONOBJ(j,v) cJSON_GetObjectItem(j,v) ? cJSON_GetObjectItem(j, v)->valuestring: NULL
#define GETSTR_JSONARRAY(j,i) cJSON_GetArrayItem(defacl_json, i)->valuestring
#define GETINT_JSONOBJ(j,v) cJSON_GetObjectItem(j,v) ? cJSON_GetObjectItem(j, v)->valueint: 0

