/*
 * Copyright (c) 2017-2018 by Cisco Systems, Inc.
 * All rights reserved.
 */

extern char *acl_list_prefix;
extern cJSON *defacl_json;
extern cJSON *defacl_v6_json;

cJSON* create_cisco_dacl_policy(ACL *acllist, int acl_count,
			     	enum acl_direction direction);
