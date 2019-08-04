/*
 * Copyright (c) 2017-2018 Cisco and/or its affiliates.
 * All rights reserved.
 */

extern char *acl_list_prefix;
extern cJSON *defacl_json;
extern cJSON *defacl_v6_json;

static char *ACEPERMIT="%s#%d=permit";
static char *ACEDENY="%s#%d=deny";

cJSON* create_cisco_dacl_policy(ACL *acllist, int acl_count,
				enum acl_direction direction, int use_vlan);

cJSON* get_cisco_dacl_policy(char *acl_name);

