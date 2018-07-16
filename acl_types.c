/*
 * Copyright (c) 2017-2018 by Cisco Systems, Inc.
 * All rights reserved.
 *
 * Handle different formats for ACL types.
 */
#include <cJSON.h>
#include "acl.h"
#include "log.h"
#include "acl_types.h"
#include "cisco_dacl.h"

cJSON* create_policy_from_acllist(enum acl_policy_type acl_type,
				  ACL *acllist, int acl_count, 
			    	  enum acl_direction direction) 
{
    switch (acl_type) {
	case CISCO_DACL:
	   return create_cisco_dacl_policy(acllist, acl_count,
		   				  direction);
	default:
	   MUDC_LOG_ERR("Unsupported ACL type: %d\n",
		          acl_type);
	   return NULL;
    }
}

cJSON* get_policy_by_aclname(enum acl_policy_type acl_type, char* acl_name) 
{
    switch (acl_type) {
	case CISCO_DACL:
	   return get_cisco_dacl_policy(acl_name);
	default:
	   MUDC_LOG_ERR("Unsupported ACL type: %d\n",
		          acl_type);
	   return NULL;
    }
}
