/*
 * Copyright (c) 2017-2018 by Cisco Systems, Inc.
 * All rights reserved.
 *
 * Handle different formats for ACL types.
 */
#include <mongoose.h>
#include <cJSON.h>
#include "acl.h"
#include "log.h"
#include "acl_types.h"
#include "cisco_dacl.h"

cJSON* create_policy_from_acllist(enum acl_response_type response_type,
				  ACL *acllist, int acl_count, 
			    	  enum acl_direction direction) 
{
    switch (response_type) {
	case CISCO_DACL:
	   return create_cisco_dacl_policy(acllist, acl_count,
		   				  direction);
	default:
	   MUDC_LOG_ERR("Unsupported ACL response type: %d\n",
		          response_type);
	   return NULL;
    }
}
