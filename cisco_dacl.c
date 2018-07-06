/*
 * Copyright (c) 2017-2018 by Cisco Systems, Inc.
 * All rights reserved.
 *
 * Create a Cisco DACL response for a RADIUS server.
 */
#include <mongoose.h>
#include <cJSON.h>
#include "acl.h"
#include "log.h"
#include "acl_types.h"
#include "cisco_dacl.h"

/*
 * Return Cisco DACL RADIUS attributes.
 */
cJSON* create_cisco_dacl_policy(ACL *acllist, int acl_count,
				enum acl_direction direction)
{
    cJSON *response_acl=NULL, *parsed_json=NULL, *acefmt=NULL;
    char *ace_ptr=NULL, *acl_prefix=NULL;
    char policy_name[80], ace_str[1024];
    int ace_index=0, index=0, i=0;
    char *txt=NULL;
    char *dnsname=NULL;

    if (acllist == NULL || acl_count <= 0) {
        MUDC_LOG_ERR("Invalid parameters");
        return NULL;
    }

    parsed_json = cJSON_CreateArray();
    ace_ptr = ace_str;

    for (index=0; index < acl_count; index++) {
        if ((acllist[index].pak_direction == EGRESS) && 
	    (direction == INGRESS_ONLY_ACL)) {
            MUDC_LOG_INFO("Building INGRESS ACLs only");
            continue;
        }

        response_acl = cJSON_CreateObject();
        if (response_acl == NULL) {
            MUDC_LOG_ERR("Error allocating resposne_acl");
            cJSON_Delete(parsed_json);
            return NULL;
        }

        MUDC_LOG_INFO("ACLName <%s> %d", acllist[index].acl_name, acllist[index].pak_direction);
        if (acl_list_prefix != NULL) {
            sprintf(policy_name, "%s", acl_list_prefix);
        }
        if (acllist[index].pak_direction == INGRESS) {
            sprintf(policy_name, "%sCiscoSecure-Defined-ACL=%s.in", policy_name, acllist[index].acl_name);
            acl_prefix="inacl";
        } else if (acllist[index].pak_direction == EGRESS) {
            sprintf(policy_name, "%sCiscoSecure-Defined-ACL=%s.out", policy_name, acllist[index].acl_name);
            acl_prefix="outacl";
        }

        cJSON_AddItemToObject(response_acl, "DACL_Name",cJSON_CreateString(policy_name));
        cJSON_AddItemToObject(response_acl, "DACL", acefmt = cJSON_CreateArray());

        MUDC_LOG_INFO("Ace Count <%d>", acllist[index].ace_count);
        for (ace_index=0; ace_index < acllist[index].ace_count; ace_index++) {
            if (strcmp(acllist[index].acl_type, "ipv4") == 0) {
                ace_ptr+= sprintf(ace_ptr, "ip:");
            } else if (strcmp(acllist[index].acl_type, "ipv6") == 0) {
                ace_ptr+= sprintf(ace_ptr, "ipv6:");
            }

            if (acllist[index].ace[ace_index].action == 1) {
		if (acllist[index].ace[ace_index].num_ace == 2) {
                	ace_ptr+= sprintf(ace_ptr, "%s#%d=permit", acl_prefix, (ace_index+1)*10-1);
		} else {
                	ace_ptr+= sprintf(ace_ptr, "%s#%d=permit", acl_prefix, (ace_index+1)*10);
		}
            }
            if (acllist[index].ace[ace_index].matches.protocol == 6) {
                ace_ptr+= sprintf(ace_ptr, " tcp");
            } else if (acllist[index].ace[ace_index].matches.protocol == 17) {
                ace_ptr+= sprintf(ace_ptr, " udp");
            }

            if (acllist[index].pak_direction == INGRESS) {
                ace_ptr += sprintf(ace_ptr, " any");
                if ((acllist[index].ace[ace_index].matches.src_lower_port != 0)
                        && (acllist[index].ace[ace_index].matches.src_upper_port != 0 )) {
                    ace_ptr += sprintf(ace_ptr, " range %d %d", acllist[index].ace[ace_index].matches.src_lower_port,
                        acllist[index].ace[ace_index].matches.src_upper_port);
                }
            }

            dnsname = acllist[index].ace[ace_index].matches.dnsname;
            if (dnsname && (strcmp(dnsname, "any") == 0)) {
                ace_ptr += sprintf(ace_ptr, " any");
            } else {
                ace_ptr += sprintf(ace_ptr, " host %s", dnsname);
            }

            if (acllist[index].pak_direction == INGRESS) {
                if ((acllist[index].ace[ace_index].matches.dst_lower_port != 0)
                        && (acllist[index].ace[ace_index].matches.dst_upper_port != 0 )) {
                    ace_ptr += sprintf(ace_ptr, " range %d %d", acllist[index].ace[ace_index].matches.dst_lower_port,
                        acllist[index].ace[ace_index].matches.dst_upper_port);
                }
            } else if (acllist[index].pak_direction == EGRESS) {
                if ((acllist[index].ace[ace_index].matches.src_lower_port != 0)
                        && (acllist[index].ace[ace_index].matches.src_upper_port != 0 )) {
                    ace_ptr += sprintf(ace_ptr, " range %d %d", acllist[index].ace[ace_index].matches.src_lower_port,
                        acllist[index].ace[ace_index].matches.src_upper_port);
                }
                ace_ptr += sprintf(ace_ptr, " any");
                if ((acllist[index].ace[ace_index].matches.dst_lower_port != 0)
                        && (acllist[index].ace[ace_index].matches.dst_upper_port != 0 )) {
                    ace_ptr += sprintf(ace_ptr, " range %d %d", acllist[index].ace[ace_index].matches.dst_lower_port, 
                        acllist[index].ace[ace_index].matches.dst_upper_port);
                }
            }

            if ((acllist[index].ace[ace_index].matches.protocol == 6) && 
                    (acllist[index].ace[ace_index].matches.dir_initiated != -1)) {
                if (acllist[index].ace[ace_index].num_ace == 2) {
                    ace_ptr += sprintf(ace_ptr, " syn");
		    acllist[index].ace[ace_index].num_ace--;
                    ace_index--;
                } else {
                    ace_ptr += sprintf(ace_ptr, " established");
                }
            }
            MUDC_LOG_INFO("ACE Ptr: %s", ace_str);
            cJSON_AddItemToArray(acefmt, cJSON_CreateString(ace_str));
            ace_ptr = ace_str;
        }
        if (defacl_json == NULL) {
            MUDC_LOG_INFO("In NULL if");
            if (strcmp(acllist[index].acl_type, "ipv4") == 0) {
                ace_ptr += sprintf(ace_ptr, "ip:%s#%d=deny ip any any", acl_prefix, (ace_index+1)*10);
            } else if (strcmp(acllist[index].acl_type, "ipv6") == 0) {
                ace_ptr += sprintf(ace_ptr, "ip:%s#%d=deny ipv6 any any", acl_prefix, (ace_index+1)*10);
            }
            cJSON_AddItemToArray(acefmt, cJSON_CreateString(ace_str));
            ace_ptr = ace_str;
            cJSON_AddItemToArray(parsed_json, cJSON_Duplicate(response_acl, 
				 (cJSON_bool)1));
        } else {
            if (strcmp(acllist[index].acl_type, "ipv4") == 0) {
                for(i=0; i < cJSON_GetArraySize(defacl_json); i++) {
                    ace_ptr += sprintf(ace_ptr, "ip:%s#%d=%s", acl_prefix, (ace_index+1)*10+i, GETSTR_JSONARRAY(defacl_json, i));
                    cJSON_AddItemToArray(acefmt, cJSON_CreateString(ace_str));
                    ace_ptr = ace_str;
                }
            } else if (strcmp(acllist[index].acl_type, "ipv6") == 0) {
                for(i=0; i < cJSON_GetArraySize(defacl_v6_json); i++) {
                    ace_ptr += sprintf(ace_ptr, "ipv6:%s#%d=%s", acl_prefix, (ace_index+1)*10+i, GETSTR_JSONARRAY(defacl_v6_json, i));
                    cJSON_AddItemToArray(acefmt, cJSON_CreateString(ace_str));
                    ace_ptr = ace_str;
                }
            }
            cJSON_AddItemToArray(parsed_json, cJSON_Duplicate(response_acl, 
				 (cJSON_bool)1));
        }
        cJSON_Delete(response_acl);
    }
    txt = cJSON_Print(parsed_json);
    if (txt != NULL) {
        MUDC_LOG_INFO("Returning parsed_json %s", txt);
        free(txt);
    }
    return(parsed_json);
}
