/*
 * Copyright (c) 2017-2018 Cisco and/or its affiliates.
 * All rights reserved.
 */

struct _match {
    char* dnsname;
    int protocol;
    int is_ipv6;
    int src_lower_port;
    int src_upper_port;
    int dst_lower_port;
    int dst_upper_port;
    int dir_initiated;
};

typedef struct _ace {
    char* rule_name;
    struct _match matches;
    int action;
    int num_ace;
} ACE;

typedef struct _acl_struct {
    char* acl_name;
    char* acl_type;
    int  pak_direction;
    ACE *ace;
    int ace_count;
} ACL;

/*
 * These definitions are used in ACL pak_direction.
 */
#define INGRESS 0
#define EGRESS 1 

/*
 * These definitions are used to determine the direction that
 * ACLs will be applied to enforce policy.
 */
enum acl_direction {
    INGRESS_ONLY_ACL,
    INGRESS_EGRESS_ACLS
};
