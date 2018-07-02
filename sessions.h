/*
 * Copyright (c) 2017-2018 by Cisco Systems, Inc.
 * All rights reserved.
 */


#define SESS_ERROR 0
#define SESS_ADDED 1
#define SESS_EXISTS 2


typedef struct _sessions_info {
    char mac_addr[50+1];
    char sessid[25+1];
    char nas[50+1];
    char uri[255+1];
    struct _sessions_info *next;  
} sessions_info;

extern sessions_info *sess_list;

extern int add_session(const char* mac, const char* sessid, const char* nas, 
                       const char *uri);
extern void remove_session(char* mac);
extern sessions_info *find_session(char *mac);
