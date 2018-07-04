/*
 * Copyright (c) 2017-2018 by Cisco Systems, Inc.
 * All rights reserved.
 *
 * The sessions structure keeps track of MAC addresses and 
 * dynamic information that has been disovered about those MAC addresses
 * since the program was started.
 */

#include <string.h>
#include <malloc.h>
#include "log.h"
#include "sessions.h"

sessions_info *sess_list = NULL;

int add_session(const char* mac, const char* sessid, const char* nas, 
                       const char *uri)
{
    int ret = SESS_ERROR;
    sessions_info *tmp=NULL, *new=NULL, *prev=NULL;

    if (mac == NULL || sessid == NULL || nas == NULL) {
        MUDC_LOG_ERR("invalid parameters");
        return SESS_ERROR;
    }

    if (sess_list == NULL) {
        sess_list = (sessions_info*) calloc(1, sizeof(struct _sessions_info));
        strncpy(sess_list->mac_addr, mac, sizeof(sess_list->mac_addr) - 1);
        strncpy(sess_list->sessid, sessid, sizeof(sess_list->sessid) - 1);
        strncpy(sess_list->nas, nas, sizeof(sess_list->nas) - 1);
        strncpy(sess_list->uri, uri, sizeof(sess_list->uri) - 1);
        ret = SESS_ADDED;
    } else {
        tmp = sess_list;
	prev = sess_list;
        while (tmp != NULL) {
            if (strcmp(tmp->mac_addr, mac) == 0) {
                if (strcmp(tmp->sessid, sessid) != 0) {
                    strncpy(tmp->sessid, sessid, sizeof(tmp->sessid) - 1);
                }
                ret = SESS_EXISTS;
           }
	   prev = tmp;
           tmp = tmp->next;
        }
        if (ret != SESS_EXISTS) {
            new = (sessions_info*) calloc(1, sizeof(struct _sessions_info));
            strncpy(new->mac_addr, mac, sizeof(new->mac_addr) - 1);
            strncpy(new->sessid, sessid, sizeof(new->sessid) - 1);
            strncpy(new->nas, nas, sizeof(new->nas) - 1);
            prev->next = new;
            ret = SESS_ADDED;
        }
    }
    return ret;
}

void remove_session(char* mac) 
{
    sessions_info *tmp=NULL, *prev=NULL;

    if (mac == NULL) {
        MUDC_LOG_ERR("invalid parameters");
        return;
    }

    tmp = sess_list;
    while (tmp != NULL) {
        if (strcmp(tmp->mac_addr, mac) == 0) {
	    if (prev == NULL) {
		sess_list = NULL;
	    } else {
                 prev->next = tmp->next;
	    }
            free(tmp);
            break;
        } else {
            prev = tmp;
            tmp = tmp->next;
	}
    }
}

sessions_info *find_session(char *mac) 
{
    sessions_info *tmp=NULL;
    int found = 0;

    if (mac == NULL) {
        MUDC_LOG_ERR("invalid parameters");
        return NULL;
    }

    tmp = sess_list;
    while (tmp != NULL) {
        if (strcmp(tmp->mac_addr, mac) == 0) {
            found = 1;            
            break;
        }
        tmp = tmp->next;
    }
    if (found) {
        return tmp;
    } else {
        MUDC_LOG_ERR("Error: Session for this MAC is not found");
        return NULL;
    }
}

