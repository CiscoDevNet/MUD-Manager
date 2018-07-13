/*
 * Copyright (c) 2017-2018 by Cisco Systems, Inc.
 * All rights reserved.
 */

char *fetch_file(CURL *curl, char *get_url,
		      int *response_len, char *response_app_string,
		      char *fs_ca_cert);
