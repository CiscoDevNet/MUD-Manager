/*
 * Copyright (c) 2017-2018 by Cisco Systems, Inc.
 * All rights reserved.
 */
#include <malloc.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include "log.h"

/*
 * Memory for callbacks
 */
struct MemoryStruct {
      char *memory;
        size_t size;
};

static size_t
WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
    size_t realsize = size * nmemb;
    struct MemoryStruct *mem = (struct MemoryStruct *)userp;
	 
    mem->memory = realloc(mem->memory, mem->size + realsize + 1);
    if (mem->memory == NULL) {
    	/* out of memory! */ 
	MUDC_LOG_ERR("not enough memory (realloc returned NULL)\n");
	return 0;
    }
	     
    memcpy(&(mem->memory[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->memory[mem->size] = 0;
		   
    return realsize;
}

static size_t validateheaders(void *ptr, size_t size, size_t nmemb, 
			      void *userdata)
{
    int s=0,r=0;
    char str[10];
    int code = 0;
    int ret = size * nmemb; /* Return's OK. Any other value with be an error. */
    char contenttype[100];

    char *header = (char *)userdata;

    MUDC_LOG_INFO("Header: %s", ptr);

    /*
     * Check the HTTP return code.
     */
    s = strncmp(ptr, "HTTP/", 5);
    if (s == 0) {
	/* 
	 * Check for the code. The 'str' variable is unused, but
	 * provides a means to capture the HTTP code, regardless of 
	 * HTTP version. (sscanf() uses its own parsing languague
	 * rather then regexp.)
	 */
	r = sscanf(ptr, "HTTP/%[^ ]%d OK", str, &code);
    	if (r == 0) {
	    MUDC_LOG_ERR("HTTP code not found\n");
	    ret = 0;
    	} else if (code != 200) {
	    MUDC_LOG_ERR("Unexpected return code: %d\n", code);
	    ret = 0;
    	}
	MUDC_LOG_INFO("str: %s\n", str);
    }

    s = sscanf(ptr, "Content-Type: %s\n", contenttype);
    if (s) {
    	/*
     	 * Verify that the retrieved content-type is the expected one.
     	 */
	if (strncmp(contenttype, header, strlen(header))) {
	    MUDC_LOG_INFO("contenttype=%sXXX\n", contenttype);
	    MUDC_LOG_INFO("header=%sXXX\n", header);
	    MUDC_LOG_ERR(" Unexpected Content-Type: %s\n", contenttype);
	    ret = 0;
	}
    }

    return ret;
}

char *fetch_file(CURL *curl, char *get_url,
		      int *response_len, char *response_app_string,
		      char *fs_ca_cert)
{
    CURLcode res = CURLE_OK;
    struct curl_slist *headers = NULL;
    struct MemoryStruct response;
    char exp_response_header[100];
    char *retbuf=NULL;

    memset(exp_response_header, 0, sizeof(exp_response_header));
    memset(&response, 0, sizeof(response));


    sprintf(exp_response_header, "application/%s", response_app_string);

    response.memory = malloc(1);  /* be grown as needed by the realloc above */ 
    response.size = 0;    /* no data at this point */ 


    curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L); /* Set to 1L for more output */
    curl_easy_setopt(curl, CURLOPT_URL, get_url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, validateheaders);
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, exp_response_header);
    curl_easy_setopt(curl, CURLOPT_HEADER, 0L); /* Don't inc. hdrs. in resp. */
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&response);

    curl_easy_setopt(curl, CURLOPT_CAINFO, fs_ca_cert);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    
    if (strstr(get_url, ".json")) {
        headers = curl_slist_append(headers, "Accept: application/mud+json");
    } else if (strstr(get_url, ".p7s")) {
        headers = curl_slist_append(headers, 
				    "Accept: application/pkcs7-signed");
    } else {
	MUDC_LOG_ERR("Request is not a .json file or signature file\n");
	return NULL;
    }
    headers = curl_slist_append(headers, "Content-Type: application/mud+json");
    headers = curl_slist_append(headers, "Accept-Language: en");
    headers = curl_slist_append(headers, "User-Agent: prototype-mud-manager");

    res = curl_easy_perform(curl);
    /* check for errors */ 
    if (res != CURLE_OK) {
        MUDC_LOG_ERR("curl_easy_perform() failed: %s\n",
	                 curl_easy_strerror(res));
        curl_slist_free_all(headers);
        free(response.memory);
	return NULL;
    }

    /*
     * Now, our response.memory points to a memory block that is response.size
     * bytes big and contains the result.
     */
    *response_len = response.size;
    retbuf = calloc(response.size + 1, sizeof(char));
    memcpy(retbuf, response.memory, response.size);
    free(response.memory);
    curl_slist_free_all(headers);
    
    return retbuf;
}

