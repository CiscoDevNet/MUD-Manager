/*
 * Copyright (c) 2017-2018 by Cisco Systems, Inc.
 * All rights reserved.
 */
#include <malloc.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>

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
	printf("not enough memory (realloc returned NULL)\n");
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
    int s,r;
    char str[10];
    int code = 0;
    int ret = size * nmemb; /* Return's OK. Any other value with be an error. */
    char contenttype[100];

    char *header = (char *)userdata;

    /*
     * Check the HTTP return code.
     */
    s = strncmp(ptr, "HTTP/", 5);
    if (s == 0) {
	/* 
	 * Check for the code. The 'str' variable i unused, but
	 * provides a sort of regular expression way to capture
	 * the code, regardless of HTTP version.
	 */
	r = sscanf(ptr, "HTTP/%[^ ]%d OK", str, &code);
    	if (r == 0) {
	    printf("HTTP code not found\n");
	    ret = 0;
    	} else if (code != 200) {
	    printf("Unexpected return code: %d\n", code);
	    ret = 0;
    	} 
    }

    s = sscanf(ptr, "Content-Type: %s\n", contenttype);
    if (s) {
    	/*
     	 * Verify that the retrieved content-type is the expected one.
     	 */
	if (strncmp(contenttype, header, strlen(header))) {
	    printf("contenttype=%sXXX\n", contenttype);
	    printf("header=%sXXX\n", header);
	    printf(" Unexpected Content-Type: %s\n", contenttype);
	    ret = 0;
	}
    }

    return ret;
}

char *fetch_file(CURL *curl, char *get_url,
		      int *response_len, char *response_app_string,
		      char *fs_ca_cert)
{
    CURLcode res;
    struct curl_slist *headers = NULL;
    struct MemoryStruct response;
    char exp_response_header[100];

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
	fprintf(stderr, "Request is not a .json file or signature file\n");
	return NULL;
    }
    headers = curl_slist_append(headers, "Content-Type: application/mud+json");
    headers = curl_slist_append(headers, "Accept-Language: en");
    headers = curl_slist_append(headers, "User-Agent: prototype-mud-manager");

    res = curl_easy_perform(curl);
    /* check for errors */ 
    if (res != CURLE_OK) {
        fprintf(stderr, "curl_easy_perform() failed: %s\n",
	                 curl_easy_strerror(res));
	return NULL;
    }

    /*
     * Now, our response.memory points to a memory block that is response.size
     * bytes big and contains the result.
     */
    *response_len = response.size;
    
    return response.memory;
}
