/*
 * Copyright (c) 2017-2018 by Cisco Systems, Inc.
 * All rights reserved.
 */

#include <signal.h>
#include <string.h>
#include <malloc.h>
#include <getopt.h>
#include <cJSON.h>
#include <openssl/evp.h>

#include <curl/curl.h>

int s_exit_flag=0;

#define MAX_STR_LEN 255

#define WEBSERVERMAX 40
#define MUDFILEMAX 80
#define MACADDRMAX 15
#define NASMAX 15
#define SESSMAX 15

char mudcontroller_ip[WEBSERVERMAX];
int mudcontroller_port;

int test_client_get_dacl(char* uri, char* aclname);

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
    int code = 0;
    char str[10];
    int ret = size * nmemb; /* OK */
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
	    printf(" Unexpected Content-Type: %s\n", contenttype);
	    ret = 0;
	}
    }

    return ret;
}

static void test_client_initialize()
{
    	OpenSSL_add_all_algorithms();
}

char *fetch_json_info(CURL *curl, char *get_url, char *request_str, 
		      int *response_len, char *response_app_string)
{
    CURLcode res;
    struct curl_slist *headers = NULL;
    struct MemoryStruct response;
    char exp_response_header[100];

    sprintf(exp_response_header, "application/%s", response_app_string);

    response.memory = malloc(1);  /* be grown as needed by the realloc above */ 
    response.size = 0;    /* no data at this point */ 

    curl_easy_setopt(curl, CURLOPT_VERBOSE, 0L); /* Set to 1L for more output */
    curl_easy_setopt(curl, CURLOPT_URL, get_url);
    headers = curl_slist_append(headers, "Accept: application/json");
    headers = curl_slist_append(headers, "Content-Type: application/json");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, validateheaders);
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, exp_response_header);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, request_str);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&response);
    
    res = curl_easy_perform(curl);
    /* check for errors */ 
    if (res != CURLE_OK) {
        fprintf(stderr, "curl_easy_perform() failed: %s\n",
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
    
    return response.memory;
}

char *create_uri(char *command)
{
    char *get_url = malloc(MAX_STR_LEN);

    if (mudcontroller_port) {
    	sprintf(get_url, "http://%s:%d/%s", mudcontroller_ip, 
		mudcontroller_port, command);
    } else {
    	sprintf(get_url, "http://%s/%s", mudcontroller_ip, command);
    }
    return get_url;
}

int test_client_get_acls(CURL *curl, char* uri, char* mac_addr, char* nas, 
			 char* sess_id)
{
    char *request_str;
    cJSON *jsonRequest;
    char *get_url;
    int status = 0;
    char *response;
    int response_len = 0;
    int i, j;
    cJSON* res_json, *acl_name_array, *acl_array;
    char *aclname, *full_aclname, *acl;
    
    jsonRequest = cJSON_CreateObject();
    if (uri != NULL) {
        cJSON_AddItemToObject(jsonRequest, "MUD_URI", cJSON_CreateString((char*)uri));
    }
    if (mac_addr != NULL) {
        cJSON_AddItemToObject(jsonRequest, "MAC_ADDR", cJSON_CreateString((char*)mac_addr));
    }
    if (nas != NULL) {
        cJSON_AddItemToObject(jsonRequest, "NAS", cJSON_CreateString((char*)nas));
    }
    if (sess_id != NULL) {
        cJSON_AddItemToObject(jsonRequest, "SESS_ID", cJSON_CreateString((char*)sess_id));
    }

    request_str = cJSON_Print(jsonRequest);

    get_url = create_uri("getaclname");
    printf("\nStarting RESTful client against %s\n", get_url);
    printf("    with request %s\n", request_str);

    /*
     * Request an ACL name for this MUD URL.
     */
    response = fetch_json_info(curl, get_url, request_str, &response_len,
	    		       "aclname");
    if ((response_len == 0) && (!response)) {
	fprintf(stderr, "Aborting. No ACL name found.\n");
    	cJSON_Delete(jsonRequest);
	curl_easy_cleanup(curl);
	return 1;
    }
    cJSON_Delete(jsonRequest);
    free(get_url);
    get_url = NULL;

    get_url = create_uri("getaclpolicy");

    printf("Got ACL Names\n");
    res_json = cJSON_Parse((char*)response);
    acl_name_array = cJSON_GetObjectItem(res_json, "Cisco-AVPair");
    for (i=0; i< cJSON_GetArraySize(acl_name_array); i++) {
	full_aclname = cJSON_GetArrayItem(acl_name_array, i)->valuestring;
    	printf("Full ACL Name %d: %s\n", i, full_aclname);

	/*
	 * Request the ACL for the ACL name. The requested ACL name
	 * must be simply the ACL name, without the DACL framework.
	 */
	aclname = index(full_aclname, '=');
	if (!aclname) {
	    printf("Malformed ACL name: no = sign.\n");
	    return 1;
	}
	aclname++; /* Skip past '=' */
	printf("ACLname: %s\n", aclname);

    	jsonRequest = cJSON_CreateObject();
        cJSON_AddItemToObject(jsonRequest, "ACL_NAME", 
	   		      cJSON_CreateString(aclname));
    	request_str = cJSON_Print(jsonRequest);

    	printf("\nStarting RESTful client against %s with request %s\n", 
		get_url, request_str);
    	response = fetch_json_info(curl, get_url, request_str, &response_len,
				   "dacl");
    	if ((response_len == 0) && (!response)) {
	    fprintf(stderr, "Aborting. No ACL name found.\n");
	    return 1;
    	}
    	cJSON_Delete(jsonRequest);
    	free(get_url);

    	res_json = cJSON_Parse((char*)response);
	/*
	 * Validate that the Username is the ACL name.
	 */
	printf("Username: %s\n",
		cJSON_GetObjectItem(res_json, "User-Name")->valuestring);
	printf("Got DACL contents:\n");
    	acl_array = cJSON_GetObjectItem(res_json, "Cisco-AVPair");
    	for (j=0; j< cJSON_GetArraySize(acl_array); j++) {
		acl = cJSON_GetArrayItem(acl_array,j)->valuestring;
		printf("\tACE: %s\n", acl);
	}	
    }

    free(response);
 
    /* we're done with libcurl, so clean it up */ 
    curl_easy_cleanup(curl);

    return status;
}

int test_client_get_masauri(CURL *curl, char* uri)
{
    char *request_str;
    int status=0;
    cJSON *jsonRequest, *res_json;
    char *get_url;
    char *response;
    int response_len = 0;

    jsonRequest = cJSON_CreateObject();
    cJSON_AddItemToObject(jsonRequest, "MUD_URI", 
    cJSON_CreateString((char*)uri));

    request_str = cJSON_Print(jsonRequest);

    get_url = create_uri("getmasauri");
    printf("\nStarting RESTful client against %s\n", get_url);

    /*
     * Request an ACL name for this MUD URL.
     */
    response = fetch_json_info(curl, get_url, request_str, &response_len,
	    		       "masauri");
    if ((response_len == 0) && (!response)) {
	fprintf(stderr, "Aborting. No MASA Server found.\n");
	return 1;
    }
    cJSON_Delete(jsonRequest);
    free(get_url);

    res_json = cJSON_Parse((char*)response);
    cJSON_Delete(jsonRequest);

    printf("Got MASA URI: %s",
    	cJSON_GetObjectItem(res_json, "MASA-URI")->valuestring);

    return status;
}

void usage(char *filename)
{
    fprintf(stderr, "Usage: %s [-b ] [-m] -f mudfilename "
                "-w <address:port> -c<address:port>\n", filename);
    return;
}

int main(int argc, char *argv[]) 
{
    int testmasa = 0;
    int testmud = 0;
    int testmudwithmac = 0;
    char webserver[WEBSERVERMAX];
    char mudfile[MUDFILEMAX];
    char mac_addr[MACADDRMAX];
    char nas[NASMAX];
    char sess_id[SESSMAX];
    int opt;
    char url[14+WEBSERVERMAX+MUDFILEMAX];
    CURL *curl;

   memset(webserver, 0, WEBSERVERMAX); 
   memset(mudfile, 0, MUDFILEMAX); 
   memset(mac_addr, 0, MACADDRMAX); 
   memset(nas, 0, NASMAX); 
   memset(sess_id, 0, SESSMAX); 

    while ((opt = getopt(argc, argv, "a:n:s:bf:mw:c:p:")) != -1) {
        switch (opt) {
            case 'a': 
                testmudwithmac = 1;
                strncpy(mac_addr, optarg, MACADDRMAX);
                break;
            case 'b':
                testmasa = 1;
                break;
            case 'f':
                strncpy(mudfile, optarg, MUDFILEMAX);
                break;
            case 'n': 
                strncpy(nas, optarg, NASMAX);
                break;
            case 'm':
                testmud = 1;
                break;
            case 's': 
                strncpy(sess_id, optarg, SESSMAX);
                break;
            case 'w':
                strncpy(webserver, optarg, WEBSERVERMAX);
                break;
            case 'c':
                strncpy(mudcontroller_ip, optarg, WEBSERVERMAX);
                break;
            case 'p':
                mudcontroller_port = atoi(optarg);
                break;
            default:
                usage(argv[0]);
                exit(1);
        }
    }

    if ((webserver[0] == 0) || (mudfile[0] == 0)) {
    	usage(argv[0]);
        exit(1);
    }

    /*
     * Default is to test for a MUD file.
     */
    if (!testmasa && !testmud) {
        testmud = 1;
    }

    test_client_initialize();

    /*
     * Build URL from args. Save the webserver info too.
     */
    strcpy(url, "https://");
    strncat(url, webserver, WEBSERVERMAX);
    strncat(url, "/", 1);
    strncat(url, mudfile, MUDFILEMAX);

    curl = curl_easy_init();

    if (testmasa) {
        test_client_get_masauri(curl, url);
    }

    if (testmudwithmac) {
        test_client_get_acls(curl, url, mac_addr, nas, sess_id);
    } else if (testmud) {
        printf ("URL:  %s\n", url);
        test_client_get_acls(curl, url, NULL, NULL, NULL);
    }

    return(0);
}


