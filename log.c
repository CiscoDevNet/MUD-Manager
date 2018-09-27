/*
 * Copyright (c) 2017-2018 Cisco and/or its affiliates.
 * All rights reserved.
 *
 * This file contains logging functions and controls.
 */

#include <stdarg.h>
#include <stdio.h>
#include "log.h"

/* Default logging level is INFO */
int log_level = LOG_LEVEL_INFO;

void mudc_log (int level, char *format, ...) 
{
    va_list arguments;

    if (level <= log_level) {

    	va_start(arguments, format);

    	vfprintf(stdout, format, arguments);
    	fflush(stdout);
    }
}

/*
 * mudc_log_status prints out messages regardless of debug level.
 */
void mudc_log_status (char *format, ...) 
{
    va_list arguments;

    va_start(arguments, format);

    vfprintf(stdout, format, arguments);
    fflush(stdout);
}

void DumpHex(const void* data, size_t size) {
	char ascii[17];
	size_t i, j;
	ascii[16] = '\0';
	for (i = 0; i < size; ++i) {
		printf("%02X ", ((unsigned char*)data)[i]);
		if (((unsigned char*)data)[i] >= ' ' && ((unsigned char*)data)[i] <= '~') {
			ascii[i % 16] = ((unsigned char*)data)[i];
		} else {
			ascii[i % 16] = '.';
		}
		if ((i+1) % 8 == 0 || i+1 == size) {
			printf(" ");
			if ((i+1) % 16 == 0) {
				printf("|  %s \n", ascii);
			} else if (i+1 == size) {
				ascii[(i+1) % 16] = '\0';
				if ((i+1) % 16 <= 8) {
					printf(" ");
				}
				for (j = (i+1) % 16; j < 16; ++j) {
					printf("   ");
				}
				printf("|  %s \n", ascii);
			}
		}
	}
	printf("\n");
}

void mudc_log_hex (int level, const char *func, int line, 
		   char *context, char *buf, int buf_len)
{
    if (level <= log_level) {

	fprintf(stdout, "***MUDC [DEBUG][%s:%d]--> %s (length %d)\n", 
	       func, line, context, buf_len);
	DumpHex(buf, buf_len);
    	fflush(stdout);
    }
}

