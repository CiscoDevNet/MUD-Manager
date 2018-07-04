/*
 * Copyright (c) 2017-2018 by Cisco Systems, Inc.
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
