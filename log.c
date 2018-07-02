/*
 * Copyright (c) 2017-2018 by Cisco Systems, Inc.
 * All rights reserved.
 */

#include <stdarg.h>
#include <stdio.h>
#include "log.h"

void mudc_log (char *format, ...) 
{
    va_list arguments;

    va_start(arguments, format);

    vfprintf(stdout, format, arguments);
    fflush(stdout);
}
