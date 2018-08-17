/*
 * Copyright (c) 2017-2018 Cisco and/or its affiliates.
 * All rights reserved.
 */

enum {
    LOG_LEVEL_NONE = 0,
    LOG_LEVEL_ERROR = 1,
    LOG_LEVEL_INFO = 2,
    LOG_LEVEL_ALL = 3,
};


#define MUDC_LOG_INFO(format, args ...) do { \
    mudc_log(LOG_LEVEL_INFO, "***MUDC [INFO][%s:%d]--> " format "\n", \
                __func__, __LINE__, ##args); \
} while (0)

#define MUDC_LOG_ERR(format, args ...) do { \
    mudc_log(LOG_LEVEL_ERROR, "***MUDC [ERROR][%s:%d]--> " format "\n", \
                __func__, __LINE__, ##args); \
} while (0)

extern int log_level;

extern void mudc_log (int level, char *format, ...);
