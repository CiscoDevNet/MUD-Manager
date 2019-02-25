/*
 * Copyright (c) 2017-2018 Cisco and/or its affiliates.
 * All rights reserved.
 */

enum {
    LOG_LEVEL_NONE = 0,
    LOG_LEVEL_ERROR = 1,
    LOG_LEVEL_INFO = 2,
    LOG_LEVEL_DEBUG = 3,
    LOG_LEVEL_ALL = 4,
};


#define MUDC_LOG_INFO(format, args ...) do { \
    mudc_log(LOG_LEVEL_INFO, "***MUDC [INFO][%s:%d]--> " format "\n", \
                __func__, __LINE__, ##args); \
} while (0)

#define MUDC_LOG_ERR(format, args ...) do { \
    mudc_log(LOG_LEVEL_ERROR, "***MUDC [ERROR][%s:%d]--> " format "\n", \
                __func__, __LINE__, ##args); \
} while (0)

#define MUDC_LOG_DEBUG(format, args ...) do { \
    mudc_log(LOG_LEVEL_DEBUG, "***MUDC [DEBUG][%s:%d]--> " format "\n", \
                __func__, __LINE__, ##args); \
} while (0)

#define MUDC_LOG_DEBUG_HEX(context_str, buf, buf_len) do { \
    mudc_log_hex(LOG_LEVEL_DEBUG, __func__, __LINE__, context_str, buf, buf_len); \
} while (0)

#define MUDC_LOG_WRITE_DATA(nc, format, args ...) do { \
    MUDC_LOG_INFO(format, ##args); \
    mg_printf(nc, format, ##args); \
} while (0)

#define MUDC_LOG_STATUS(format, args ...) do { \
    mudc_log_status("***MUDC [STATUS][%s:%d]--> " format "\n", \
                __func__, __LINE__, ##args); \
} while (0)

extern int log_level;

extern void mudc_log (int level, char *format, ...);
extern void mudc_log_hex (int level, const char *func, int line, char *context, 
			  char *buf, int buf_len);
extern void mudc_log_status (char *format, ...);
