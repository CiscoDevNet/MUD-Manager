
#define MUDC_LOG_INFO(format, args ...) do { \
    mudc_log("***MUDC [INFO][%s:%d]--> " format "\n", \
                __func__, __LINE__, ##args); \
} while (0)

#define MUDC_LOG_ERR(format, args ...) do { \
    mudc_log("***MUDC [INFO][%s:%d]--> " format "\n", \
                __func__, __LINE__, ##args); \
} while (0)

extern void mudc_log (char *format, ...);
