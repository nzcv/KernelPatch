#ifndef BASE_LOG
#define BASE_LOG
#if defined (__ANDROID__)
#include <android/log.h>
#endif

#include <unistd.h>
#include <dlfcn.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

#if defined (__ANDROID__)
#define LOGI(format, args...) __android_log_print(ANDROID_LOG_INFO, "monoInject", format, ##args)
#define LOGD(format, args...) __android_log_print(ANDROID_LOG_DEBUG, "monoInject", "%s:%d " format, __FILE__, __LINE__, ##args)
#define LOGE(format, args...) __android_log_print(ANDROID_LOG_ERROR, "monoInject", format, ##args)
#define LOG_INFO(format, args...) __android_log_print(ANDROID_LOG_INFO, "monoInject", format, ##args)
#define LOG_TRACE(format, args...) 
#define PLOGE(fmt, args...) LOGE("[%d: %s]" fmt, errno, strerror(errno), ##args)
#define LOGP(fp, fmt, ...) do { fprintf(fp, "[+]" fmt , ##__VA_ARGS__ );  __android_log_print(ANDROID_LOG_INFO, "monoInject", fmt, ##__VA_ARGS__); } while(0)
#define LOGF(fmt, ...) do { printf("[+] " fmt "\n", ##__VA_ARGS__); __android_log_print(ANDROID_LOG_INFO, "monoInject", fmt, ##__VA_ARGS__); } while(0)
//__android_log_print(ANDROID_LOG_INFO, "monoInject", fmt, ##__VA_ARGS__); } while(0)

#else
#define LOGI(format, args...)
#define LOGD(format, args...)
#define LOGE(format, args...)
#define LOGF(format, args...)
#define LOG_TRACE(format, args...)
#endif // ENABLE_LOG

#endif /* BASE_LOG */