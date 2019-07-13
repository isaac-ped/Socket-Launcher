#ifndef LOGGING_H_
#define LOGGING_H_

#include <stdio.h>
#include <pthread.h>
#include <time.h>

static double __attribute__((__unused__)) get_logtime() {
    struct timespec t;
    //clock_gettime(CLOCK_REALTIME_COARSE, &t);
    clock_gettime(CLOCK_REALTIME_COARSE, &t);
    return ((int)t.tv_sec % 100)+ (double)t.tv_nsec * 1e-9;
}

#define ANSI_COLOR_RED     "\x1b[31m"
#define ANSI_COLOR_RESET   "\x1b[0m"

#define LOGTIME get_logtime()

/** Where logs are printed to */
#define LOG_STREAM stderr


/** Macro utilized by all loggers **/
#define log_to_stream(lvl_label, color, f, fmt, ...)\
        fprintf(f, "" color "%.04f:%u:%s:%d:%s(): " lvl_label ": " fmt ANSI_COLOR_RESET "\n", \
                LOGTIME, (unsigned int)pthread_self(), __FILE__, __LINE__, __func__, \
                ##__VA_ARGS__) \

#define log_at_level(lvl_label, color, fmt, ...) \
        (void) (\
            log_to_stream(lvl_label, color, LOG_STREAM, fmt, ##__VA_ARGS__) \
        )


#define logerr(msg, ...) log_at_level("ERR:", ANSI_COLOR_RED, msg, ##__VA_ARGS__)
//#define DO_LOG

#ifdef DO_LOG

#define loginfo(msg, ...) log_at_level("INFO:", ANSI_COLOR_RESET, msg, ##__VA_ARGS__)

#else
#define loginfo(msg, ...)

#endif

#endif
