#ifndef LOGGING_H_
#define LOGGING_H_

#include <stdio.h>

#define logerr(msg, ...) fprintf(stderr, "ERR: " msg "\n", ##__VA_ARGS__)
#define loginfo(msg, ...) fprintf(stderr, "INFO: " msg "\n", ##__VA_ARGS__)

#endif
