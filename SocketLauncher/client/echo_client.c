#define _GNU_SOURCE
#include <pthread.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <netinet/ip.h>
#include <stdlib.h>
#include <arpa/inet.h>

#define MAX_COUNT 10000

struct args {
    int fd;
    int count;
    int i;
    double rcv_latencies[MAX_COUNT];
};

#define MSG_TEMPLATE "Ping: %d"
#define MAX_SIMUL 100

pthread_mutex_t ready_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t  ready_cond  = PTHREAD_COND_INITIALIZER;
bool ready = false;


void *run_client(void *vfd) {
    struct args *args = vfd;
    pthread_t self = pthread_self();
    cpu_set_t cpuset;

   	CPU_ZERO(&cpuset);
   	CPU_SET(args->i % 8, &cpuset);

    int rtn = pthread_setaffinity_np(self, sizeof(cpu_set_t), &cpuset);
    if (rtn != 0)
	   perror("pthread_setaffinity_np");

    pthread_mutex_lock(&ready_mutex);
    while (!ready) {
        pthread_cond_wait(&ready_cond, &ready_mutex);
    }
    pthread_mutex_unlock(&ready_mutex);

    struct timespec start_time, end_time;

    char msg[strlen(MSG_TEMPLATE)+10];
    for (int i=0; i < args->count; i++) {
        size_t n = snprintf(msg, sizeof(msg), MSG_TEMPLATE, i);
        int rtn = clock_gettime(CLOCK_MONOTONIC_RAW, &start_time);
        if (rtn < 0) {
            perror("clock_gettime");
        }
        ssize_t sent = send(args->fd, msg, n, 0);
        if (sent < 0) {
            perror("sending");
            return NULL;
        }
        ssize_t rcvd = recv(args->fd, msg, sent, 0);
        rtn = clock_gettime(CLOCK_MONOTONIC_RAW, &end_time);
        if (rcvd != sent) {
            perror("receiving");
        }
        if (rtn < 0) {
            perror("clock_gettime end");
        }
        args->rcv_latencies[i] = \
                (end_time.tv_sec - start_time.tv_sec) + \
                (end_time.tv_nsec - start_time.tv_nsec) * 1e-9;
    }
    return 0;
}

int main(int argc, char **argv) {

    if (argc != 6) {
        printf("Usage: %s IP PORT SIMUL COUNT OUTFILE\n", argv[0]);
        return -1;
    }

    struct sockaddr_in addr;
    int rtn = inet_pton(AF_INET, argv[1], &addr.sin_addr.s_addr);
    if (rtn != 1) {
        perror("inet_pton");
        return -1;
    }
    addr.sin_family = AF_INET;
    addr.sin_port = htons(atoi(argv[2]));
    int simul = atoi(argv[3]);
    int count = atoi(argv[4]);

    FILE *outfile = fopen(argv[5], "w");
    if (!outfile) {
        perror("fopen");
        return -1;
    }

    struct args *all_args = malloc(sizeof(*all_args) * simul);
    pthread_t *all_threads = malloc(sizeof(*all_threads) * simul);

    pthread_mutex_lock(&ready_mutex);

    for (int i=0; i < simul; i++) {
        all_args[i].fd = socket(AF_INET, SOCK_STREAM, 0);
        all_args[i].i = i;
        int rtn = connect(all_args[i].fd, (struct sockaddr*)&addr, sizeof(addr));
        if (rtn != 0) {
            perror("connect");
            return -1;
        }
        all_args[i].count = count;
        pthread_create(&all_threads[i], NULL, run_client, &all_args[i]);
    }

    usleep(1e5);

    ready = true;
    pthread_cond_broadcast(&ready_cond);
    pthread_mutex_unlock(&ready_mutex);

    for (int i=0; i < simul; i++) {
        pthread_join(all_threads[i], NULL);
    }

    for (int i=0; i < simul; i++) {
        for (int j=0; j < count; j++) {
            fprintf(outfile, "%d,%d,%f\n",i, j, all_args[i].rcv_latencies[j]);
        }
    }
    fclose(outfile);
    printf("DONE %d\n", simul);
    return 0;
}
