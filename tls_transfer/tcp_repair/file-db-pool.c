#include <pthread.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h> // Malloc
#include "file-db-pool.h"


struct thread_queue {
    void *item;
    struct thread_queue *next;
};

struct thread_pool {
    pthread_mutex_t mutex;
    pthread_cond_t condition;

    bool terminate;

    struct thread_queue *head;
    struct thread_queue *tail;

    int max_length;
    int length;

    unsigned int n_threads;
    pthread_t *threads;

    tp_callback callback;
    void *shared_arg;
};

int tp_terminate(struct thread_pool *tp) {
    if (pthread_mutex_lock(&tp->mutex)) {
        perror("pthread_mutex_lock");
        return -1;
    }

    tp->terminate = true;

    if (pthread_cond_broadcast(&tp->condition)) {
        perror("pthread_cond_broadcast");
        return -1;
    }
    if (pthread_mutex_unlock(&tp->mutex)) {
        perror("pthread_mutex_unlock");
        return -1;
    }

    for (int i=0; i < tp->n_threads; i++) {
        if (pthread_join(tp->threads[i], NULL)) {
            perror("pthread_join");
            return -1;
        }
    }

    // TODO: Clean up mutexes, thread pool object
    return 0;
}

int tp_enqueue(struct thread_pool *tp, void *item) {

    struct thread_queue *next = malloc(sizeof(*next));
    next->item = item;
    next->next = NULL;

    if (pthread_mutex_lock(&tp->mutex)) {
        perror("pthread_mutex_lock");
        return -1;
    }
    if (tp->max_length > 0 && tp->length >= tp->max_length) {
        if (pthread_mutex_unlock(&tp->mutex)) {
            perror("pthread_mutex_unlock");
            return -1;
        }
        if (tp->length > 1) {
            printf("TP LENGTH %d\n", tp->length);
        }
        return 1;
    }

    if (tp->tail) {
        tp->tail->next = next;
        tp->tail = next;
    } else {
        tp->head = next;
        tp->tail = next;
    }
    tp->length += 1;

    if(pthread_cond_signal(&tp->condition)) {
        perror("pthread_cond_signal");
        return -1;
    }
    if (pthread_mutex_unlock(&tp->mutex)) {
        perror("pthread_mutex_unlock");
        return -1;
    }
    return 0;
}


void *tp_dequeue(struct thread_pool *tp) {
    if (pthread_mutex_lock(&tp->mutex)) {
        perror("pthread_mutex_lock");
        return NULL;
    }

    while ((!tp->head) && (!tp->terminate)) {
        if (pthread_cond_wait(&tp->condition, &tp->mutex)) {
            perror("pthread_cond_wait");
            return NULL;
        }
    }

    struct thread_queue *active = tp->head;
    if (active) {
        tp->length -= 1;
        void *arg = active->item;
        tp->head = tp->head->next;
        if (tp->head == NULL) {
            tp->tail = NULL;
        }

        if (pthread_mutex_unlock(&tp->mutex)) {
            perror("pthread_mutex_unlock");
            return NULL;
        }
        free(active);
        return arg;
    }
    pthread_mutex_unlock(&tp->mutex);
    return NULL;
}

void *thread_loop(void *arg) {
    struct thread_pool *tp = arg;
    void *thread_arg;
    while (!tp->terminate) {
        if ((thread_arg = tp_dequeue(tp)) != NULL) {
            tp->callback(thread_arg, tp->shared_arg);
        }
    }
    pthread_exit(NULL);
}

struct thread_pool * init_thread_pool(unsigned int n_threads, tp_callback callback, void *shared_arg, int max_length) {

    struct thread_pool *tp = malloc(sizeof(*tp));
    if (!tp) {
        perror("malloc");
        return NULL;
    }
    pthread_mutex_init(&tp->mutex, NULL);
    tp->max_length = max_length;
    tp->head = NULL;
    tp->tail = NULL;
    tp->n_threads = n_threads;
    tp->threads = malloc(sizeof(*tp->threads) * n_threads);
    tp->terminate = false;
    tp->shared_arg = shared_arg;
    tp->callback = callback;

    for (int i=0; i < n_threads; i++) {
        if (pthread_create(&tp->threads[i], NULL, thread_loop, tp)) {
            perror("pthread_create");
            return NULL;
        }
    }

    return tp;
}
