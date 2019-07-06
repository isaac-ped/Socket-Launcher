#ifndef FILE_DB_POOL_H_
#define FILE_DB_POOL_H_

// Defined in file-db-pool.c (forward declaration)
struct thread_pool;

typedef void (*tp_callback)(void *thread_arg, void *shared_arg);

int tp_enqueue(struct thread_pool *tp, void *item);
int tp_terminate(struct thread_pool *tp);

struct thread_pool *init_thread_pool(unsigned int n_threads,
                                     tp_callback callback,
                                     void *shared_arg);

#endif
