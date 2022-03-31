#ifndef GENERATOR_H
#define GENERATOR_H

    typedef struct buffer_t {
        unsigned char *data;
        size_t length;

    } buffer_t;

    typedef struct benchmark_pass_t {
        unsigned int success;    // upload success
        clock_t time_begin;      // init time
        clock_t time_end;        // end time
        struct timeval rtime_begin;
        struct timeval rtime_end;

    } benchmark_pass_t;

    typedef struct benchmark_t {
        // internal reference
        unsigned int id;          // benchmark unique id
        pthread_t pthread;        // thread context

        // context and callbacks
        void *kntxt;              // caller context
        int (*close)(void *);     // close thread (cleanup)

        buffer_t (*pass_write)(void *, unsigned char *, size_t, unsigned char *, size_t);
        int (*pass_write_done)(void *);
        buffer_t (*pass_read)(void *, unsigned char *, size_t);
        int (*pass_read_done)(void *);

        // internal counters
        unsigned int chunksize;    // chunk size
        unsigned int chunks;       // chunks length
        unsigned char **buffers;   // chunks buffers
        unsigned char **hashes;    // chunks hashes
        unsigned char **responses; // copy of the redis response
        size_t *sizes;             // size of the responses

        struct benchmark_pass_t read;
        struct benchmark_pass_t secread;
        struct benchmark_pass_t write;

    } benchmark_t;

    typedef struct benchsuite_t {
        benchmark_t **benchmarks;
        size_t length;

    } benchsuite_t;



    benchsuite_t *benchmark_initialize();
    int benchmark_run(benchsuite_t *suite);
    int benchmark_statistics(benchsuite_t *suite);

    void diep(char *str);

#endif
