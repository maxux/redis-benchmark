#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <pthread.h>
#include <sys/types.h>
#include <openssl/sha.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>
#include <fcntl.h>
#include <getopt.h>
#include <signal.h>
#include "generator.h"

#define SHA256LEN     (size_t) SHA256_DIGEST_LENGTH * 2

static struct option long_options[] = {
    {"size",    required_argument, 0, 's'},
    {"keys",    required_argument, 0, 'k'},
    {"threads", required_argument, 0, 't'},
    {"host",    required_argument, 0, 'h'},
    {"port",    required_argument, 0, 'p'},
    {0, 0, 0, 0}
};

void diep(char *str) {
    perror(str);
    exit(EXIT_FAILURE);
}

//
// hashing
//
char __hex[] = "0123456789abcdef";

static char *sha256hex(unsigned char *hash) {
    char *buffer = calloc((SHA256_DIGEST_LENGTH * 2) + 1, sizeof(char));
    char *writer = buffer;

    for(int i = 0, j = 0; i < SHA256_DIGEST_LENGTH; i++, j += 2) {
        *writer++ = __hex[(hash[i] & 0xF0) >> 4];
        *writer++ = __hex[hash[i] & 0x0F];
    }

    return buffer;
}

static unsigned char *sha256(const unsigned char *buffer, size_t length) {
    unsigned char *hash = calloc(SHA256_DIGEST_LENGTH, 1);
    SHA256_CTX sha256;

    SHA256_Init(&sha256);
    SHA256_Update(&sha256, buffer, length);
    SHA256_Final(hash, &sha256);

    return hash;
}

//
// progress bar
//
void progressbar(size_t now, size_t total) {
    int progress = ((double) now / (double) total) * 50;

    printf("[");
    for(int i = 0; i < progress; i++)
        printf("=");

    for(int i = progress; i < 50; i++)
        printf(".");

    printf("]\r");

    fflush(stdout);
}

void progress(unsigned int clientid, char *status, size_t now, size_t total) {
    printf("\r[+] client %u, %s: ", clientid, status);
    progressbar(now, total);
}

void progressdone(unsigned int clientid, char *status) {
    printf("\r[+] client %u, %s: ", clientid, status);
    progressbar(100, 100);
    printf("\n");
}

//
// redis
//
benchmark_t *benchmark_init() {
    benchmark_t *bench;

    if(!(bench = calloc(sizeof(benchmark_t), 1)))
        diep("malloc");

    return bench;
}

//
// benchmark passes
//
static void *benchmark_pass_write(void *data) {
    benchmark_t *b = (benchmark_t *) data;

    gettimeofday(&b->write.rtime_begin, NULL);
    b->write.time_begin = clock();

    for(unsigned int i = 0; i < b->chunks; i++) {
        // reply = redisCommand(b->redis, "SET %b %b", b->hashes[i], SHA256_DIGEST_LENGTH, b->buffers[i], b->chunksize);
        buffer_t value = b->pass_write(b->kntxt, b->hashes[i], SHA256_DIGEST_LENGTH, b->buffers[i], b->chunksize);

        if((i % ((b->chunks > 1024 ? b->chunks / 128 : 2))) == 0)
            progress(b->id, "writing chunks  ", i, b->chunks);

        b->sizes[i] = value.length;
        b->responses[i] = value.data;

        b->write.success += 1;
    }

    progressdone(b->id, "writing chunks  ");

    if(b->pass_write_done)
        b->pass_write_done(b->kntxt);

    b->write.time_end = clock();
    gettimeofday(&b->write.rtime_end, NULL);

    return NULL;
}

static void *benchmark_pass_read(void *data) {
    benchmark_t *b = (benchmark_t *) data;

    gettimeofday(&b->read.rtime_begin, NULL);
    b->read.time_begin = clock();

    for(unsigned int i = 0; i < b->chunks; i++) {
        // ask response and discard it directly (no check)
        buffer_t value = b->pass_read(b->kntxt, b->responses[i], b->sizes[i]);
        free(value.data);

        if((i % ((b->chunks > 1024 ? b->chunks / 128 : 2))) == 0)
            progress(b->id, "reading (simple)", i, b->chunks);

        b->read.success += 1;
    }

    progressdone(b->id, "reading (simple)");

    if(b->pass_read_done)
        b->pass_read_done(b->kntxt);

    b->read.time_end = clock();
    gettimeofday(&b->read.rtime_end, NULL);

    return NULL;
}

static void *benchmark_pass_read_secure(void *data) {
    benchmark_t *b = (benchmark_t *) data;

    gettimeofday(&b->secread.rtime_begin, NULL);
    b->secread.time_begin = clock();

    for(unsigned int i = 0; i < b->chunks; i++) {
        // ask response and compare hash
        buffer_t value = b->pass_read(b->kntxt, b->responses[i], b->sizes[i]);

        unsigned char *hash = sha256(value.data, value.length);

        // compare hashes
        if(memcmp(hash, b->hashes[i], SHA256_DIGEST_LENGTH)) {
            char *expected = sha256hex(b->hashes[i]);
            char *received = sha256hex(hash);

            fprintf(stderr, "\n[-] hash mismatch: %s\n", received);
            fprintf(stderr, "[-] hash expected: %s\n", expected);
            fprintf(stderr, "[-] size expected: %d, received: %lu\n", b->chunksize, value.length);

            free(expected);
            free(received);
        }

        if((i % ((b->chunks > 1024 ? b->chunks / 128 : 2))) == 0)
            progress(b->id, "reading (secure)", i, b->chunks);

        free(value.data);
    }

    progressdone(b->id, "reading (secure)");

    if(b->pass_read_done)
        b->pass_read_done(b->kntxt);

    b->secread.time_end = clock();
    gettimeofday(&b->secread.rtime_end, NULL);

    return NULL;
}

//
// buffers
//
static size_t randomize(unsigned char *buffer, size_t length) {
    int rnd = open("/dev/urandom", O_RDONLY);
    size_t rndread = 0;
    ssize_t result;

    while (rndread < length) {
        if((result = read(rnd, buffer + rndread, length - rndread)) < 0)
            diep("read");

        rndread += result;
    }

    close(rnd);

    return rndread;
}

static unsigned char *benchmark_buffer_generate(benchmark_t *bench, size_t buffer) {
    if(!(bench->buffers[buffer] = (unsigned char *) malloc(sizeof(char) * bench->chunksize)))
        diep("malloc: buffer");

    if(randomize(bench->buffers[buffer], bench->chunksize) != bench->chunksize) {
        fprintf(stderr, "[-] not enought random data\n");
        exit(EXIT_FAILURE);
    }

    bench->hashes[buffer] = sha256(bench->buffers[buffer], bench->chunksize);

    // if(buffer % 16 == 0)
    //    progress(bench->id, "generating data ", buffer, bench->chunks);

    return bench->hashes[buffer];
}

static benchmark_t *benchmark_generate(benchmark_t *bench) {
    printf("[+] allocating buffers [client %u]\n", bench->id);

    // allocating memory for hashes
    if(!(bench->hashes = (unsigned char **) malloc(sizeof(char *) * bench->chunks)))
        diep("malloc: hashes");

    // allocating memory for buffers
    if(!(bench->buffers = (unsigned char **) malloc(sizeof(char *) * bench->chunks)))
        diep("malloc: buffers");

    // allocating memory for responses
    if(!(bench->responses = (unsigned char **) malloc(sizeof(char *) * bench->chunks)))
        diep("malloc: responses");

    // allocating memory for responses
    if(!(bench->sizes = (size_t *) malloc(sizeof(size_t) * bench->chunks)))
        diep("malloc: sizes");

    size_t datasize = (size_t) bench->chunks * bench->chunksize;
    printf("[+] generator: will allocate %u keys (payload: %u bytes)\n", bench->chunks, bench->chunksize);
    printf("[+] generator: payload memory usage: %.2f MB\n", datasize / (1024 * 1024.0));
    printf("[+] generator: hashkey memory usage: %.2f MB\n", (bench->chunks * SHA256_DIGEST_LENGTH) / (1024 * 1024.0));

    // generating buffers
    unsigned int computed = 0;

    #pragma omp parallel for
    for(unsigned int buffer = 0; buffer < bench->chunks; buffer++) {
        benchmark_buffer_generate(bench, buffer);

        if(++computed % 16 != 0)
            continue;

        #pragma omp critical
        {
            progress(bench->id, "generating data ", computed, bench->chunks);
        }
    }

    progressdone(bench->id, "generating data ");

    return bench;
}

static double benchmark_time_spent(struct timeval *timer) {
    return (((size_t) timer->tv_sec * 1000000) + timer->tv_usec) / 1000000.0;
}

static double benchmark_speed(size_t size, double timed) {
    return (size / timed) / (1024 * 1024);
}

void benchmark_statistics_passes(benchmark_t *bench) {
    // double wtime = (double)(bench->write.time_end - bench->write.time_begin) / CLOCKS_PER_SEC;
    // double rtime = (double)(bench->read.time_end - bench->read.time_begin) / CLOCKS_PER_SEC;

    double wrtime = benchmark_time_spent(&bench->write.rtime_end) - benchmark_time_spent(&bench->write.rtime_begin);
    double rrtime = benchmark_time_spent(&bench->read.rtime_end) - benchmark_time_spent(&bench->read.rtime_begin);
    double secrrtime = benchmark_time_spent(&bench->secread.rtime_end) - benchmark_time_spent(&bench->secread.rtime_begin);

    float chunkskb = bench->chunksize / 1024.0;
    // double wspeed = benchmark_speed(bench->chunksize * bench->chunks, wtime);
    // double rspeed = benchmark_speed(bench->chunksize * bench->chunks, rtime);

    double wrspeed = benchmark_speed((size_t) bench->chunksize * bench->chunks, wrtime);
    double rrspeed = benchmark_speed((size_t) bench->chunksize * bench->chunks, rrtime);
    double secrrspeed = benchmark_speed((size_t) bench->chunksize * bench->chunks, secrrtime);

    printf("[+] --- client %u ---\n", bench->id);
    /*
    printf("[+] sys write: %u keys of %.2f KB uploaded in %.2f seconds\n", bench->write.success, chunkskb, wtime);
    printf("[+] sys read : %u keys of %.2f KB uploaded in %.2f seconds\n", bench->read.success, chunkskb, rtime);

    printf("[+] sys write: client speed: %.2f MB/s\n", wspeed);
    printf("[+] sys read : client speed: %.2f MB/s\n", rspeed);
    */

    printf("[+] user write: %u keys [%.2f KB] in %.2f sec, %.1f k/s\n", bench->write.success, chunkskb, wrtime, bench->write.success / wrtime);
    printf("[+] user read : %u keys [%.2f KB] in %.2f sec, %.1f k/s\n", bench->read.success, chunkskb, rrtime, bench->read.success / rrtime);

    printf("[+] default write: %.2f MB/s\n", wrspeed);
    printf("[+] regular read : %.2f MB/s\n", rrspeed);
    printf("[+] secure  read : %.2f MB/s\n", secrrspeed);
}

void benchmark_statistics_summary(benchmark_t **benchs, unsigned int length) {
    double readtime = 0;
    double writetime = 0;
    double readspeed = 0;
    double writespeed = 0;

    for(unsigned int i = 0; i < length; i++) {
        benchmark_t *bench = benchs[i];

        readtime = benchmark_time_spent(&bench->read.rtime_end) - benchmark_time_spent(&bench->read.rtime_begin);
        writetime = benchmark_time_spent(&bench->write.rtime_end) - benchmark_time_spent(&bench->write.rtime_begin);

        readspeed += benchmark_speed((size_t) bench->chunksize * bench->chunks, readtime);
        writespeed += benchmark_speed((size_t) bench->chunksize * bench->chunks, writetime);
    }

    printf("[+] read speed: %.3f MB/s\n", readspeed);
    printf("[+] write speed: %.3f MB/s\n", writespeed);
}

void benchmark_passes(benchmark_t **benchs, unsigned int length) {
    //
    // starting write pass
    // during this pass, buffers are written to the backend
    //

    // printf("[+] starting pass: write\n");
    for(unsigned int i = 0; i < length; i++)
        if(pthread_create(&benchs[i]->pthread, NULL, benchmark_pass_write, benchs[i]))
            diep("pthread_create");

    for(unsigned int i = 0; i < length; i++)
        pthread_join(benchs[i]->pthread, NULL);

    //
    // starting read pass
    // during this pass, we get hashes keys but we don't do anything with them
    //

    //printf("[+] starting pass: read, simple\n");
    for(unsigned int i = 0; i < length; i++)
        if(pthread_create(&benchs[i]->pthread, NULL, benchmark_pass_read, benchs[i]))
            diep("pthread_create");

    for(unsigned int i = 0; i < length; i++)
        pthread_join(benchs[i]->pthread, NULL);

    //
    // starting read secure pass
    // during this pass, we get hashes keys from backend and data hashes of
    // data are compared to keys to check data consistancy, we don't mesure time
    // of this pass because hashing time is not related to backend read/write
    //

    // printf("[+] starting pass: read, secure\n");
    for(unsigned int i = 0; i < length; i++)
        if(pthread_create(&benchs[i]->pthread, NULL, benchmark_pass_read_secure, benchs[i]))
            diep("pthread_create");

    for(unsigned int i = 0; i < length; i++)
        pthread_join(benchs[i]->pthread, NULL);
}

int benchmark_run(benchsuite_t *suite) {
    printf("\033[?25l");

    //
    // allocating and fill buffers with random data
    // computing hash of buffers, which will be used as keys
    //
    printf("[+] generating random buffers\n");
    for(unsigned int i = 0; i < suite->length; i++)
        benchmark_generate(suite->benchmarks[i]);

    //
    // running benchmark's differents passes
    //
    printf("[+] running passes\n");
    benchmark_passes(suite->benchmarks, suite->length);

    printf("\033[?25h");
}


int benchmark_statistics(benchsuite_t *suite) {
    // collecting and computing statistics per client (speed, ...)
    printf("[+] collecting statistics\n");
    for(unsigned int i = 0; i < suite->length; i++)
        benchmark_statistics_passes(suite->benchmarks[i]);

    printf("[+] \n");
    printf("[+] final statistics\n");
    printf("[+] ==========================================\n");
    benchmark_statistics_summary(suite->benchmarks, suite->length);

    printf("\033[?25h");

    return 0;
}

static int signal_intercept(int signal, void (*function)(int)) {
    struct sigaction sig;
    int ret;

    sigemptyset(&sig.sa_mask);
    sig.sa_handler = function;
    sig.sa_flags   = 0;

    if((ret = sigaction(signal, &sig, NULL)) == -1)
        diep("sigaction");

    return ret;
}

static void sighandler(int signal) {
    if(signal == SIGSEGV)
        printf("\n[-] segmentation fault");

    if(signal == SIGFPE)
        printf("\n[-] floating point exception");

    printf("\n[+] stopping\n");
    printf("\033[?25h");

    // forwarding original error code
    exit(128 + signal);
}

benchsuite_t *benchmark_initialize(size_t chunksize, size_t chunks, size_t clients) {
    benchmark_t **remotes;
    unsigned int threads = clients;

    signal_intercept(SIGINT, sighandler);
    signal_intercept(SIGSEGV, sighandler);
    signal_intercept(SIGFPE, sighandler);

    // initializing
    printf("[+] benchmark: initializing\n");
    if(!(remotes = (benchmark_t **) malloc(sizeof(benchmark_t *) * threads)))
        diep("malloc");

    printf("[+] benchmark: %lu threads\n", clients);
    printf("[+] benchmark: %lu chunks of %lu bytes\n", chunks, chunksize);

    //
    // connecting clients
    //
    printf("[+] benchmark: initializing threads\n");
    for(unsigned int i = 0; i < threads; i++) {
        if(!(remotes[i] = benchmark_init())) {
            fprintf(stderr, "[-] cannot allocate benchmark\n");
            exit(EXIT_FAILURE);
        }

        remotes[i]->id = i;
        remotes[i]->chunksize = chunksize;
        remotes[i]->chunks = chunks;
    }

    // build response
    benchsuite_t *suite = malloc(sizeof(benchsuite_t));
    suite->benchmarks = remotes;
    suite->length = threads;

    return suite;
}

