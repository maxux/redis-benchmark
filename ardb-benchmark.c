#include <stdio.h>
#include <stdlib.h>
#include <hiredis.h>
#include <time.h>
#include <string.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>
#include <fcntl.h>
#include "openssl/sha.h"

#define CHUNKSIZE     512   // 16 KB
#define CHUNKS        32768         // 4096 chunks of 8 KB per client

#define SHA256LEN     (size_t) SHA256_DIGEST_LENGTH * 2

typedef struct benchmark_pass_t {
    unsigned int success;    // upload success
    clock_t time_begin;      // init time
    clock_t time_end;        // end time
    struct timeval rtime_begin;
    struct timeval rtime_end;

} benchmark_pass_t;

typedef struct benchmark_t {
    unsigned int id;          // benchmark unique id
    redisContext *redis;      // redis context
    pthread_t pthread;        // thread context

    unsigned int chunksize;   // chunk size
    unsigned int chunks;      // chunks length
    unsigned char **buffers;  // chunks buffers
    char **hashes;   // chunks hashes
    char **responses;

    struct benchmark_pass_t read;
    struct benchmark_pass_t secread;
    struct benchmark_pass_t write;

} benchmark_t;

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

static char *sha256(const unsigned char *buffer, size_t length) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;

    SHA256_Init(&sha256);
    SHA256_Update(&sha256, buffer, length);
    SHA256_Final(hash, &sha256);

    return sha256hex(hash);
}

//
// redis
//
benchmark_t *benchmark_init(const char *host, int port) {
    struct timeval timeout = {5, 0};
    benchmark_t *bench;
    redisReply *reply;

    if(!(bench = calloc(sizeof(benchmark_t), 1)))
        diep("malloc");

    bench->redis = redisConnectWithTimeout(host, port, timeout);
    if(bench->redis == NULL || bench->redis->err) {
        printf("[-] redis: %s\n", (bench->redis->err) ? bench->redis->errstr : "memory error.");
        return NULL;
    }

    // ping redis to ensure connection
    reply = redisCommand(bench->redis, "PING");
    if(strcmp(reply->str, "PONG"))
        fprintf(stderr, "[-] warning, invalid redis PING response: %s\n", reply->str);

    freeReplyObject(reply);

    return bench;
}

//
// benchmark passes
//
static void *benchmark_pass_write(void *data) {
    benchmark_t *b = (benchmark_t *) data;
    redisReply *reply;

    gettimeofday(&b->write.rtime_begin, NULL);
    b->write.time_begin = clock();

    for(unsigned int i = 0; i < b->chunks; i++) {
        reply = redisCommand(b->redis, "SET %b %b", b->hashes[i], SHA256LEN, b->buffers[i], b->chunksize);
        // reply = redisCommand(b->redis, "SET X %b", b->buffers[i], b->chunksize);
        // printf("[+] uploading: %s: %s\n", bench->hashes[i], reply->str);
        printf("[+] uploading chunk %d: %s\n", i, reply->str);
        b->responses[i] = strdup(reply->str);

        freeReplyObject(reply);

        b->write.success += 1;
    }

    b->write.time_end = clock();
    gettimeofday(&b->write.rtime_end, NULL);

    return NULL;
}

static void *benchmark_pass_read(void *data) {
    benchmark_t *b = (benchmark_t *) data;
    redisReply *reply;

    gettimeofday(&b->read.rtime_begin, NULL);
    b->read.time_begin = clock();

    for(unsigned int i = 0; i < b->chunks; i++) {
        reply = redisCommand(b->redis, "GET %s", b->responses[i], strlen(b->responses[i]));
        // printf("[+] downloaded: %s\n", bench->hashes[i]);
        freeReplyObject(reply);

        b->read.success += 1;
    }

    b->read.time_end = clock();
    gettimeofday(&b->read.rtime_end, NULL);

    return NULL;
}

static void *benchmark_pass_read_secure(void *data) {
    benchmark_t *b = (benchmark_t *) data;
    redisReply *reply;

    gettimeofday(&b->secread.rtime_begin, NULL);
    b->secread.time_begin = clock();

    for(unsigned int i = 0; i < b->chunks; i++) {
        reply = redisCommand(b->redis, "GET %s", b->responses[i], strlen(b->responses[i]));
        // printf("[+] downloaded: %s\n", bench->hashes[i]);

        char *hash = sha256((unsigned char *) reply->str, reply->len);

        // compare hashes
        if(strcmp((const char *) hash, (const char *) b->hashes[i])) {
            fprintf(stderr, "[-] hash mismatch: %s <> %s\n", hash, b->hashes[i]);
            // exit(EXIT_FAILURE);
        }

        freeReplyObject(reply);
    }

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

static char *benchmark_buffer_generate(benchmark_t *bench, size_t buffer) {
    if(!(bench->buffers[buffer] = (unsigned char *) malloc(sizeof(char) * bench->chunksize)))
        diep("malloc: buffer");

    if(randomize(bench->buffers[buffer], bench->chunksize) != bench->chunksize) {
        fprintf(stderr, "[-] not enought random data\n");
        exit(EXIT_FAILURE);
    }

    bench->hashes[buffer] = sha256(bench->buffers[buffer], bench->chunksize);
    printf("[+] client %u, buffer %lu: %s\n", bench->id, buffer, bench->hashes[buffer]);

    return bench->hashes[buffer];
}

static benchmark_t *benchmark_generate(benchmark_t *bench) {
    printf("[+] allocating buffers [client %u]\n", bench->id);

    // allocating memory for hashes
    if(!(bench->hashes = (char **) malloc(sizeof(char *) * bench->chunks)))
        diep("malloc: hashes");

    // allocating memory for buffers
    if(!(bench->buffers = (unsigned char **) malloc(sizeof(char *) * bench->chunks)))
        diep("malloc: buffers");

    // allocating memory for responses
    if(!(bench->responses = (char **) malloc(sizeof(char *) * bench->chunks)))
        diep("malloc: responses");

    // generating buffers
    for(unsigned int buffer = 0; buffer < bench->chunks; buffer++)
        benchmark_buffer_generate(bench, buffer);

    return bench;
}

void benchmark_statistics(benchmark_t *bench) {
    double wtime = (double)(bench->write.time_end - bench->write.time_begin) / CLOCKS_PER_SEC;
    double rtime = (double)(bench->read.time_end - bench->read.time_begin) / CLOCKS_PER_SEC;

    double wbreal = (((unsigned long long) bench->write.rtime_begin.tv_sec * 1000000) + bench->write.rtime_begin.tv_usec) / 1000000.0;
    double wereal = (((unsigned long long) bench->write.rtime_end.tv_sec * 1000000) + bench->write.rtime_end.tv_usec) / 1000000.0;
    double rbreal = (((unsigned long long) bench->read.rtime_begin.tv_sec * 1000000) + bench->read.rtime_begin.tv_usec) / 1000000.0;
    double rereal = (((unsigned long long) bench->read.rtime_end.tv_sec * 1000000) + bench->read.rtime_end.tv_usec) / 1000000.0;
    double secrbreal = (((unsigned long long) bench->secread.rtime_begin.tv_sec * 1000000) + bench->secread.rtime_begin.tv_usec) / 1000000.0;
    double secrereal = (((unsigned long long) bench->secread.rtime_end.tv_sec * 1000000) + bench->secread.rtime_end.tv_usec) / 1000000.0;

    double wrtime = wereal - wbreal;
    double rrtime = rereal - rbreal;
    double secrrtime = secrereal - secrbreal;

    float chunkskb = bench->chunksize / 1024.0;
    float wspeed = ((bench->chunksize * bench->chunks) / wtime) / (1024 * 1024);
    float rspeed = ((bench->chunksize * bench->chunks) / rtime) / (1024 * 1024);

    float wrspeed = ((bench->chunksize * bench->chunks) / wrtime) / (1024 * 1024);
    float rrspeed = ((bench->chunksize * bench->chunks) / rrtime) / (1024 * 1024);
    float secrrspeed = ((bench->chunksize * bench->chunks) / secrrtime) / (1024 * 1024);

    printf("[+] --- client %u ---\n", bench->id);
    printf("[+] sys write: %u keys of %.2f KB uploaded in %.2f seconds\n", bench->write.success, chunkskb, wtime);
    printf("[+] sys read : %u keys of %.2f KB uploaded in %.2f seconds\n", bench->read.success, chunkskb, rtime);

    printf("[+] sys write: client speed: %.2f MB/s\n", wspeed);
    printf("[+] sys read : client speed: %.2f MB/s\n", rspeed);

    printf("[+] user write: %u keys of %.2f KB uploaded in %.2f seconds\n", bench->write.success, chunkskb, wrtime);
    printf("[+] user read : %u keys of %.2f KB uploaded in %.2f seconds\n", bench->read.success, chunkskb, rrtime);

    printf("[+] user write: client speed: %.2f MB/s\n", wrspeed);
    printf("[+] reg user read : client speed: %.2f MB/s\n", rrspeed);
    printf("[+] sec user read : client speed: %.2f MB/s\n", secrrspeed);
}

void benchmark_passes(benchmark_t **benchs, unsigned int length) {
    //
    // starting write pass
    // during this pass, buffers are written to the backend
    //
    printf("[+] starting pass: write\n");
    for(unsigned int i = 0; i < length; i++)
        if(pthread_create(&benchs[i]->pthread, NULL, benchmark_pass_write, benchs[i]))
            diep("pthread_create");

    for(unsigned int i = 0; i < length; i++)
        pthread_join(benchs[i]->pthread, NULL);

    //
    // starting read pass
    // during this pass, we get hashes keys but we don't do anything with them
    //
    printf("[+] starting pass: read, simple\n");
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
    printf("[+] starting pass: read, secure\n");
    for(unsigned int i = 0; i < length; i++)
        if(pthread_create(&benchs[i]->pthread, NULL, benchmark_pass_read_secure, benchs[i]))
            diep("pthread_create");

    for(unsigned int i = 0; i < length; i++)
        pthread_join(benchs[i]->pthread, NULL);
}

int benchmark(benchmark_t **benchs, unsigned int length) {
    //
    // allocating and fill buffers with random data
    // computing hash of buffers, which will be used as keys
    //
    printf("[+] generating random buffers\n");
    for(unsigned int i = 0; i < length; i++)
        benchmark_generate(benchs[i]);

    //
    // running benchmark's differents passes
    //
    printf("[+] running passes\n");
    benchmark_passes(benchs, length);

    //
    // collecting and computing statistics per client (speed, ...)
    //
    printf("[+] collecting statistics\n");
    for(unsigned int i = 0; i < length; i++)
        benchmark_statistics(benchs[i]);

    return 0;
}

int main(int argc, char *argv[]) {
    benchmark_t **remotes;
    unsigned int threads = 1;

    //
    // settings
    //
    if(argc > 1)
        threads = atoi(argv[1]);

    if(threads < 1 || threads > 16) {
        fprintf(stderr, "[-] invalid threads count\n");
        exit(EXIT_FAILURE);
    }

    //
    // initializing
    //
    printf("[+] initializing\n");
    if(!(remotes = (benchmark_t **) malloc(sizeof(benchmark_t *) * threads)))
        diep("malloc");

    //
    // connecting clients
    //
    printf("[+] connecting redis [%d threads]\n", threads);
    for(unsigned int i = 0; i < threads; i++) {
        if(!(remotes[i] = benchmark_init("127.0.0.1", 9900))) {
            fprintf(stderr, "[-] cannot allocate benchmark\n");
            exit(EXIT_FAILURE);
        }

        remotes[i]->id = i;
        remotes[i]->chunksize = CHUNKSIZE;
        remotes[i]->chunks = CHUNKS;
    }

    //
    // starting benchmarks process
    //
    return benchmark(remotes, threads);
}