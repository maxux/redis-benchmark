// gcc -o  ardb-benchmark ardb-benchmark.c -W -Wall -O2 -pthread -I/usr/include/hiredis -lhiredis -lpthread -lssl -lcrypto

#include <stdio.h>
#include <stdlib.h>
#include <hiredis.h>
#include <time.h>
#include <string.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include "openssl/sha.h"

#define CHUNKSIZE     16 * 1024   // 16 KB
#define CHUNKS        4096        // 4096 chunks of 16 KB per client

#define SHA256LEN     (size_t) SHA256_DIGEST_LENGTH * 2

typedef struct benchmark_pass_t {
    unsigned int success;    // upload success
    clock_t time_begin;      // init time
    clock_t time_end;        // end time

} benchmark_pass_t;

typedef struct benchmark_t {
    unsigned int id;          // benchmark unique id
    redisContext *redis;      // redis context
    pthread_t pthread;        // thread context

    unsigned int chunksize;   // chunk size
    unsigned int chunks;      // chunks length
    unsigned char **buffers;  // chunks buffers
    unsigned char **hashes;   // chunks hashes

    struct benchmark_pass_t read;
    struct benchmark_pass_t write;

} benchmark_t;

void diep(char *str) {
    perror(str);
    exit(EXIT_FAILURE);
}

//
// hashing
//
static unsigned char *sha256hex(unsigned char *hash) {
    unsigned char *buffer = calloc((SHA256_DIGEST_LENGTH * 2) + 1, sizeof(char));

    for(int i = 0; i < SHA256_DIGEST_LENGTH; i++)
        sprintf((char *) buffer + (i * 2), "%02x", hash[i]);

    return buffer;
}

static unsigned char *sha256(const unsigned char *buffer, size_t length) {
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

    b->write.time_begin = clock();

    for(unsigned int i = 0; i < b->chunks; i++) {
        reply = redisCommand(b->redis, "SET %b %b", b->hashes[i], SHA256LEN, b->buffers[i], b->chunksize);
        // printf("[+] uploading: %s: %s\n", bench->hashes[i], reply->str);
        freeReplyObject(reply);

        b->write.success += 1;
    }

    b->write.time_end = clock();

    return NULL;
}

static void *benchmark_pass_read(void *data) {
    benchmark_t *b = (benchmark_t *) data;
    redisReply *reply;

    b->read.time_begin = clock();

    for(unsigned int i = 0; i < b->chunks; i++) {
        reply = redisCommand(b->redis, "GET %b", b->hashes[i], SHA256LEN);
        // printf("[+] downloaded: %s\n", bench->hashes[i]);
        freeReplyObject(reply);

        b->read.success += 1;
    }

    b->read.time_end = clock();

    return NULL;
}

static void *benchmark_pass_read_secure(void *data) {
    benchmark_t *b = (benchmark_t *) data;
    redisReply *reply;

    for(unsigned int i = 0; i < b->chunks; i++) {
        reply = redisCommand(b->redis, "GET %b", b->hashes[i], SHA256LEN);
        // printf("[+] downloaded: %s\n", bench->hashes[i]);

        unsigned char *hash = sha256((unsigned char *) reply->str, reply->len);

        // compare hashes
        if(strcmp((const char *) hash, (const char *) b->hashes[i])) {
            fprintf(stderr, "[-] hash mismatch: %s <> %s\n", hash, b->hashes[i]);
            // exit(EXIT_FAILURE);
        }

        freeReplyObject(reply);
    }

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
    printf("[+] client %u, buffer %lu: %s\n", bench->id, buffer, bench->hashes[buffer]);

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

    // generating buffers
    for(unsigned int buffer = 0; buffer < bench->chunks; buffer++)
        benchmark_buffer_generate(bench, buffer);

    return bench;
}

void benchmark_statistics(benchmark_t *bench) {
    double wtime = (double)(bench->write.time_end - bench->write.time_begin) / CLOCKS_PER_SEC;
    double rtime = (double)(bench->read.time_end - bench->read.time_begin) / CLOCKS_PER_SEC;

    float chunkskb = bench->chunksize / 1024.0;
    float wspeed = ((bench->chunksize * bench->chunks) / wtime) / (1024 * 1024);
    float rspeed = ((bench->chunksize * bench->chunks) / rtime) / (1024 * 1024);

    printf("[+] --- client %u ---\n", bench->id);
    printf("[+] write: %u keys of %.2f KB uploaded in %.2f seconds\n", bench->write.success, chunkskb, wtime);
    printf("[+] read : %u keys of %.2f KB uploaded in %.2f seconds\n", bench->read.success, chunkskb, rtime);

    printf("[+] write: client speed: %.2f MB/s\n", wspeed);
    printf("[+] read : client speed: %.2f MB/s\n", rspeed);
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
    unsigned int threads = 4;

    //
    // settings
    //
    if(argc > 1)
        threads = atoi(threads);

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
        if(!(remotes[i] = benchmark_init("172.17.0.4", 16379))) {
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
