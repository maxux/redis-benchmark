#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>
#include <time.h>
#include <hiredis/hiredis.h>
#include "generator.h"

#define DEFAULT_CHUNKSIZE     4 * 1024  // 4 KB payload
#define DEFAULT_CHUNKS        8 * 1024  // 8192 keys

static struct option long_options[] = {
    {"size",    required_argument, 0, 's'},
    {"keys",    required_argument, 0, 'k'},
    {"threads", required_argument, 0, 't'},
    {"host",    required_argument, 0, 'h'},
    {"port",    required_argument, 0, 'p'},
    {0, 0, 0, 0}
};

typedef struct zdb_kntxt_t {
    redisContext *redis;
    char *host;
    int port;

} zdb_kntxt_t;

void *kntxt_init(char *host, int port) {
    struct timeval timeout = {5, 0};
    zdb_kntxt_t *kntxt;

    if(!(kntxt = malloc(sizeof(zdb_kntxt_t))))
        diep("malloc");

    kntxt->redis = redisConnectWithTimeout(host, port, timeout);
    if(kntxt->redis == NULL || kntxt->redis->err) {
        printf("[-] redis: %s\n", (kntxt->redis->err) ? kntxt->redis->errstr : "memory error");
        return NULL;
    }

    // ping redis to ensure connection
    redisReply *reply = redisCommand(kntxt->redis, "PING");
    if(strcmp(reply->str, "PONG"))
        fprintf(stderr, "[-] warning, invalid redis PING response: %s\n", reply->str);

    freeReplyObject(reply);

    return kntxt;
}

int callback_close(void *kntxt) {
    return 0;
}

buffer_t callback_pass_write(void *ptr, unsigned char *key, size_t keylen, unsigned char *data, size_t datalen) {
    zdb_kntxt_t *kntxt = (zdb_kntxt_t *) ptr;
    redisReply *reply;
    buffer_t buffer = {
        .data = NULL,
        .length = 0,
    };

    reply = redisCommand(kntxt->redis, "SET %b %b", key, keylen, data, datalen);

    if(reply->len == 0 || reply->type == REDIS_REPLY_ERROR) {
        if(reply->len == 0)
            fprintf(stderr, "\n[-] write: empty response\n");

        if(reply->type == REDIS_REPLY_ERROR)
            fprintf(stderr, "\n[-] write: invalid response: %.*s\n", (int) reply->len, reply->str);

        freeReplyObject(reply);
        return buffer;
    }

    buffer.data = reply->str;
    buffer.length = reply->len;

    // freeReplyObject(reply);

    return buffer;
}

int callback_pass_write_done(void *kntxt) {
    return 0;
}

buffer_t callback_pass_read(void *ptr, unsigned char *key, size_t keylen) {
    zdb_kntxt_t *kntxt = (zdb_kntxt_t *) ptr;
    redisReply *reply;
    buffer_t buffer = {
        .data = NULL,
        .length = 0,
    };

    reply = redisCommand(kntxt->redis, "GET %b", key, keylen);

    buffer.data = reply->str;
    buffer.length = reply->len;

    return buffer;
}

int callback_pass_read_done(void *kntxt) {
    return 0;
}

int main(int argc, char *argv[]) {
    int option_index = 0;
    size_t chunksize = DEFAULT_CHUNKSIZE;
    size_t chunks = DEFAULT_CHUNKS;
    size_t clients = 1;
    char *remote = "localhost";
    int port = 9900;

    while(1) {
        int i = getopt_long_only(argc, argv, "", long_options, &option_index);

        if(i == -1)
            break;

        switch(i) {
            case 's':
                chunksize = atoi(optarg);
                break;

            case 'k':
                chunks = atoi(optarg);
                break;

            case 't':
                clients = atoi(optarg);
                break;

            case 'h':
                remote = optarg;
                break;

            case 'p':
                port = atoi(optarg);
                break;

            case '?':
            default:
               printf("Usage: %s [--size payload-size] [--keys count] [--threads clients]\n", argv[0]);
               printf("       %s [--host hostname] [--port port]\n", argv[0]);
               exit(EXIT_FAILURE);
        }
    }

    benchsuite_t *benchmarks = benchmark_initialize(chunksize, chunks, clients);

    // setup callbacks
    for(size_t i = 0; i < benchmarks->length; i++) {
        benchmarks->benchmarks[i]->kntxt = kntxt_init(remote, port);
        benchmarks->benchmarks[i]->pass_write = callback_pass_write;
        benchmarks->benchmarks[i]->pass_write_done = callback_pass_write_done;
        benchmarks->benchmarks[i]->pass_read = callback_pass_read;
        benchmarks->benchmarks[i]->pass_read_done = callback_pass_read_done;
        benchmarks->benchmarks[i]->close = callback_close;
    }

    // run benchmark
    benchmark_run(benchmarks);

    // show statistics
    benchmark_statistics(benchmarks);

    return 0;
}
