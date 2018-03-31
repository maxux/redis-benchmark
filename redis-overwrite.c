#include <stdio.h>
#include <stdlib.h>
#include <hiredis.h>
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

#define DEFAULT_CHUNKSIZE     4 * 1024  // 4 KB payload

static struct option long_options[] = {
    {"size",    required_argument, 0, 's'},
    {"threads", required_argument, 0, 't'},
    {"host",    required_argument, 0, 'h'},
    {"port",    required_argument, 0, 'p'},
    {0, 0, 0, 0}
};

size_t rootchunksize = DEFAULT_CHUNKSIZE;
size_t rootclients = 1;
char *rootremote = "localhost";
int rootport = 9900;

typedef struct benchmark_t {
    unsigned int id;          // benchmark unique id
    redisContext *redis;      // redis context
    pthread_t pthread;        // thread context

    unsigned int chunksize;   // chunk size
    unsigned int chunks;      // chunk length

} benchmark_t;

void diep(char *str) {
    perror(str);
    exit(EXIT_FAILURE);
}

benchmark_t *benchmark_init(const char *host, int port) {
    struct timeval timeout = {5, 0};
    benchmark_t *bench;
    redisReply *reply;

    if(!(bench = calloc(sizeof(benchmark_t), 1)))
        diep("malloc");

    bench->redis = redisConnectWithTimeout(host, port, timeout);
    if(bench->redis == NULL || bench->redis->err) {
        printf("[-] redis: %s\n", (bench->redis->err) ? bench->redis->errstr : "memory error");
        return NULL;
    }

    // ping redis to ensure connection
    reply = redisCommand(bench->redis, "PING");
    if(strcmp(reply->str, "PONG"))
        fprintf(stderr, "[-] warning, invalid redis PING response: %s\n", reply->str);

    freeReplyObject(reply);

    return bench;
}

int benchmark_write(benchmark_t *bench, char *key, char *payload) {
    int value = 0;

    redisReply *reply;

    reply = redisCommand(bench->redis, "SET %s %s", key, payload);
    value = reply->len;

    freeReplyObject(reply);

    return value;
}

char *benchmark_read(benchmark_t *bench, char *key) {
    redisReply *reply;
    char *payload = NULL;

    reply = redisCommand(bench->redis, "GET %s", key, payload);
    payload = strdup(reply->str);

    freeReplyObject(reply);

    return payload;
}

int benchmark(benchmark_t **benchs, unsigned int length) {
    (void) length;
    benchmark_t *bench = *benchs;
    char key[64];
    unsigned int size = 512;
    unsigned int keys = 1 * 1024 * 512;
    char *source = NULL;

    if(!(source = calloc(sizeof(char), size + 1)))
        diep("malloc");

    printf("[+] writing first values\n");

    memset(source, 'a', size);

    for(unsigned int i = 0; i < keys; i++) {
        sprintf(key, "%d", i);
        benchmark_write(bench, key, source);
    }

    printf("[+] writing seconds values\n");

    memset(source, 'x', size);

    for(unsigned int i = 0; i < keys; i++) {
        sprintf(key, "%d", i);
        benchmark_write(bench, key, source);
    }

    printf("[+] checking values\n");

    for(unsigned int i = 0; i < keys; i++) {
        sprintf(key, "%d", i);
        char *payload = benchmark_read(bench, key);

        if(strcmp(payload, source) != 0) {
            printf("[-] key %d mismatch\n", i);
            exit(EXIT_FAILURE);
        }

        free(payload);
    }

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

benchmark_t **remotes;
unsigned int threads = 0;

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


int initialize() {
    threads = rootclients;

    signal_intercept(SIGINT, sighandler);
    signal_intercept(SIGSEGV, sighandler);
    signal_intercept(SIGFPE, sighandler);

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
        if(!(remotes[i] = benchmark_init(rootremote, rootport))) {
            fprintf(stderr, "[-] cannot allocate benchmark\n");
            exit(EXIT_FAILURE);
        }

        remotes[i]->id = i;
        remotes[i]->chunksize = rootchunksize;
    }

    //
    // starting benchmarks process
    //
    return benchmark(remotes, threads);
}

int main(int argc, char *argv[]) {
    int option_index = 0;

    while(1) {
        // int i = getopt_long_only(argc, argv, "d:i:l:p:vxh", long_options, &option_index);
        int i = getopt_long_only(argc, argv, "", long_options, &option_index);

        if(i == -1)
            break;

        switch(i) {
            case 's':
                rootchunksize = atoi(optarg);
                break;

            case 't':
                rootclients = atoi(optarg);
                break;

            case 'h':
                rootremote = optarg;
                break;

            case 'p':
                rootport = atoi(optarg);
                break;

            case '?':
            default:
               printf("Usage: %s [--size payload-size] [--threads clients]\n", argv[0]);
               printf("       %s [--host hostname] [--port port]\n", argv[0]);
               exit(EXIT_FAILURE);
        }
    }

    return initialize();
}
