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

#define SHA256LEN     (size_t) SHA256_DIGEST_LENGTH * 2

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
    unsigned int chunks;      // chunk length
    unsigned char *buffer;    // chunk buffer
    char *hash;
    char *response;

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

static unsigned char *benchmark_buffer_generate(benchmark_t *bench) {
    if(randomize(bench->buffer, bench->chunksize) != bench->chunksize) {
        fprintf(stderr, "[-] not enought random data\n");
        exit(EXIT_FAILURE);
    }

    return bench->buffer;
}

static benchmark_t *benchmark_generate(benchmark_t *bench) {
    printf("[+] allocating buffer [client %u]\n", bench->id);

    // allocating memory for hashes
    if(!(bench->hash = (char *) malloc(SHA256LEN + 1)))
        diep("malloc: hash");

    // allocating memory for buffers
    if(!(bench->buffer = (unsigned char *) malloc(sizeof(char) * bench->chunksize)))
        diep("malloc: buffers");

    // allocating memory for responses
    if(!(bench->response = (char *) malloc(sizeof(char) * 512)))
        diep("malloc: responses");

    return bench;
}

static double benchmark_time_spent(struct timeval *timer) {
    return (((size_t) timer->tv_sec * 1000000) + timer->tv_usec) / 1000000.0;
}

static double benchmark_speed(size_t size, double timed) {
    return (size / timed) / (1024 * 1024);
}

void benchmark_statistics(benchmark_t *bench) {
    // double wtime = (double)(bench->write.time_end - bench->write.time_begin) / CLOCKS_PER_SEC;
    // double rtime = (double)(bench->read.time_end - bench->read.time_begin) / CLOCKS_PER_SEC;

    float chunkskb = bench->chunksize / 1024.0;

    double wrtime = benchmark_time_spent(&bench->write.rtime_end) - benchmark_time_spent(&bench->write.rtime_begin);
    double wrspeed = benchmark_speed((size_t) bench->chunksize * bench->write.success, wrtime);
    // double rrspeed = benchmark_speed((size_t) bench->chunksize * bench->chunks, rrtime);
    // double secrrspeed = benchmark_speed((size_t) bench->chunksize * bench->chunks, secrrtime);

    printf("[+] --- client %u ---\n", bench->id);
    printf("[+] user write: %u keys of %.2f KB uploaded in %.2f seconds\n", bench->write.success, chunkskb, wrtime);
    printf("[+] default write: %.2f MB/s\n", wrspeed);
}

void benchmark_statistics_summary(benchmark_t **benchs, unsigned int length) {
    double writetime = 0;
    double writespeed = 0;

    for(unsigned int i = 0; i < length; i++) {
        benchmark_t *bench = benchs[i];

        writetime += benchmark_time_spent(&bench->write.rtime_end) - benchmark_time_spent(&bench->write.rtime_begin);
        writespeed += benchmark_speed((size_t) bench->chunksize * bench->write.success, writetime);
    }

    printf("[+] write speed: %.3f MB/s\n", writespeed);
}

//
// benchmark passes
//
static void *benchmark_pass_write(void *data) {
    benchmark_t *b = (benchmark_t *) data;
    redisReply *reply;

    gettimeofday(&b->write.rtime_begin, NULL);
    b->write.time_begin = clock();

    while(1) {
        printf("[+] generating a new buffer\n");

        benchmark_buffer_generate(b);

        for(unsigned int i = 0; i < b->chunksize; i++) {
            for(unsigned char byte = 0; byte < 255; byte++) {
                // changing the buffer
                b->buffer[i]++;
                b->hash = sha256(b->buffer, b->chunksize);

                reply = redisCommand(b->redis, "SET %b %b", b->hash, SHA256LEN, b->buffer, b->chunksize);

                b->response = strdup(reply->str);
                freeReplyObject(reply);

                b->write.success += 1;
            }
        }
    }

    return NULL;
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
}

int benchmark(benchmark_t **benchs, unsigned int length) {
    printf("\033[?25l");

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

    /*
    printf("[+] \n");
    printf("[+] final statistics\n");
    printf("[+] ==========================================\n");
    benchmark_statistics_summary(benchs, length);
    */

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

benchmark_t **remotes;
unsigned int threads = 0;

static void sighandler(int signal) {
    if(signal == SIGSEGV)
        printf("\n[-] segmentation fault");

    if(signal == SIGFPE)
        printf("\n[-] floating point exception");

    for(unsigned int i = 0; i < threads; i++) {
        remotes[i]->write.time_end = clock();
        gettimeofday(&remotes[i]->write.rtime_end, NULL);

        benchmark_statistics(remotes[i]);
    }

    benchmark_statistics_summary(remotes, threads);

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
        // remotes[i]->chunks = rootchunks;
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
