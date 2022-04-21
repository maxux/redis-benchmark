#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>
#include <time.h>
#include <sqlite3.h>
#include "generator.h"

#define DEFAULT_CHUNKSIZE     4 * 1024  // 4 KB payload
#define DEFAULT_CHUNKS        8 * 1024  // 8192 keys

static struct option long_options[] = {
    {"size",    required_argument, 0, 's'},
    {"keys",    required_argument, 0, 'k'},
    {"threads", required_argument, 0, 't'},
    {"file",    required_argument, 0, 'f'},
    {0, 0, 0, 0}
};

typedef struct sqlite_kntxt_t {
    char *filename;
    sqlite3 *db;

    sqlite3_stmt *insert;
    sqlite3_stmt *select;

} sqlite_kntxt_t;

void *kntxt_init(char *filename) {
    sqlite_kntxt_t *kntxt;

    if(!(kntxt = malloc(sizeof(sqlite_kntxt_t))))
        diep("malloc");

    kntxt->filename = filename;

    printf("[+] database: opening: %s\n", kntxt->filename);

    if(sqlite3_open(kntxt->filename, &kntxt->db)) {
        fprintf(stderr, "[-] sqlite3_open: %s", sqlite3_errmsg(kntxt->db));
        exit(EXIT_FAILURE);
    }

    char *query = "CREATE TABLE IF NOT EXISTS benchmark (key BLOB(64) PRIMARY KEY, value BLOB);";
    sqlite3_exec(kntxt->db, query, NULL, NULL, NULL);

    sqlite3_exec(kntxt->db, "BEGIN TRANSACTION;", NULL, NULL, NULL);

    char *q1 = "SELECT value FROM benchmark WHERE key = ?1";
    char *q2 = "INSERT INTO benchmark (key, value) VALUES (?1, ?2)";

    if(sqlite3_prepare_v2(kntxt->db, q1, -1, &kntxt->select, 0) != SQLITE_OK) {
        fprintf(stderr, "sqlite3_prepare_v2: SELECT: %s", sqlite3_errmsg(kntxt->db));
        exit(EXIT_FAILURE);
    }

    if(sqlite3_prepare_v2(kntxt->db, q2, -1, &kntxt->insert, 0) != SQLITE_OK) {
        fprintf(stderr, "sqlite3_prepare_v2: INSERT: %s", sqlite3_errmsg(kntxt->db));
        exit(EXIT_FAILURE);
    }

    return kntxt;
}

int callback_close(void *ptr) {
    sqlite_kntxt_t *kntxt = (sqlite_kntxt_t *) ptr;
    sqlite3_close(kntxt->db);
    return 0;
}

buffer_t callback_pass_write(void *ptr, unsigned char *key, size_t keylen, unsigned char *data, size_t datalen) {
    sqlite_kntxt_t *kntxt = (sqlite_kntxt_t *) ptr;
    buffer_t buffer = {
        .data = NULL,
        .length = 0,
    };

    sqlite3_reset(kntxt->insert);
    sqlite3_bind_text(kntxt->insert, 1, (char *) key, keylen, SQLITE_STATIC);
    sqlite3_bind_blob(kntxt->insert, 2, data, datalen, SQLITE_STATIC);

    if(sqlite3_step(kntxt->insert) != SQLITE_DONE) {
        fprintf(stderr, "[-] set: sqlite3_step: %s", sqlite3_errmsg(kntxt->db));
        return buffer;
    }


    buffer.data = malloc(keylen);
    memcpy(buffer.data, key, keylen);
    buffer.length = keylen;

    return buffer;
}

int callback_pass_write_done(void *ptr) {
    sqlite_kntxt_t *kntxt = (sqlite_kntxt_t *) ptr;

    sqlite3_exec(kntxt->db, "COMMIT;", NULL, NULL, NULL);
    // sqlite3_exec(kntxt->db, "VACUUM;", NULL, NULL, NULL);

    return 0;
}

buffer_t callback_pass_read(void *ptr, unsigned char *key, size_t keylen) {
    sqlite_kntxt_t *kntxt = (sqlite_kntxt_t *) ptr;
    buffer_t buffer = {
        .data = NULL,
        .length = 0,
    };

    sqlite3_reset(kntxt->select);
    sqlite3_bind_text(kntxt->select, 1, (char *) key, keylen, SQLITE_STATIC);

    int data = sqlite3_step(kntxt->select);

    if(data == SQLITE_ROW) {
        buffer.length = sqlite3_column_bytes(kntxt->select, 0);
        buffer.data = malloc(buffer.length);
        memcpy(buffer.data, sqlite3_column_blob(kntxt->select, 0), buffer.length);

        return buffer;
    }

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
    char *filename = "/tmp/benchmark.sqlite3";

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

            case 'f':
                filename = optarg;
                break;

            case '?':
            default:
               printf("Usage: %s [--size payload-size] [--keys count] [--threads clients]\n", argv[0]);
               printf("       %s [--file filename]\n", argv[0]);
               exit(EXIT_FAILURE);
        }
    }

    benchsuite_t *benchmarks = benchmark_initialize(chunksize, chunks, clients);

    // setup callbacks
    for(size_t i = 0; i < benchmarks->length; i++) {
        benchmarks->benchmarks[i]->kntxt = kntxt_init(filename);
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
