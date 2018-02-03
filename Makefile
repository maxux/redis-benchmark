CFLAGS=-g -W -Wall -O2 -fopenmp -pthread -I/usr/include/hiredis
LDFLAGS=-fopenmp -rdynamic -lhiredis -lpthread -lssl -lcrypto

all: redis-benchmark redis-write-burst

run: all
	./redis-benchmark

# benchmark
redis-benchmark: redis-benchmark.o
	$(CC) -o $@ $^ $(LDFLAGS)

redis-benchmark.o: redis-benchmark.c
	$(CC) $(CFLAGS) -c $<

# write burst
redis-write-burst: redis-write-burst.o
	$(CC) -o $@ $^ $(LDFLAGS)

redis-write-burst.o: redis-write-burst.c
	$(CC) $(CFLAGS) -c $<


clean:
	$(RM) *.o

mrproper: clean
	$(RM) redis-benchmark redis-write-burst

