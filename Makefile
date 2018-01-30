EXEC=redis-benchmark
SRC=$(wildcard *.c)
OBJ=$(SRC:.c=.o)

CFLAGS=-g -W -Wall -O2 -pthread -I/usr/include/hiredis
LDFLAGS=-rdynamic -lhiredis -lpthread -lssl -lcrypto

all: $(EXEC)

run: all
	./$(EXEC)

$(EXEC): $(OBJ)
	$(CC) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $<

clean:
	$(RM) *.o

mrproper: clean
	$(RM) $(EXEC)

