
VERSION = 1

CC = gcc
CFLAGS = -Wall -O3 -Werror -pthread

OBJS = sysstatd.c csapp.c csapp.h
#OBJS = sysstatd.o


all: $(OBJS)
	$(CC) $(CFLAGS) -o sysstatd $(OBJS)

sysstatd.o: sysstatd.c csapp.c csapp.h

clean: 
	rm -f *~ *.o sysstatd