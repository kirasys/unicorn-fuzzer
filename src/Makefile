CC = g++
LD = ld
CFLAGS  = -g -w -std=c++11
CFLAGS += -L ../afl-window/unicorn -I ../afl-window/unicorn/include
CFLAGS += -L /usr/lib -I /usr/include/jsoncpp

LDLIBS  = -pthread
LDLIBS += -lunicorn -ljsoncpp
TARGET = unicorn_loader
OBJS = unicorn_loader.o AflUnicornEngine.o

$(TARGET) : $(OBJS)
	$(CC) $(CFLAGS) -o unicorn_loader $(OBJS) $(LDLIBS)

unicorn_loader.o : unicorn_loader.cpp
	$(CC) $(CFLAGS) $(LDLIBS) -c unicorn_loader.cpp

AflUnicornEngine.o : AflUnicornEngine.cpp
	$(CC) $(CFLAGS) $(LDLIBS) -c AflUnicornEngine.cpp

clean :
	rm *.o unicorn_loader