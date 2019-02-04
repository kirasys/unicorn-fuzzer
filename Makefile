CC = g++
LD = ld
CFLAGS  = -g -w
CFLAGS += -L ../afl-window/unicorn -I ../afl-window/unicorn/include
CFLAGS += -L /usr/lib -I /usr/include/jsoncpp

LDLIBS  = -pthread
LDLIBS += -lunicorn -ljsoncpp
TARGET = loader
OBJS = loader.o AflUnicornEngine.o

$(TARGET) : $(OBJS)
	$(CC) $(CFLAGS) -o loader $(OBJS) $(LDLIBS)

loader.o : loader.cpp
	$(CC) $(CFLAGS) $(LDLIBS) -c loader.cpp

AflUnicornEngine.o : AflUnicornEngine.cpp
	$(CC) $(CFLAGS) $(LDLIBS) -c AflUnicornEngine.cpp

clean :
	rm *.o loader