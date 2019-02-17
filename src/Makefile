CC = g++
LD = ld
CFLAGS  = -g -W -std=c++11
CFLAGS += -L ../lib -I ../include

LDLIBS  = -pthread
LDLIBS += -lunicorn -lz
TARGET = unicorn_loader
OBJS = unicorn_loader.o AflUnicornEngine.o UnicornSimpleHeap.o

$(TARGET) : $(OBJS)
	$(CC) $(CFLAGS) -o unicorn_loader $(OBJS) $(LDLIBS)

unicorn_loader.o : unicorn_loader.cpp
	$(CC) $(CFLAGS) $(LDLIBS) -c unicorn_loader.cpp

AflUnicornEngine.o : AflUnicornEngine.cpp
	$(CC) $(CFLAGS) $(LDLIBS) -c AflUnicornEngine.cpp

UnicornSimpleHeap.o : UnicornSimpleHeap.cpp
	$(CC) $(CFLAGS) $(LDLIBS) -c UnicornSimpleHeap.cpp
    
clean :
	rm *.o unicorn_loader