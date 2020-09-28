CC=gcc
CXX=g++
CFLAGS=-g -Wall
TARGET=scan_iface
OBJS=main.o

$(TARGET): $(OBJS)
	$(CC) -o $@ $(OBJS) -lpcap
	rm $(OBJS)

main.o: include.h main.cpp

clean:
	rm -rf $(OBJS) $(TARGET)