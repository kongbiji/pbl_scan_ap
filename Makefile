CC=gcc
CXX=g++
CFLAGS=-g -Wall
TARGET=scan_iface
OBJS=main.o

$(TARGET): $(OBJS)
	$(CXX) -o $@ $(OBJS) -lpcap -lpthread

main.o: include.h main.cpp

clean:
	rm -rf $(OBJS) $(TARGET)
