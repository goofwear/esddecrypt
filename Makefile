CC=g++
CFLAGS= -Os -fpermissive -municode -static -Wall
LIBS= -lcrypt32

all: esddecrypt32.exe esddecrypt64.exe

esddecrypt32.exe:
	$(CC) $(CFLAGS) -m32 -o $@ esddecrypt.cpp $(LIBS)
	strip -s $@

esddecrypt64.exe:
	$(CC) $(CFLAGS) -m64 -o $@ esddecrypt.cpp $(LIBS)
	strip -s $@

clean:
	del esddecrypt32.exe esddecrypt64.exe
