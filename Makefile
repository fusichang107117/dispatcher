#CC=arm-miot-linux-uclibcgnueabi-gcc
#CFLAGS=-I. -I/home/fu/project/toolchain/json-armv5-uclibc/include -L/home/fu/project/toolchain/json-armv5-uclibc/lib -ljson-c -lpthread -lrt -lm -s -O2 -std=gnu99

CC=gcc
CFLAGS=-I. -ljson-c -s -O2

RM=rm -f

TARGET1=miio_dispatcher
OBJS1=miio_dispatcher.o miio_json.o

TARGET2=dispatcher_client
OBJS2=dispatcher_client.o


all:$(TARGET1) $(TARGET2)

#SOURCE_FILES=$(wildcard *.c)
#OBJS=$(patsubst %.c,%.o, $(SOURCE_FILES))

$(TARGET1):$(OBJS1)
	$(CC) -o $@ $^ $(CFLAGS)

$(TARGET2):$(OBJS2)
	$(CC) -o $@ $^ $(CFLAGS)

$(OBJS1):%.o:%.c
	$(CC) -c $< -o $@ $(CFLAGS)

$(OBJS2):%.o:%.c
	$(CC) -c $< -o $@ $(CFLAGS)


clean:
	-$(RM) $(TARGET1) $(TARGET2)
	-$(RM) $(OBJS1) $(OBJS2)
