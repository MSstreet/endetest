CC = gcc

INC = -I./include/
LIB_DIRS = -L./lib/

TARGET = OperEnde
LIBS = -lEdgeCrypto

LIB_PATH = ./lib/
EXE_PATH = 
OBJ_PATH = 
C_PATH = ./src/

$(TARGET) : main1.c libEnde libEdgeCrypto.so
	$(CC) -g -o $(TARGET) main1.c -L./ -lEdgeCrypto -lEnde $(INC)

libEnde : ende.o hexende.o
	gcc -shared -o libEnde.so ende.o hexende.o

ende.o : ende.c
	gcc -fPIC -c ende.c

hexende.o : hexende.c
	gcc -fPIC -c hexende.c

clean :
	rm -f *.o
	rm -f $(TARGET)

