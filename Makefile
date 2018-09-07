CC = gcc
CFLAGS = -Wall -O -g -fPIC -I./
SCFLAGS= -shared -fPIC
LDFLAG = -lcrypto
OBJS   = a_crypto.o a_kdf.o a_tls13.o a_tls.o a_tls_cipher.o a_tls_extension.o a_tls_lib.o 
SRC    = a_crypto.c a_kdf.c a_tls13.c a_tls.c a_tls_cipher.c a_tls_extension.c a_tls_lib.c
BINSRC = daemon_server
TARGET = libatls

ifdef debug
CFLAGS += -DTLS_DEBUG
endif
ifdef cryptodir
CFLAGS += -I$(cryptodir)/include -L$(cryptodir)/lib -Wl,-rpath=$(cryptodir)/lib
acryptofile=$(cryptodir)/lib/libcrypto.a
endif

exist = $(shell if [ -f "$(acryptofile)" ]; then echo "exist"; else echo "notexist"; fi;)
ifeq ($(exist), exist)
cmd = gcc $(CFLAGS)  -o $(BINSRC) ./daemon/$(BINSRC).c $(TARGET).a $(acryptofile) -ldl -lpthread
else
cmd = gcc $(CFLAGS) ./daemon/$(BINSRC).c -o $(BINSRC) $(TARGET).a $(LDFLAG)
endif

all: static shared bin

$(OBJS):$(SRC)
	$(CC) $(CFLAGS) -c $(SRC)

static:$(OBJS)
	ar rcs $(TARGET).a $(OBJS)

shared:$(OBJS)
	$(CC) $(OBJS) $(SCFLAGS) $(LDFLAG) -o $(TARGET).so

bin:
	$(cmd)
clean:
	rm -f *.o *.so *.a $(BINSRC)
