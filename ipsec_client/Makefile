CC      = gcc
CFLAGS  = -Wall -Wextra -O2 -g \
          -I. \
          -D_GNU_SOURCE
LDFLAGS = -lssl -lcrypto

TARGET  = ipsec_client

SRCS = main.c \
       ikev2/ike_message.c \
       ikev2/ike_sa_init.c \
       ikev2/ike_auth.c \
       ikev2/ike_crypto.c \
       crypto/dh.c \
       crypto/prf.c \
       crypto/aes_utils.c \
       xfrm/xfrm_api.c \
       http/http_client.c

OBJS = $(SRCS:.c=.o)

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)
	@echo ""
	@echo "Build successful: ./$(TARGET)"
	@echo "Usage: sudo ./$(TARGET) <server_ip> [http_port] [http_path]"

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(OBJS) $(TARGET)

check-deps:
	@echo "Checking build dependencies..."
	@pkg-config --exists openssl && echo "OpenSSL: OK" || echo "OpenSSL: MISSING - install libssl-dev"
	@test -f /usr/include/linux/xfrm.h && echo "XFRM headers: OK" || echo "XFRM headers: MISSING"
	@gcc --version >/dev/null 2>&1 && echo "GCC: OK" || echo "GCC: MISSING"

install-deps:
	apt-get install -y gcc libssl-dev linux-headers-$(shell uname -r)

.PHONY: all clean check-deps install-deps
