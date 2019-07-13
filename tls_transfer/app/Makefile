all: echo_client xfer_echo_client

%: %.c
	gcc -Wall -O3  -g $^ -o $@ -lpthread --std=gnu99

clean:
	rm echo_client xfer_echo_client
