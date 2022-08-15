all: xperf_client xperf_server

xperf_client: xperf_client.c xperf.h xperf_kern.h
	@echo CC $@
	@gcc -Wall -Werror -O2 -o $@ $<

xperf_server: xperf_server.c xperf.h xperf_kern.h
	@echo CC $@
	@gcc -Wall -Werror -O2 -o $@ $< -lpthread

clean:
	@echo RM xperf_client xperf_server
	@rm -f xperf_client xperf_server
