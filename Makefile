all: xperf_client xperf_server

xperf_client: xperf_client.c xperf_parser.c xperf.h xperf_kern.h xperf_parser.h
	@echo CC $@
	@gcc -Wall -Wextra -Werror -O2 -o $@ $(filter %.c, $^)

xperf_server: xperf_server.c xperf_monitor.c xperf.h xperf_kern.h xperf_parser.h
	@echo CC $@
	@gcc -Wall -Wextra -Werror -O2 -o $@ $(filter %.c, $^) -lpthread

clean:
	@echo RM xperf_client xperf_server
	@rm -f xperf_client xperf_server
