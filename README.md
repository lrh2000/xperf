XPerf
=====

Measure the maximum achievable bandwidth between the server and the client, while:
  1. transferring some server-side files to the client (e.g. captured TCP packets by `tcpdump`), and
  2. leaking some TCP indicators calculated in the server-side kernel to the client (e.g. congestion window).

Building
-----

 1. Build the user-space programs with `make`:
```
cd PATH-TO-XPERF; make
```
 Two executable binaries `xperf_client` and `xperf_server` should be built.

 2. Patch the kernel since we need to leak in-kernel TCP indicators to the client:
```
cd PATH-TO-LINUX; git apply PATH-TO-XPERF/xperf.linux6.0-rc1.patch
```
 Then build and install the kernel according to any kernel building guide.

Usage
-----
  1. Run `xperf_server` on the server side. If there are any files that are produced in the server but are needed in the client (e.g. online plotting), specify such files in the command line:
```
Usage: ./xperf_server [-p PORT] [FILES...]
Options:
        -p PORT         TCP port that the server listens at
                        (Default: 9999)
        FILES...        Files that the server sends to the client
```
  2. Run `xperf_client` on the client side. It is possible to specify a directory in which the files that the server send to the client are stored:
```
Usage: ./xperf_client [-d DIR] [-p PORT] SERVER-ADDR
Options:
        -d DIR          Directory to store server-side files
                        (Default: Current woring directory)
        -p PORT         Server's TCP port
                        (Default: 9999)
        SERVER-ADDR     Server's IPv4 address
```

Note:
 - The server-side files are sent to the client in an incremental manner. However, only appending new data to these files are supported. Altering already existing bytes will be totally ignored and will lead to an inconsistent state between the server-side file and the client-side file.
 - The server-side files are sent to the client and stored in the specified directory (or the current working directory), using the same filename. The path hierarchy is ignored. For example, when invoking `xperf_server abc/def.txt` and `xperf_client -d efg`,  the file `abc/def.txt` will be stored as `efg/def.txt` on the client side.
 - A special file named `kdat` is reserved. The special file will always be generated, and some key in-kernel TCP indicators are stored into this file.

