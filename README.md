# netmon

netmon is a small utility that listens for changes in neighbours using Netlink
and dispatches events on NATS for each of these changes.

## Usage

    netmon [-d] [-f] [-c config] [-p pidfile] [-v]

where

    -d  enables verbose logging (default: false);
    -f  prevents netmon from running as daemon (default: false);
    -c  provides the path to netmon configuration (default: /etc/netmon.cfg);
    -p  provides the path to netmon pidfile (default: /run/netmon.pid);
    -v  prints out the version number of netmon and exits;
    -h  prints out a short help text and exits.

## Configuration

Netmon can be configured by a simple configuration file that is read upon 
startup. By default, it expects the configuration file to reside in 
`/etc/netmon.cfg`, but you can override it by means of the `-c` argument.

The configuration file is expected to be a plain YAML file encoded as UTF-8.
Note that not all YAML constructs are supported, only simple blocks.

The default configuration is defined as:

```yaml   
# netmon configuration

daemon:
   # Denotes the user the daemon process will run under.
   # Defaults to "nobody".
   user: nobody
   # Denotes the group the daemon process will run under.
   # Defaults to "nobody".
   group: nogroup

nats:
   # Denotes how the netmon identifies itself to the NATS server.
   # Defaults to netmon.
   client_id: netmon_zeus
   # The hostname or IP address of the NATS server
   # Defaults to localhost.
   host: localhost
   # The port of the NATS server.
   # Defaults to 4222.
   port: 4222
   # Denotes what quality of service to use: 
   #   0 = at most once, 1 = at lease once, 2 = exactly once.
   # Defaults to 1.
   qos: 1
   # Whether or not the NATS server should retain messages for 
   # future subscribers. Defaults to true.
   retain: true

   auth:
      # The username to authenticate against the NATS server. By default,
      # no authentication is used.
      username: foo
      # The password to authenticate against the NATS server. By default,
      # no authentication is used.
      password: bar

   tls:
      # The CA certificate file, encoded in PEM format.
      # By default, no file is defined.
      ca_cert_file: /etc/ssl/certs/ca.pem
      # The client certificate file, encoded in PEM format.
      # By default, no file is defined.
      cert_file: netmon.crt
      # The client private key file, encoded in PEM format.
      # By default, no file is defined.
      key_file: netmon.key
      # Whether or not the identity of the NATS server should be verified.
      # use with case: only disable this setting when debugging TLS 
      # connection problems! Defaults to true.
      verify_peer: yes
      # Denotes what TLS version should be used. Can be one of "tlsv1.0",
      # "tlsv1.1", "tlsv1.2" or "tlsv1.3".
      # Defaults to "tlsv1.2"
      tls_version: "tlsv1.2"
      # What TLS ciphers should be used for the TLS connection.
      # Defaults to an empty string, denoting that the default ciphers
      # of the SSL library should be used.
      ciphers: "TLSv1.2"

###EOF###
```

## Development

### Compilation

Netmon requires the following build dependencies:

- libmnl (1.0.4 or later);
- cnats (1.8.0 or later);
- libprotobuf-c-dev (1.2.0 or later);
- libyaml (0.2.1 or later).

In addition, you a libc implementation that supports PTHREADS, such as glibc.

Since netlink functionality is used, netmon will only compile under Linux.

Compilation is done by running `make all`. All build artifacts are placed in 
the `build` directory.

### Finding memory leaks

You can use valgrind to test for memory leaks:

```sh
valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes --verbose \
         ./build/netmon -f -d -c netmon.cfg
```

Let it run for a while and terminate the process with `CTRL+C`. The results 
should indicate that all heap blocks were freed and no memory leaks are 
possible.

## Installation

To install netmon, you should copy the `netmon` from the `build` directory to
the destination location. In addition, you should copy or create the 
netmon configuration file in `/etc` (or whatever location you want to use). By
default, `/etc/netmon.cfg` is used as configuration file.

## License

netmon is licensed under Apache License 2.0.

## Author

netmon is written by Jan Willem Janssen `j dot w dot janssen at lxtreme dot nl`.

## Copyright

(C) Copyright 2019, Jan Willem Janssen.
