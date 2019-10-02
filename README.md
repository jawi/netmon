# netmon

netmon is a small utility that listens for changes in using Netlink and dispatches
events on a MQTT topic for each of these changes.

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

mqtt:
   # Denotes how the MQTT client identifies itself to the MQTT broker.
   # Defaults to netmon.
   client_id: netmon_zeus
   # The hostname or IP address of the MQTT broker
   # Defaults to localhost.
   host: localhost
   # The port of the MQTT broker, use 8883 for TLS connections.
   # Defaults to 1883, or 8883 if TLS settings are defined.
   port: 1883
   # Denotes what quality of service to use: 
   #   0 = at most once, 1 = at lease once, 2 = exactly once.
   # Defaults to 1.
   qos: 1
   # Whether or not the MQTT broker should retain messages for 
   # future subscribers. Defaults to true.
   retain: true

   auth:
      # The username to authenticate against the MQTT broker. By default,
      # no authentication is used.
      username: foo
      # The password to authenticate against the MQTT broker. By default,
      # no authentication is used.
      password: bar

   tls:
      # The path to the CA certificates. Either this setting *or* the
      # 'ca_cert_file' setting should be given to enable TLS connections!
      # By default, no path is defined.
      ca_cert_path: /etc/ssl/certs
      # The CA certificate file, encoded in PEM format.
      # By default, no file is defined.
      ca_cert_file: /etc/ssl/certs/ca.pem
      # The client certificate file, encoded in PEM format.
      # By default, no file is defined.
      cert_file: netmon.crt
      # The client private key file, encoded in PEM format.
      # By default, no file is defined.
      key_file: netmon.key
      # Whether or not the identity of the MQTT broker should be verified.
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

## Output

The event data is published on the MQTT topic `netmon.neigh` as a JSON object,
for example:

```json
{
   "last_seen": 1558955353,
   "addr": "192.168.1.99",
   "mac": "af:b8:62:f5:38:8c",
   "src_iface": "eth0",
   "src_mac": "10:67:ec:22:af:4e",
   "src_vlan": 2,
   "src_ip": "192.168.1.1"
}
```

**Note**: the actual output of the JSON object is compressed to a single line
without newlines. The order of fields is not guaranteed to be the same across
restarts of netmon.

The fields in the JSON object have the following semantics:

| Field     | Description                                                                |
|-----------|----------------------------------------------------------------------------|
| last_seen | the Unix epoch timestamp on which the neighbour was last seen by netmon    |
| addr      | the IP address of the neighbour                                            |
| mac       | the MAC address of the neighbour                                           |
| src       | the information about the source interface on which the neighbour was seen |
| src_iface | the source network interface                                               |
| src_mac   | the source MAC address                                                     |
| src_vlan  | the source VLAN address (most probably also the VLAN of the neighbour)     |
| src_ip    | the source IP address                                                      |

## Development

### Compilation

Netmon requires the following build dependencies:

- libmnl (1.0.4 or later);
- libmosquitto (1.5.5 or later);
- libyaml (0.2.1 or later).

In addition, you a libc implementation that supports PTHREADS, such as glibc or
musl.

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
