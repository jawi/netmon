# netmon

netmon is a small utility that listens for changes in network addresses, links
and neighbours using Netlink and dispatches events on MQTT for each of these 
changes.

## Usage

    netmon [-d] [-f] [-c config] [-p pidfile]

where

    -d  enables verbose logging (default: false)
    -f  prevents netmon from running as daemon (default: false)
    -c  provides the path to netmon configuration (default: /etc/netmon.cfg)
    -p  provides the path to netmon pidfile (default: /run/netmon.pid)

## Configuration

Netmon can be configured by a simple configuration file that is read upon startup. The default configuration is defined as:

    # netmon configuration

    # Denotes how the MQTT client identifies itself to the MQTT broker.
    # Defaults to netmon.
    client_id = netmon
    
    # The hostname or IP address of the MQTT broker
    # Defaults to localhost.
    host = localhost

    # The port of the MQTT broker, use 8883 for TLS connections.
    # Defaults to 1883.
    port = 1883
    
    # Denotes what quality of service to use: 
    #   0 = at most once, 1 = at lease once, 2 = exactly once.
    # Defaults to 1.
    qos = 1
    
    # Whether or not the MQTT broker should retain messages for 
    # future subscribers. Defaults to true.
    retain = true
    
    # The username to authenticate against the MQTT broker. By default,
    # no authentication is used.
    # username = ""

    # The password to authenticate against the MQTT broker. By default,
    # no authentication is used.
    # password = ""
    
    # The path to the CA certificates. Either this setting *or* the
    # 'ca_cert_file' setting should be given to enable TLS connections!
    # By default, no path is defined.
    # ca_cert_path = /etc/ssl/certs
    
    # The CA certificate file, encoded in PEM format.
    # By default, no file is defined.
    # ca_cert_file = /path/to/ca.pem
    
    # The client certificate file, encoded in PEM format.
    # By default, no file is defined.
    # cert_file = /path/to/cert.pem
    
    # The client private key file, encoded in PEM format.
    # By default, no file is defined.
    # key_file = /path/to/key.pem
    
    # Whether or not the identity of the MQTT broker should be verified.
    # use with case: only disable this setting when debugging TLS 
    # connection problems! Defaults to true.
    # verify_peer = true

    # What TLS ciphers should be used for the TLS connection.
    # Defaults to an empty string, denoting that the default ciphers
    # of the SSL library should be used.
    # ciphers = ""


## License

netmon is licensed under Apache License 2.0.

## Author

netmon is written by Jan Willem Janssen `j dot w dot janssen at lxtreme dot nl`.
