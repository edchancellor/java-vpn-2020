# java-vpn-2020
Java Virtual Private Network, using AES and RSA.

This project implements a port forwarder VPN, from the java files ForwardServer.java and ForwardClient.java.\
The VPN will perform a handshake, in which it will use RSA to set up a session key for AES encryption.\
\
In order to run the program, you will need:\
A **server.pem** certificate, signed by a CA.\
a **server-private.der** key, associated with that certificate.\
A **ca.pem** certificate, signed by itself.\
A **client.pem** certificate, signed by the same CA.\
a **client-private.der** key, associated with that certificate.\
\
Note that for these certificates to be accepted they must have the following format:\
The CN for the CA certificate should be the string “ca-pf.ik2206.kth.se” and the email address should use the domain "@kth.se".\
The CN for the server certificate should be the string “server-pf.ik2206.kth.se” and the email address should use the domain "@kth.se".\
The CN for the client certificate should be the string “client-pf.ik2206.kth.se” and the email address should use the domain "@kth.se".\
\
To run the server, use the following command:
```
$ java ForwardServer --handshakeport=2206 --usercert=server.pem--cacert=ca.pem --key=server-private.der
```
To run the client, use the following command:
```
$ java ForwardClient --handshakehost=portfw.kth.se --handshakeport=2206 --proxyport=9999 --targethost=server.kth.se --targetport=6789 --usercert=client.pem --cacert=ca.pem --key=client-private.der
```

The forwarder can then be tested using netcat, with the following commands:
```
$ nc -l 6789
 nc localhost 9999
 ```
