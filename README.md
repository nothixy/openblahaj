# openBLÅHAJ

```
                                 :                          
                                +++                          
                              =+++=                          
                             =***++                      ++= 
      <0><                  +=+**=                     =+++  
                           +***+*+                    +*+=   
                         =+*#**+#=                   +*+*    
           -=--==--===-====-=+==+--         **     ++*++     
     -=*====-====-=+===+==+++===+==--**-+======--=+***++=    
  =+=++*++*-+=*++=+=++==+++=+*+*++++===-+=*#**+=*+==+#**++   
-+*=++*+++++++*+++*****+++=+*+++++++*=++=++*++====   ****+  
  +++%#+*+**#*#+#++*+**+**+**+++++*+=++=*+#==+===        .+  
   +++**+**+%*#+**+*****++*+*+*+*++++==+++-==                
       ....:*+***++*#+*#++#*++*+=++++====                    
       .. .........:.-+**%*+++*-=                            
            .......::..::*##**+++               <0><         
                              *++***                         
                                  **=+                       
```

A candy WireShark clone, just a little bit worse than the original

## What is supported ?

At the physical link level :
- Bluetooth (via bluez)
- DBus
- Linux cooked capture (for example with the `any` interface)
- Ethernet

At the network level :
- ARP
- IPv4
- IPv6 (partial -> IPSec not implemented)

At the transport level :
- ICMP (partial -> Some ICMP message types not implemented)
- ICMPv6 (partial -> Some ICMP message types not implemented)
- IGMP / RGMP (partial -> Some IGMP message types not implemented)
- OSPF (v2 complete, v3 partial -> Some OSPF message types not implemented, no checksum calculation for LSAs)
- SCTP (no checksum calculation)
- TCP
- UDP

At the application level :
- BOOTP / DHCP (partial -> Some options missing)
- DNS
- FTP
- HTTP
- IMAP
- POP3
- RIP
- RIPng
- SMTP
- SSDP
- Syslog
- Telnet
- TLS
- WHOIS
- Wireguard

Note that many protocols are incomplete, for example DHCP and IPv6 which specify a lot of options.

## Goals and non goals

openBLÅHAJ should be able to display any packet from the aforementioned list with the assumption that the packets are well formed. If a packet is invalid, it might break the program in rare cases.

It should run on any modern Linux platform (tested on Ubuntu 25.10 / Linux 6.6.87.2) and any architecture.

## License

This project is released under the MIT license - check the [LICENSE.txt](LICENSE.txt) file for details.

## Third-party libraries

- **libpcap** - For receiving packets on different interfaces and reading from and saving to a file, released under the BSD license, check the [third_party_LICENSES.txt](third_party_LICENSES.txt) file for details
- **dash** - For parsing command-line arguments, released under the MIT license, check the [LICENSE.txt](LICENSE.txt) file for details

## Building

---

openBLÅHAJ uses the GNU Autotools build system. Use the following steps :

1. (optional) Run `autoreconf -ivf` (this will regenerate the configure script)
2. Change directory to `build`
3. Run `../configure` (`../configure --help=short` to list optional features)
4. Run `make`

The openBLÅHAJ executable should now be available in your build directory. The following instructions are optional.

5. `make check` (to run automated tests)
6. `make doxygen-doc` (to generate html documentation)
7. `sudo make install` (to install in default prefix with the CAP_NET_RAW capability, so that you can run openBLÅHAJ without root privileges)

## Documentation

You can run `make doxygen-doc` to generate HTML documentation inside the build/doc/html directory

## Running

openBLÅHAJ needs the CAP_NET_RAW capability to listen on an interface, which can be obtained either by running as root, or by applying the capability on the executable with `sudo setcap cap_net_raw=eip openBLAHAJ`

> [!NOTE]  
> The setcap command is automatically run by `sudo make install`

You can run openBLÅHAJ without any option, it will ask you to choose from a network interface, otherwise you can specify the following arguments:
- `-i <interface>` to start a capture from the specified interface
- `-o <file>` to read from a capture file
- `-v [1-3]` to specify the level of information displayed
- `-f <filter>` to apply a BPF filter

Run `openBLAHAJ --help` to see all available arguments.

You can also run openBLÅHAJ on an executable, for example :
```bash
openBLAHAJ curl https://example.com
```
It can also be run as a shared library although this is not the preferred way of doing, with :
```bash
LD_PRELOAD=<prefix>/lib/libopenBLAHAJ.so curl https://example.com
```

openBLÅHAJ is also available as a Docker container (on oci.hixy.tk), you can run it with `docker run --rm --network=host --cap-add=CAP_NET_RAW -it oci.hixy.tk/nothixy/openblahaj:latest`.
