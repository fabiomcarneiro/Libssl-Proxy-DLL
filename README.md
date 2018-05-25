# Libssl-Proxy-DLL
A Proxy DLL for Libssl, used to record Send / Recv functions


Used to intercept recv and send function of SSL lib in order to decrypt,
Test Case: League of Legends Client

If you wish to proxy other dll generate the def and the proto structure , many tools for that or make your own.

### How to use
Don't forget to add libssl-1_1.def as 'module definition File' on project settings

Rename original dll to : libssl-1_1_org.dll
Compile the Proxy DLL and copy to the executable folder

![Example](https://raw.githubusercontent.com/fabiommc/Libssl-Proxy-DLL/master/example.png) 

### TODO

Save traffic as libpcap (.pcap) format in order to inspect with Wireshark or similar tools 
