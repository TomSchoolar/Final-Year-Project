This git repository contains:
 - README.md: a readme file which re-iterates some of the points in this section about compilation and running the program.
 - aesDecrypter.py: a Python script used for encrypting and decrypting with the AES cipher.
 - checksumCalculator.py: a Python script that calculates the IP and UDP checksums.
 - frameCheckSequenceCalculator.py: a Python script for calculating a frame’s FCS.
 - packetSender.c: a program that sends a packet.
 - packetSender: an executable of the previous program
 - spoofingDNS.c: the main program for capturing the handshake and sending a spoofed response.
 - spoofingDNS: an executable of the previous program 

Running the programs (to run all following commands, you must have root privileges):
When trying to run the attack, you should use a linux machine and simply run the ./spoofingDNS executable with the required parameters; this will call all other scripts and programs required for the attack to run.
For example for our testing we used:
```
./spoofingDNS wlan0 Galaxy password
```

Program Usages:
```
./spoofingDNS interface networkName networkPassword
./packetSender interface senderMAC destinationMAC senderIP destinationIP senderPort destinationPort transactionId encryptionKey
```

When running these programs, the given interface must be in monitor mode to be able to capture other devices’ packets.
When switching our external network adapter to monitor mode, we used the following commands (our target network was on channel 9):
```
ifconfig wlan0 down
iwconfig wlan0 mode monitor
iwconfig wlan0 channel 9
ifconfig wlan0 up promisc
```

Compling the code:
Should you need to re-compile the code, then you should use the commands for their respective programs, making sure to keep the names the same so that the programs can execute sendingDNS can call the packetSender executable:
```
gcc spoofingDNS.c -lcrypto -o spoofingDNS
gcc packetSender.c -lpcap -o packetSender
```

To do this, you must be using a Linux device with the used libraries installed.
Libraries used in spoofingDNS.c:
 - tcpdump: https://www.tcpdump.org/manpages/tcpdump.1.html
 - openssl: https://www.openssl.org/docs/man3.0/man3/HMAC.html
 - time: https://www.tutorialspoint.com/c_standard_library/time_h.htm

Libaries used in packetSender.c:
 - pcap: https://www.tcpdump.org/manpages/pcap.3pcap.html

The Python scripts cannot be compiled, and therefore, for the program to run, the libraries used in the code must be installed on your device. The required libraries are as follows:
 - sys: https://docs.python.org/3/library/sys.html
 - Crypto.Cipher: https://pypi.org/project/pycrypto/#description 
 - binascii: https://docs.python.org/3/library/binascii.html 
 - zlib: https://docs.python.org/3/library/zlib.html


The code will save the capture taken at runtime and save it to a .pcap file; Wireshark can be used to open these files after the program has finished execution and is a helpful program to view the full set of data captured. Wireshark was very useful when debugging the program throughout the project: https://www.wireshark.org/

The program was tested using a Samsung Galaxy A20e (Android 10) mobile hotspot as the test network. The target devices were an Amazon Kindle and Raspberry Pi (Model B), and the attacker program was ran on a Kali Linux virutal device. The external network adapter used was an Alfa Network AWUS036NHA.

Python Usages if you want to run the python code separately (you must have the libraries installed as before):
```
python aesDecrypter.py encryption_key mac_address nonce data 
python checksumCalculator.py data
python frameCheckSequenceCalculator.py data
```

