build: 
	gcc -O3 -o packetParser packetParser.c -lpcap 

clean:
	rm -rf ./packetParser