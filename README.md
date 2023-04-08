To setup the build env. please run the command below, 
this will create a docker image with neccesary tools.

    docker build -t packetparser -f DockerFile .

If the setup successfull, start the newly created docker image.
Below command will start the docker and mount the PWD to /src.

    docker run -it --rm \
        --mount type=bind,source=${PWD},target=/src \
        packetparser \
        bash

Change your directory to /src.
    
    cd /src

To build packetParser run make, make will compile.

    make build

To start the packetParser give the pcap file directory as argument.

    ./packetParser capture.pcap

    root:/src# ./packetParser capture.pcap 
    HTTP traffic flows: 1234
    HTTP traffic bytes: 12345678
    Top HTTP hostname : 1.1.1.1
    root:/src#  
