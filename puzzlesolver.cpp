#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <unistd.h>
#include <sys/types.h>
#include <set>


#include "scanner.h"

using namespace std;




int main(int argc, char *argv[]){

    //pass the ports 4000-4100 on the command line
    char buffer[1400];  // Buffer for information to send
    int length;
    struct sockaddr_in destaddr;

    set<int> open_ports;

    strcpy(buffer, "Hi Port!"); // Message set to buffer
    length = strlen(buffer) + 1; // lenght of buffer

    if (argc == 2){
        const char *IP = argv[1];
        //call scanner to get the open ports that are not hidden
        Scanner port_scanner = Scanner(IP, 4000, 4100);
        int udp_sock = port_scanner.open_socket();
        destaddr.sin_family = AF_INET;
        inet_aton(IP, &destaddr.sin_addr);
        int destaddr_size = sizeof(destaddr);

        open_ports = port_scanner.the_scanner();
        for (int i : open_ports){
            cout << "open ports: " << i << endl;
        }

    }
    else if (argc == 6){
        //got the ports in as arguments
        // send the oracle a comma-seperated list of the hidden ports, and it will show us the way 4042
        // Send a message containing $group_#$ where # is our group number 4096
        const char *IP = argv[1];
        for (int i = 2; i < 6; i++){
            open_ports.insert(argv[i]);
        }
        for (auto i : open_ports){
            cout << "open ports: " << i << endl;
        }
        



    }
    return 0;
}
