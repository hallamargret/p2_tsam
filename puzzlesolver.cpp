#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <unistd.h>
#include <sys/types.h>
#include <vector>


#include "scanner.h"

using namespace std;




int main(int argc, char *argv[]){

    //pass the ports 4000-4100 on the command line
    char buffer[1400];  // Buffer for information to send
    int length;
    struct sockaddr_in destaddr;

    strcpy(buffer, "Hi Port!"); // Message set to buffer
    length = strlen(buffer) + 1; // lenght of buffer

    if (argc == 2){
        //call scanner to get the open ports that are not hidden
        const char *IP = argv[1];
        Scanner port_scanner = Scanner(IP, 4000, 4100);

        vector<int> open_ports = port_scanner.the_scanner();
        for (int i : open_ports){
            cout << "open ports: " << i << endl;
        }

        // if (udp_sock > 0){
        //     destaddr.sin_family = AF_INET;
        //     inet_aton(IP, &destaddr.sin_addr);

        //     // Scans each port from port_from to port_to
        //     for (int port = atoi(port_from); port <= atoi(port_to); port++){
        //         fd_set masterfds;
        //         FD_SET(udp_sock, &masterfds);
        //         struct timeval timeout;             // Timeout for recvfrom()
        //         timeout.tv_sec = 0;
        //         timeout.tv_usec = 20000;            // Set timeout to 0.2 seconds

        //         destaddr.sin_family = AF_INET;
        //         inet_aton(IP, &destaddr.sin_addr);
        //         destaddr.sin_port = htons(port);

        //         int array_counter = 0;
        //         // Check each port 4 times because udp is an unreliable protocol
        //         for (int i = 0; i < 4; i++){
        //             if (sendto(udp_sock, buffer, length, 0, (const struct sockaddr *)&destaddr, sizeof(destaddr)) < 0){
        //                 perror("Failed to send");
        //             }
        //             else {
        //                 int t = select(udp_sock + 1, &masterfds, NULL, NULL, &timeout);
        //                 if (t > 0){ // if t is 0, timeout accured
        //                     int destaddr_size = sizeof(destaddr);
        //                     if(recvfrom(udp_sock, buffer, length, 0, (sockaddr *)&destaddr, (socklen_t *)&destaddr_size) < 0){
        //                         perror("Failed to recieve");
        //                     }
        //                     else { // if ok, print port
        //                         cout << port << endl; // The port is open, print the port and break to check the next port
        //                         ports[array_counter] = port;
        //                         array_counter ++;
        //                         cout << "Message: " << buffer << endl;
        //                         break;
        //                     }
        //                 }
        //             }
        //         }
        //     }
        // }
    


    }
    else if (argc == 6){
        //got the ports in as arguments
        // send the oracle a comma-seperated list of the hidden ports, and it will show us the way 4042
        // Send a message containing $group_#$ where # is our group number 4096


    }
    return 0;
}
