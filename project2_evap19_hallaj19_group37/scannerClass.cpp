#include "scannerClass.h"
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


using namespace std;


Scanner::Scanner(const char *IP_addr, int port_from, int port_to){
    this->IP_addr = IP_addr;
    this->port_from = port_from;
    this->port_to = port_to;
}

Scanner::~Scanner(){
}

// creating a socket, returns the socked if successfully opened socket, if not returns -1 
int Scanner::open_socket(){

    this->udp_sock = socket(AF_INET, SOCK_DGRAM, 0);

    if(udp_sock < 0) // -1 if error
      {
         perror("Failed to open socket in scanner");
         return(-1);
      }
    return udp_sock;
}



set<int> Scanner::the_scanner(){

    //pass the ports 4000-4100 on the command line  

    strcpy(buffer, "$group_37$"); // Message set to buffer
    length = strlen(buffer) + 1; // lenght of buffer


    if (open_socket() > 0){

        // Scans each port from port_from to port_to
        for (int port = this->port_from; port <= this->port_to; port++){
            fd_set masterfds;
            FD_SET(udp_sock, &masterfds);
            struct timeval timeout;             // Timeout for recvfrom()
            timeout.tv_sec = 0;
            timeout.tv_usec = 20000;            // Set timeout to 0.2 seconds

            destaddr.sin_family = AF_INET;
            inet_aton(this->IP_addr, &destaddr.sin_addr);
            destaddr.sin_port = htons(port);

            // Check each port 4 times because udp is an unreliable protocol
            for (int i = 0; i < 4; i++){
                if (sendto(udp_sock, buffer, length, 0, (const struct sockaddr *)&destaddr, sizeof(destaddr)) < 0){
                    perror("Failed to send");
                }
                else {
                    int t = select(udp_sock + 1, &masterfds, NULL, NULL, &timeout);
                    if (t > 0){ // if t is 0, timeout accured
                        int destaddr_size = sizeof(destaddr);
                        if(recvfrom(udp_sock, buffer, length, 0, (sockaddr *)&destaddr, (socklen_t *)&destaddr_size) < 0){
                            perror("Failed to recieve");
                        }
                        else { // if ok, add port to open ports set
                            if (string(IP_addr) == "130.208.242.120"){
                                int open_port = ntohs(destaddr.sin_port);
                                open_ports.insert(open_port);
                                
                            }
                            break;
                        }
                    }
                }
            }
        }
    }
    
    return open_ports;
}