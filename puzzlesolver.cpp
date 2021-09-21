#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <unistd.h>
#include <sys/types.h>

using namespace std;

// creating a socket, returns the socked if successfully opened socket, if not returns -1 
int open_socket(){
    struct sockaddr_in server_addr;
    struct hostent *server;

    int udp_sock = socket(AF_INET, SOCK_DGRAM, 0);

    if(udp_sock < 0) // -1 if error
      {
         perror("Failed to open socket");
         return(-1);
      }
    return udp_sock;
}


int main(int argc, char *argv[]){

    //pass the ports 4000-4100 on the command line
    int udp_sock;       // The socket
    char buffer[1400];  // Buffer for information to send
    int length;
    struct sockaddr_in destaddr;

    strcpy(buffer, "Hi Port!"); // Message set to buffer
    length = strlen(buffer) + 1; // lenght of buffer

    if (argc == 4){
        const char *IP = argv[1];
        const char *port_from = argv[2];
        const char *port_to = argv[3];

        udp_sock = open_socket();

        if (udp_sock > 0){
            destaddr.sin_family = AF_INET;
            inet_aton(IP, &destaddr.sin_addr);

            // Scans each port from port_from to port_to
            for (int port = atoi(port_from); port <= atoi(port_to); port++){
                fd_set masterfds;
                FD_SET(udp_sock, &masterfds);
                struct timeval timeout;             // Timeout for recvfrom()
                timeout.tv_sec = 0;
                timeout.tv_usec = 20000;            // Set timeout to 0.2 seconds

                destaddr.sin_family = AF_INET;
                inet_aton(IP, &destaddr.sin_addr);
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
                            else { // if ok, print port
                                cout << port << endl; // The port is open, print the port and break to check the next port
                                break;
                            }
                        }
                    }
                }
            }
        }
    }
    return 0;
}
