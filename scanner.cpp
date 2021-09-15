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

// ./scanner 130.208.242.120 4000 4010

void reciveFromServer(int sock_fd){
                char buffer[1025];      //Buffer to store the server's output
                memset(buffer, 0, sizeof(buffer));  //resetting the buffer
                int nread = read(sock_fd, buffer, sizeof(buffer));      //reading the output from the command executed on the server onto the buffer
                cout << buffer;
            }


int main(int argc, char *argv[]){

    //pass the ports 4000-4100 on the command line
    int udp_sock;
    int from = 4000;        //change before handin
    int to = 4100;
    char buffer[1400];
    int length;
    struct sockaddr_in destaddr;
     struct timeval timeout;

    timeout.tv_sec = 10;                    /*set the timeout to 10 seconds*/
    timeout.tv_usec = 0;
    fd_set readfds, masterfds;

    FD_ZERO(&masterfds);
    FD_SET(udp_sock, &masterfds);

    memcpy(&readfds, &masterfds, sizeof(fd_set));

    strcpy(buffer, "Hi Port!");
    length = strlen(buffer) + 1;

    if (argc == 4){
        const char *IP = argv[1];
        const char *port_from = argv[2];
        const char *port_to = argv[3];


        if ((udp_sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0){
            perror("Unable to open socket");
            return(-1);
        }

        destaddr.sin_family = AF_INET;
        inet_aton(IP, &destaddr.sin_addr);

        int counter = 0;
        for (int port = atoi(port_from); port <= atoi(port_to); port++){
            destaddr.sin_port = htons(port);
            // sendto(int socket, const void *buffer, size_t length, int flags, const struct sockaddr *dest_addr, socklen_t dest_len)
            int counter = 0;
            bool open = false;
            for (int i = 0; i < 4; i++){
                if (sendto(udp_sock, buffer, length, 0, (const struct sockaddr *)&destaddr, sizeof(destaddr)) < 0){
                    perror("Failed to send");
                }
                else {
                    if (FD_ISSET(udp_sock, &readfds)){
                        int destaddr_size = sizeof(destaddr);
                        recvfrom(udp_sock, buffer, length, 0, (sockaddr *)&destaddr, (socklen_t *)&destaddr_size);
                        cout<< buffer<< endl;
                    }
                
                    
                // if (recvfrom(udp_sock, buffer, length, 0, (sockaddr *)&destaddr, (socklen_t *)&destaddr_size) < 0){
                //     perror("Failed to recieve");
                // }
                // else{
                //     open = true;
                //     counter += 1;
                //     break;
                // }
                //cout << buffer << endl;
                }
            }
            if (open){
                cout << counter<< endl;

            }
            
            
            
        
        }
    }

    return 0;
}