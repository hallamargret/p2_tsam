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

// creating a socket, returns the socked if successfully opened socket, if not returns -1 
int open_socket(){
    struct sockaddr_in server_addr;
    struct hostent *server;

    int udp_sock = socket(AF_INET, SOCK_DGRAM, 0);

    if(udp_sock < 0)
      {
         perror("Failed to open socket");
         return(-1);
      }
    return udp_sock;

}


int main(int argc, char *argv[]){

    //pass the ports 4000-4100 on the command line
    int udp_sock;
    char buffer[1400];
    int length;
    struct sockaddr_in destaddr;


    char szbuff[256];
    memset(szbuff, ' ', sizeof(szbuff));

    strcpy(buffer, "Hi Port!");
    length = strlen(buffer) + 1;

    if (argc == 4){
        const char *IP = argv[1];
        const char *port_from = argv[2];
        const char *port_to = argv[3];

        udp_sock = open_socket();

        if (udp_sock > 0){
            destaddr.sin_family = AF_INET;
            inet_aton(IP, &destaddr.sin_addr);

            for (int port = atoi(port_from); port <= atoi(port_to); port++){
                fd_set masterfds;
                FD_SET(udp_sock, &masterfds);
                struct timeval timeout;
                timeout.tv_sec = 0;                    /*set the timeout to 10 seconds*/
                timeout.tv_usec = 20000;
                destaddr.sin_family = AF_INET;
                inet_aton(IP, &destaddr.sin_addr);
                destaddr.sin_port = htons(port);
                bool open = false;
                for (int i = 0; i < 4; i++){
                    if (sendto(udp_sock, buffer, length, 0, (const struct sockaddr *)&destaddr, sizeof(destaddr)) < 0){
                        perror("Failed to send");
                    }
                    else {
                        int t = select(udp_sock + 1, &masterfds, NULL, NULL, &timeout);
                        if (t > 0){
                            int destaddr_size = sizeof(destaddr);
                            recvfrom(udp_sock, buffer, length, 0, (sockaddr *)&destaddr, (socklen_t *)&destaddr_size);
                            open = true;
                        }
                    
                    }
                }
                if (open){
                    cout << port << endl;
                }


            }
        }
    
    }
    return 0;
}
