#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include <sys/socket.h>


int main(int argc, char *argv[]){

    //pass the ports 4000-4100 on the command line
    int udp_sock;
    int from = 4000;        //change before handin
    int to = 4100;
    char buffer[1400];
    int length;
    struct sockaddr_in destaddr;

    strcpy(buffer, "Hi Port!");
    length = strlen(buffer) + 1;

    if ((udp_sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0){
        perror("Unable to open socket");
        return(-1);
    }

    destaddr.sin_family = AF_INET;
    inet_aton("130.208.243.61", &destaddr.sin_addr);

    for (int port = from; port <= to; port++){
        destaddr.sin_port = htons(port);
        // sendto(int socket, const void *buffer, size_t length, int flags, const struct sockaddr *dest_addr, socklen_t dest_len)
        if (sendto(udp_sock, buffer, length, 0, (const struct sockaddr *)&destaddr, sizeof(destaddr)) < 0){
            perror("Failed to send");
        }
    }

    return 0;
}