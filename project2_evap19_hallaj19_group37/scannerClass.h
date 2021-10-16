#ifndef scanner
#define scanner 

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

class Scanner{

public:
    int udp_sock;       // The socket
    char buffer[1400];  // Buffer for information to send
    int length;
    struct sockaddr_in destaddr;
    const char *IP_addr;
    int port_from;
    int port_to;
    struct sockaddr_in server_addr;
    struct hostent *server;
    struct timeval timeout;
    
    Scanner(const char *IP_addr, int port_from, int port_to);
    ~Scanner();
    int open_socket();
    set<int> the_scanner();

private:
    int udp_socket;
    set<int> open_ports;

    
    

};

#endif