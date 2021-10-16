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

#include "scannerClass.h"

using namespace std;

int main(int argc, const char *argv[]) {
    set<int> open_ports;
    const char *IP;

    if (argc == 2){
        IP = argv[1];
        //call scanner to get the open ports that are not hidden
        Scanner port_scanner = Scanner(IP, 4000, 4100);

        port_scanner.open_socket();

        open_ports = port_scanner.the_scanner();

    }
    if (argc == 4){
        IP = argv[1];
        int port_from = atoi(argv[2]);
        int port_to = atoi(argv[3]);

        //call scanner to get the open ports that are not hidden
        Scanner port_scanner = Scanner(IP, port_from, port_to);

        open_ports = port_scanner.the_scanner();
    }
    for (int port : open_ports){
            cout << "Open port: " << port << endl;

        }


    return 0;
}