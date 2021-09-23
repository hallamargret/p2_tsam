#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
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

int open_socket(){
    int udp_sock = socket(AF_INET, SOCK_DGRAM, 0);

        if(udp_sock < 0) // -1 if error
        {
            perror("Failed to open socket in puzzlesolver ");
            return(-1);
        }
    return udp_sock;
}

string send_recv(const char* IP, int port, char* buffer, struct sockaddr_in destaddr, int udp_sock){
    char message_buffer[1400];
    memset(&message_buffer, 0, sizeof(message_buffer));
    string return_messages;
    //int udp_sock = open_socket();
    if(udp_sock > 0){
        fd_set masterfds;
        FD_SET(udp_sock, &masterfds);
        struct timeval timeout;             // Timeout for recvfrom()
        timeout.tv_sec = 0;
        timeout.tv_usec = 20000;            // Set timeout to 0.2 seconds
        

        destaddr.sin_family = AF_INET;
        inet_aton(IP, &destaddr.sin_addr);
        destaddr.sin_port = htons(port);

        if (sendto(udp_sock, buffer, strlen(buffer), 0, (const struct sockaddr *)&destaddr, sizeof(destaddr)) < 0){
            perror("Failed to send");
        }
        else {
            int t = select(udp_sock + 1, &masterfds, NULL, NULL, &timeout);
            if (t > 0){ // if t is 0, timeout accured
                int destaddr_size = sizeof(destaddr);
                if(recvfrom(udp_sock, message_buffer, sizeof(message_buffer), 0, (sockaddr *)&destaddr, (socklen_t *)&destaddr_size) < 0){
                    perror("Failed to recieve");
                }
                else { // if ok, print buffer messages
                    return_messages = message_buffer;
                    return return_messages;
                }
            }
        }
    }
    return return_messages;
}

void make_udp_packet(string last_six, int checksum, string given_source_addr, int port, int udp_sock, struct sockaddr_in destaddr)
{
    struct sockaddr_in source_addr;
    source_addr.sin_family = AF_INET;
    inet_aton(given_source_addr.c_str(), &source_addr.sin_addr);
    source_addr.sin_port = htons(59507);
    const char *data = last_six.c_str();
    char udp_packet[20 + 8 + last_six.size()];
    struct ip *ip_header = (struct ip*) udp_packet;
    struct udphdr *udp_header = (struct udphdr*) (udp_packet);
    char *message_buffer = (char *) (udp_packet + 20 + 8);
    strcpy(message_buffer, data);
    ip_header->ip_src = inet_makeaddr(inet_addr(given_source_addr.c_str()), INADDR_ANY);
    ip_header->ip_dst = inet_makeaddr(inet_addr("130.208.242.120"), INADDR_ANY);
    ip_header->ip_ttl = 5;
    udp_header->uh_dport = port;
    udp_header->uh_sport = source_addr.sin_port;
    udp_header->uh_sum = checksum;

    string messages = "";
    messages = send_recv("130.208.242.120", port, udp_packet, destaddr, udp_sock);
    while (messages == ""){
        messages = send_recv("130.208.242.120", port, udp_packet, destaddr, udp_sock);
    }
    cout << "Answer: " << messages << endl;

    // if (sendto(udp_sock, udp_packet, (20 + 8 + sizeof(data)), 0, (const struct sockaddr *)&destaddr, sizeof(destaddr)) < 0){
    //         perror("Failed to send");
    //     }
    //     else {
    //         int t = select(udp_sock + 1, &masterfds, NULL, NULL, &timeout);
    //         if (t > 0){ // if t is 0, timeout accured
    //             int destaddr_size = sizeof(destaddr);
    //             if(recvfrom(udp_sock, message_buffer, sizeof(message_buffer), 0, (sockaddr *)&destaddr, (socklen_t *)&destaddr_size) < 0){
    //                 perror("Failed to recieve");
    //             }
    //             else { // if ok, print buffer messages
    //                 return_messages = message_buffer;
    //                 return return_messages;
    //             }
    //         }
    //     }
    

}




int main(int argc, char *argv[]){

    //pass the ports 4000-4100 on the command line
    char buffer[1400];  // Buffer for information to send
    int length;
    struct sockaddr_in destaddr;
    string messages;
    const char *IP;
    int udp_sock;


    set<int> open_ports;

    strcpy(buffer, "$group_37$"); // Message set to buffer
    length = strlen(buffer) + 1; // lenght of buffer

    if (argc == 2){
        IP = argv[1];
        //call scanner to get the open ports that are not hidden
        Scanner port_scanner = Scanner(IP, 4000, 4100);
        udp_sock = port_scanner.open_socket();
        destaddr.sin_family = AF_INET;
        inet_aton(IP, &destaddr.sin_addr);
        int destaddr_size = sizeof(destaddr);
        

        open_ports = port_scanner.the_scanner();

    }
    else if (argc == 6){
        //got the ports in as arguments
        udp_sock = open_socket();
        IP = argv[1];
        for (int i = 2; i < 6; i++){
            open_ports.insert(atoi(argv[i]));
        }


    }
    for (int port : open_ports){
            messages = "";
            messages = send_recv(IP, port, buffer, destaddr, udp_sock);
            while (messages == ""){
                messages = send_recv(IP, port, buffer, destaddr, udp_sock);
            }
            cout << port << ": " << messages << endl;
            string groupstr_begin = "Hello, group_37!";
            bool same = true;
            for (int i = 0; i <16; i++){
                
                if (messages[i] != groupstr_begin[i]){
                    same = false;
                }
            }
            if (same){
                string given_source_addr = "";
                string before_source_addr = "source address being ";
                int position = messages.find(before_source_addr) + before_source_addr.size();
                while (messages[position] != '!'){
                    given_source_addr += messages[position];
                    position ++;
                }
                cout << "source addr: "<< given_source_addr<< endl;

                string checksum;
                string before_checksum = " UDP checksum of ";
                int position_check = messages.find(before_checksum) + before_checksum.size();
                while (messages[position_check] != ','){
                    checksum += messages[position_check];
                    position_check ++;
                }
                string last_six;
                cout << "checksum: "<< checksum<< endl;
                string before_bytes = " network order)";
                int position_bytes = messages.find(before_bytes) + before_bytes.size();
                while (position_bytes < messages.size()){
                    last_six += messages[position_bytes];
                    position_bytes ++;
                }

                //string last_six = messages.substr(messages.size()-6);

                cout << "last 6 bytes: " <<last_six << endl;
                cout << "stoi checksum: "<< stoi(checksum, 0, 16) <<endl;
                cout <<"not stoi checksum, regular: "<< checksum <<endl;

                make_udp_packet(last_six, stoi(checksum, 0, 16), given_source_addr, port, udp_sock, destaddr);
            }
            
        }
    return 0;
}
