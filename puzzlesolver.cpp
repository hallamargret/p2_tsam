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

// Closes the socket
void close_socket(int sock){
    shutdown(sock, SHUT_RDWR);
    close(sock);
}

struct pseudo_header{
        u_int32_t source_address;
        u_int32_t dest_address;
        u_int8_t placeholder;
        u_int8_t protocol;
        u_int16_t udp_length;
    };

string send_recv(const char* IP, int port, char* buffer, int size_buffer, struct sockaddr_in destaddr, int udp_sock){
    char message_buffer[1400];
    memset(&message_buffer, 0, sizeof(message_buffer));
    string return_messages;
    //int udp_sock = open_socket();
    if(udp_sock > 0){
        fd_set masterfds;
        FD_SET(udp_sock, &masterfds);
        struct timeval timeout;             // Timeout for recvfrom()
        timeout.tv_sec = 1;
        timeout.tv_usec = 0;            // Set timeout to 1 second
        

        destaddr.sin_family = AF_INET;
        inet_aton(IP, &destaddr.sin_addr);
        destaddr.sin_port = htons(port);

        if (sendto(udp_sock, buffer, size_buffer, 0, (const struct sockaddr *)&destaddr, sizeof(destaddr)) < 0){
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

u_short calculate_checksum(unsigned short *udpheader, u_short len){
    long checksum;
    u_short odd_byte;
    short checksum_short;

    checksum = 0;
    while(len > 1) {
        checksum += *udpheader++;
        len -= 2;
    }
    if(len == 1) {
        odd_byte = 0;
        *((u_char*) &odd_byte) =*(u_char*)udpheader;
        checksum += odd_byte;
    }

    checksum = (checksum >> 16) + (checksum & 0xffff);
    checksum = checksum + (checksum >> 16);
    checksum_short = (short)~checksum;

    return checksum_short;
}

void make_udp_packet(u_short checksum, string given_source_addr, int port, int udp_sock, struct sockaddr_in destaddr)
{
    char udp_packet[4096];
    memset(udp_packet, 0, 4096);
    //const char *data = last_six.c_str();
    unsigned short data;
    //char udp_packet[20 + 8 + sizeof(data)];
    
    struct ip *ip_header = (struct ip*) udp_packet;
    struct udphdr *udp_header = (struct udphdr*) (udp_packet + sizeof(struct ip));
    struct pseudo_header psh;       // pseudo header for checksum calculations later for the udp header

    char *message_buffer = (char *) (udp_packet + sizeof(struct ip) + sizeof(struct udphdr));

    struct in_addr src_addr;
    inet_aton(given_source_addr.c_str(), &src_addr);
    ip_header->ip_src = src_addr;

    struct in_addr dst_addr;
    inet_aton("130.208.242.120", &dst_addr);
    ip_header->ip_dst = dst_addr;

    ip_header->ip_ttl = 255;
    ip_header->ip_len = htons(sizeof(struct ip) + sizeof(struct udphdr) + 2);
    ip_header->ip_hl = 5;
    ip_header->ip_p = IPPROTO_UDP;
    ip_header->ip_tos = 0;
    ip_header->ip_off = 0;
    ip_header->ip_id = 1377;
    ip_header->ip_v = 4;

    udp_header->uh_dport = htons(port);    //dest port
    udp_header->uh_sport = htons(58585);   // source port
    udp_header->uh_sum = htons(checksum);     // leave checksum as 0 now, will fill later by pseudo header
    udp_header->uh_ulen = htons(sizeof(struct udphdr) + 2);

    //tcp checksum
    // pseudo header
    psh.source_address = inet_addr(given_source_addr.c_str());
    psh.dest_address = inet_addr("130.208.242.120");
    psh.placeholder = 0;
    psh.protocol = IPPROTO_UDP;
    psh.udp_length = htons(sizeof(struct udphdr) + 2);

    int psize = sizeof(struct pseudo_header) + sizeof(struct udphdr) + 2;
    char *pseudo_data = (char *) malloc(psize);
    memcpy(pseudo_data , (char*) &psh, sizeof(struct pseudo_header));
    memcpy(pseudo_data + sizeof(struct pseudo_header), udp_header, sizeof(struct udphdr));
    memcpy(pseudo_data + sizeof(struct pseudo_header) + sizeof(struct udphdr), message_buffer, 2);

    data = calculate_checksum((unsigned short*) pseudo_data, psize);

    memcpy(message_buffer, &data, 2);

    ip_header->ip_sum = htons(calculate_checksum((unsigned short*) udp_packet, ip_header->ip_len));

    int length = sizeof(struct ip) + sizeof(struct udphdr) + 2;

    string secret_phrase;
    string messages = "";
    string msg_begin = "Congratulations group_37!";
    messages = send_recv("130.208.242.120", port, udp_packet, length, destaddr, udp_sock);
    while (true){
        if (messages.size() >= msg_begin.size()){
            bool same = true;
            for (int i = 0; i < msg_begin.size(); i++){
                if (messages[i] != msg_begin[i]){
                    same = false;
                }
            }
            if (same){
                string before_phrase = "\"";
                int position_phrase = messages.find(before_phrase) + 1;
                while (messages[position_phrase] != '\"'){
                    secret_phrase += messages[position_phrase];
                    position_phrase ++;
                }
                break;
            }
        }
        messages = send_recv("130.208.242.120", port, udp_packet, length, destaddr, udp_sock);
    }
    cout << "Secret Phrase: " << secret_phrase << endl;

}

// Here we find and return the local address.
struct in_addr local_address() {
    char buffer[1024];
    memset(buffer, 0, sizeof(buffer));

    int the_socket = socket(AF_INET, SOCK_DGRAM, 0);

    const char *google_dns_ip = "8.8.8.8";
    int dns_port = 53;

    struct sockaddr_in server;

    memset(&server, 0, sizeof(server));
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = inet_addr(google_dns_ip);
    server.sin_port = htons(dns_port);

    connect(the_socket, (const struct sockaddr *)&server, sizeof(server));

    struct sockaddr_in local_addr;
    socklen_t addr_len = sizeof(local_addr);
    getsockname(the_socket, (struct sockaddr *)&local_addr, &addr_len);

    close(the_socket);
    return local_addr.sin_addr;
}


void evil_bit(int port, const char* IP){
    int raw_sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (raw_sock < 0) {
        perror("Unable to connect socket");
        exit(-1);
    }

    int IPHDR_OPT = 1;
    if (setsockopt(raw_sock, IPPROTO_IP, IP_HDRINCL, &IPHDR_OPT, sizeof(IPHDR_OPT)) < 0){
        perror("Setsockopt error.");
        exit(-1);
    }

    char evil_packet[128];
    strcpy(evil_packet, "$group_37$");
    char *packet = (char *) malloc(sizeof(struct ip) + sizeof(struct udphdr) + strlen(evil_packet));
    struct ip *ip_header = (struct ip*) packet;
    struct udphdr *udp_header = (struct udphdr*) (packet + sizeof(struct ip));
    char *message_buffer = (char*) (packet + sizeof(struct ip) + sizeof(struct udphdr));

    struct in_addr local_addr = local_address();
    char src_address[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(local_addr), src_address, INET_ADDRSTRLEN);

    int length_buffer = sizeof(struct ip) + sizeof(struct udphdr) + 2;

    ip_header->ip_ttl = 255;        //time to live
    ip_header->ip_len = htons(sizeof(struct ip) + sizeof(struct udphdr) + strlen(evil_packet));     //total length
    ip_header->ip_hl = 5;       // ip header length
    ip_header->ip_p = IPPROTO_UDP;      // protocol
    ip_header->ip_tos = 0;      // Type of service
    ip_header->ip_off = htons(0x8000);      // Fragment offset. Evil bit.
    ip_header->ip_id = 1377;    // id
    ip_header->ip_v = 4;        // ip version
    ip_header->ip_sum = 0;      // checksum
    ip_header->ip_src = local_addr;     // Source addr:
    //ip_header->ip_src = inet_addr(src_address);                                             // Source addr: 10.3.16.180
    //ip_header->ip_dst = inet_addr(ip_address);                                              // Dest addr: 130.208.242.120 (ip_address)
    struct in_addr dst_addr;
    inet_aton("130.208.242.120", &dst_addr);
    ip_header->ip_dst = dst_addr;       // Dest addr: 130.208.242.120


    //udp header
    udp_header->uh_sport = htons(58585);        // Source port, we desice some port number.
    udp_header->uh_dport = htons(port);         // Destination port; EVIL PORT.
    udp_header->uh_ulen = htons(sizeof(struct udphdr) + strlen(evil_packet));       // Length of udp header.
    udp_header->uh_sum = 0;     // Checksum
    strcpy(message_buffer, evil_packet);

    int recv_sock = open_socket();
    struct sockaddr_in recv_addr;
    recv_addr.sin_family = AF_INET;
    inet_aton(src_address, &recv_addr.sin_addr);
    recv_addr.sin_port = htons(58585);


    if(bind(recv_sock, (const sockaddr*) &recv_addr, sizeof(recv_addr)) < 0){
        perror("Failed to bind receive socket.");
    }

    fd_set masterfds;
    FD_SET(recv_sock, &masterfds);
    struct timeval timeout;             // Timeout for recvfrom()
    timeout.tv_sec = 1;
    timeout.tv_usec = 0;            // Set timeout to 1 second

    char recv_message_buffer[1400];
    memset(&recv_message_buffer, 0, sizeof(recv_message_buffer));
    string return_messages;
    char* secret_port_evil;

    for(int i = 0; i < 5; i++){
        if (sendto(raw_sock, &evil_packet, length_buffer, 0, (const struct sockaddr *)&dst_addr, sizeof(dst_addr)) < 0) {
            perror("Failed to send");
        }

        // The select() function indicates which of the specified file descriptors is ready for reading, 
        // ready for writing, or has an error condition pending.
        if (select(recv_sock + 1, &masterfds, NULL, NULL, &timeout) > 0) {
            int response = recvfrom(recv_sock, recv_message_buffer, sizeof(recv_message_buffer), 0, (sockaddr *)&recv_addr, (socklen_t *) sizeof(recv_addr));
            if (response < 0) {
                perror("Error receiving from server");
            }
            else {
                char src_address[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &(recv_addr.sin_addr), src_address, INET_ADDRSTRLEN); // Find src_address to compare to ip address.
                if ((strcmp(IP, src_address) == 0) && ntohs(recv_addr.sin_port) == port){
                    recv_message_buffer[response] = '\0';
                    secret_port_evil = recv_message_buffer + response - 4; // To get the last four letters from the response - The secret port
                    close_socket(raw_sock);
                    close_socket(recv_sock);
                    cout << "Messages: " << recv_message_buffer << endl;
                    cout << "Secret Port " << secret_port_evil << endl;
                }
            }
        }  
    }

    // int counter = 1;
    // string messages;
    // messages = send_recv(IP, port, message_buffer, length_buffer, recv_addr ,recv_sock);
    // for (int i = 0; i < 5; i++){
    //     cout << "Messages " << counter++ << ": " << messages << endl;
    //     messages = send_recv(IP, port, message_buffer, length_buffer, recv_addr ,recv_sock);
    // }
    


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
        messages = send_recv(IP, port, buffer, strlen(buffer), destaddr, udp_sock);
        while (messages == ""){
            messages = send_recv(IP, port, buffer, strlen(buffer), destaddr, udp_sock);
        }
        cout << port << ": " << messages << endl;
        string groupstr_begin = "Hello, group_37!";
        string the_oracle = "I am the oracle,";
        string boss_port = "My boss told me ";
        string evil_begin = "The dark side of";
        bool hello_group_37 = true;
        bool oracle = true;
        bool evil = true;
        bool boss = true;
        for (int i = 0; i < 16; i++){
            
            if (messages[i] != groupstr_begin[i]){
                hello_group_37 = false;
            }
            if (messages[i] != the_oracle[i]){
                oracle = false;
            }
            if (messages[i] != boss_port[i]){
                boss = false;
            }
            if (messages[i] != evil_begin[i]){
                evil = false;
            }

        }
        
        if (oracle){
            // send a comma-seperated list of the hidden ports.
            // check if we have all the hidden ports before sending the list
        }
        if (boss){
            string hidden_port = messages.substr((messages.size()-5));
            cout << "substring: " << hidden_port << endl;
            int boss_hidden_port = stoi(hidden_port);
            cout << boss_hidden_port << endl;
        }
        // evil bit
        if (evil){
            evil_bit(port, IP);
        }

        // Hello group 37 messages - Solve checksum puzzle
        if (hello_group_37){
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
            
            u_short checksum_short = (unsigned short) (stoul(checksum, 0, 16));
            make_udp_packet(checksum_short, given_source_addr, port, udp_sock, destaddr);
        }
    }
    return 0;
}
