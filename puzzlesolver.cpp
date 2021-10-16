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
#include <vector>
#include <sstream>
#include <set>
#include <queue>

#include "scannerClass.h"

using namespace std;

int ports[4] = {0}; //Keeps track of what port is what
int ORACLE_PORT = 0;
int CHECKSUM_PORT = 1;
int EVIL_PORT = 2;
int SIMPLE_PORT = 3;

string checksum_begin = "Hello, group_37!";
string oracle_begin = "I am the oracle,";
string simple_begin = "My boss told me ";
string evil_begin = "The dark side of";

struct pseudo_header{
        u_int32_t source_address;
        u_int32_t dest_address;
        u_int8_t placeholder;
        u_int8_t protocol;
        u_int16_t udp_length;
};

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

// Sends the udp socket to the given ip address and recieve the message after the sock is sent
string send_recv(const char* IP, int port, char* buffer, int size_buffer, int udp_sock){
    struct sockaddr_in destaddr;
    char message_buffer[1400];
    memset(&message_buffer, 0, sizeof(message_buffer));
    string return_messages;

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

string get_right_substring(string messages_before, string messages){
    string return_string;
    int position = messages.find(messages_before) + messages_before.size();
    while (messages[position] != '!'){
        return_string += messages[position];
        position ++;
    }
    return return_string;
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

string get_secret_phrase(u_short checksum, string given_source_addr, int udp_sock){
    // CREATE UDP PACKET
    char udp_packet[4096];
    memset(udp_packet, 0, 4096);
    //const char *data = last_six.c_str();
    unsigned short data;
    //char udp_packet[20 + 8 + sizeof(data)];
    
    struct ip *ip_header = (struct ip*) udp_packet;
    struct udphdr *udp_header = (struct udphdr*) (udp_packet + sizeof(struct ip));
    struct pseudo_header psh;       // pseudo header for checksum calculations later for the udp header

    char *message_buffer = (char *) (udp_packet + sizeof(struct ip) + sizeof(struct udphdr));

    // SET IP HEADER
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

    // SET UDP HEADER
    udp_header->uh_dport = htons(ports[CHECKSUM_PORT]);         //dest port
    udp_header->uh_sport = htons(58585);        // source port
    udp_header->uh_sum = htons(checksum);       // Set checksum to the checksum we want
    udp_header->uh_ulen = htons(sizeof(struct udphdr) + 2);

    // MAKE PSEUDO HEADER
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

    // Use pseudo header and calculate_checksum function with data set to 0 to calculate 
    // the difference needed to make the checksum we want valid
    // We add the difference to the data to make it valid.
    data = calculate_checksum((unsigned short*) pseudo_data, psize);

    memcpy(message_buffer, &data, 2);

    // Calculate checksum for ip header
    ip_header->ip_sum = htons(calculate_checksum((unsigned short*) udp_packet, ip_header->ip_len));

    int length = sizeof(struct ip) + sizeof(struct udphdr) + 2;


    // SEND UDP PACKET WITH VALID CHECKSUM TO THE PORT
    string secret_phrase;
    string messages = "";
    string msg_begin = "Congratulations group_37!";
    messages = send_recv("130.208.242.120", ports[CHECKSUM_PORT], udp_packet, length, udp_sock);
    while (true){
        if (strstr(messages.c_str(), msg_begin.c_str())){
            string before_phrase = "\"";
            int position_phrase = messages.find(before_phrase) + 1;
            while (messages[position_phrase] != '\"'){
                secret_phrase += messages[position_phrase];
                position_phrase ++;
            }
            break;
        }
        messages = send_recv("130.208.242.120", ports[CHECKSUM_PORT], udp_packet, length, udp_sock);
    }
    return secret_phrase;
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

int evil_bit(const char* IP, struct in_addr dest_addr){
    // making a raw socket
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

    char packet[4096];
    memset(packet, 0, 4096);

    char evil_data[128];
    strcpy(evil_data, "$group_37$");
    
    //char *packet = (char *) malloc(sizeof(struct ip) + sizeof(struct udphdr) + strlen(evil_data));
    struct ip *ip_header = (struct ip*) packet;
    struct udphdr *udp_header = (struct udphdr*) (packet + sizeof(struct ip));
    char *message_buffer = (char*) (packet + sizeof(struct ip) + sizeof(struct udphdr));

    struct in_addr local_addr = local_address();
    char src_address[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(local_addr), src_address, INET_ADDRSTRLEN);


    ip_header->ip_ttl = 255;        //time to live
    ip_header->ip_len = sizeof(struct ip) + sizeof(struct udphdr) + strlen(evil_data);     //total length
    ip_header->ip_hl = 5;               // ip header length
    ip_header->ip_p = IPPROTO_UDP;      // protocol
    ip_header->ip_tos = 0;              // Type of service
    ip_header->ip_off = htons(0x8000);  // Fragment offset. Evil bit!!
    ip_header->ip_id = 5678;            // id
    ip_header->ip_v = 4;                // ip version
    ip_header->ip_sum = 0;              // checksum
    ip_header->ip_src = local_addr;      // source address is our local address
    ip_header->ip_dst = dest_addr;       // Dest addr: 130.208.242.120


    //udp header
    udp_header->uh_sport = htons(30000);             // Source port, we desice some port number.
    udp_header->uh_dport = htons(EVIL_PORT);         // Destination port;
    udp_header->uh_ulen = htons(sizeof(struct udphdr) + strlen(evil_data));       // The length of the udp header.
    udp_header->uh_sum = 0;     // Checksum
    strcpy(message_buffer, evil_data);

    int recv_sock = open_socket();
    struct sockaddr_in recv_addr;
    inet_aton(src_address, &recv_addr.sin_addr);
    recv_addr.sin_family = AF_INET;
    recv_addr.sin_port = htons(30000);


    if(bind(recv_sock, (const sockaddr*) &recv_addr, (socklen_t) sizeof(recv_addr)) < 0){
        perror("Failed to bind receive socket.");
    }

    fd_set masterfds;
    FD_SET(recv_sock, &masterfds);
    struct timeval timeout;             // Timeout for recvfrom()
    timeout.tv_sec = 1;
    timeout.tv_usec = 0;            // Set timeout to 1 second

    int addr_len = sizeof(recv_addr);

    int res_length = 1400;
    char *recv_message_buffer = new char[res_length];

    //memset(&recv_message_buffer, 0, sizeof(recv_message_buffer));
    string return_messages;
    char* secret_port_evil;
    
    for(int i = 0; i < 5; i++){
        // we cant send, the socket is not connected 
        if (sendto(raw_sock, &packet, (sizeof(struct ip) + sizeof(struct udphdr) + strlen(evil_data)), 0, (const struct sockaddr *)&dest_addr, sizeof(dest_addr)) < 0) {
            perror("Failed to send");
        }
        //just cheching if we can connect 
        if(connect(raw_sock, (struct sockaddr *) &dest_addr, sizeof(dest_addr)) < 0){
        perror("Could not connect");
    }


        // select() indicates which of the specified file descriptors is ready for reading, ready for writing, or has an error condition pending.
        if (select(recv_sock + 1, &masterfds, NULL, NULL, &timeout) > 0) {
            int response = recvfrom(recv_sock, recv_message_buffer, res_length, 0, (sockaddr *)&recv_addr, (socklen_t *) &addr_len);
            if (response < 0) {
                perror("Error receiving from server");
            }
            else {
                char src_address[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &(recv_addr.sin_addr), src_address, INET_ADDRSTRLEN); // Find the source address to compare to the ip address.
                if ((strcmp(IP, src_address) == 0) && ntohs(recv_addr.sin_port) == EVIL_PORT){
                    recv_message_buffer[response] = '\0';
                    secret_port_evil = recv_message_buffer + response - 4; // To get the last four letters from the response - The secret port
                    close_socket(raw_sock);
                    close_socket(recv_sock);
                    cout << "Messages: " << recv_message_buffer << endl;
                    cout << "Secret Port " << secret_port_evil << endl;
                    return stoi(secret_port_evil);
                }
            }
        }
    }
    return -1;
}

string knock_knock(vector<string> order_of_knock_ports, string secret_phrase, const char *IP, int udp_sock){
    string knock_messages;
    for(int i = 0; i< order_of_knock_ports.size(); i++) {    //print all splitted strings
        string msg_back;
        char messages[1400];
        int port = stoi(order_of_knock_ports.at(i));
        strcpy(messages, secret_phrase.c_str());
        msg_back = send_recv(IP, port, messages, secret_phrase.size(), udp_sock);
        if (msg_back ==  ""){
            return "Try again";
        } else {
            knock_messages = msg_back;
        }
   }
   return knock_messages;
}

void prepare_for_knock(string messages_to_oracle, string secret_phrase, const char* IP, int udp_sock){
    char messages_buffer[1400];
    vector<string> order_of_knock_ports;

    strcpy(messages_buffer, messages_to_oracle.c_str());
    string recv_messages = send_recv(IP, ports[ORACLE_PORT], messages_buffer, strlen(messages_buffer), udp_sock);
    cout << recv_messages << endl;
    string correct_begin = "4006,";
    while (true){
        if (strstr(recv_messages.c_str(), correct_begin.c_str())){  
            stringstream s_stream(recv_messages); //create string stream from the string
            while(s_stream.good()) {
                string substr;
                getline(s_stream, substr, ','); //get first string delimited by comma
                order_of_knock_ports.push_back(substr);
            }
            break;
        }
    }
    string knock_messages = knock_knock(order_of_knock_ports, secret_phrase, IP, udp_sock);
    while (knock_messages == "Try again"){
        knock_messages = knock_knock(order_of_knock_ports, secret_phrase, IP, udp_sock);
    }
    cout << knock_messages << endl;
}


void send_to_open_ports(set<int> open_ports, const char *IP, int udp_sock){
    char send_buffer[1400];
    strcpy(send_buffer, "$group_37$");

    for (int port : open_ports){
        string messages = "";
        messages = send_recv(IP, port, send_buffer, strlen(send_buffer), udp_sock);
        while (messages == ""){
            messages = send_recv(IP, port, send_buffer, strlen(send_buffer), udp_sock);
        }
        //cout << port << ": " << messages << endl;
    
        // oracle port
        if (strstr(messages.c_str(), oracle_begin.c_str())){
            ports[ORACLE_PORT] = port;
        }

        // simple port
        if (strstr(messages.c_str(), simple_begin.c_str())){
            ports[SIMPLE_PORT] = port;
        }

        // evil bit
        if (strstr(messages.c_str(), evil_begin.c_str())){
            ports[EVIL_PORT] = port;
        }

        // checksum
        if (strstr(messages.c_str(), checksum_begin.c_str())){
            ports[CHECKSUM_PORT] = port;
        }
    }
}

queue<string> get_info_for_oracle(set<int> open_ports, const char *IP, int udp_sock, struct in_addr destaddr){
    char send_buffer[1400];
    strcpy(send_buffer, "$group_37$");
    queue<string> return_values;
    string secret_phrase = "";
    set<int> secret_ports;

    // CHECKSUM PORT
    string messages = "";
    messages = send_recv(IP, ports[CHECKSUM_PORT], send_buffer, strlen(send_buffer), udp_sock);
    while (true){
        if (strstr(messages.c_str(), checksum_begin.c_str()) && secret_phrase == ""){
            string given_source_addr = get_right_substring("source address being ", messages);
            string checksum = get_right_substring(" UDP checksum of ", messages);
            u_short checksum_short = (unsigned short) (stoul(checksum, 0, 16));
            secret_phrase = get_secret_phrase(checksum_short, given_source_addr, udp_sock);
            break;
        }
        messages = send_recv(IP, ports[CHECKSUM_PORT], send_buffer, strlen(send_buffer), udp_sock);
    }

    // EVIL PORT
    messages = "";
    messages = send_recv(IP, ports[EVIL_PORT], send_buffer, strlen(send_buffer), udp_sock);
    while (true){
        if (strstr(messages.c_str(), evil_begin.c_str())){
            secret_ports.insert(4006); // Because we could not finnish evil_bit, the socket would not connect, otherwise evil_bit finished
            //uncomment the below line to call evil_bit
            //evil_bit(IP, destaddr);
            break;
        }
        messages = send_recv(IP, ports[EVIL_PORT], send_buffer, strlen(send_buffer), udp_sock);
    }

    // SIMPLE PORT 
    messages = "";
    messages = send_recv(IP, ports[SIMPLE_PORT], send_buffer, strlen(send_buffer), udp_sock);
    while (true){
        if (strstr(messages.c_str(), simple_begin.c_str())){
            string hidden_port = messages.substr((messages.size()-5));
            secret_ports.insert(stoi(hidden_port));
            break;
        }
        messages = send_recv(IP, ports[SIMPLE_PORT], send_buffer, strlen(send_buffer), udp_sock);
    }

    for (int port : secret_ports){
        return_values.push(to_string(port));
    }
    return_values.push(secret_phrase);
    return return_values;
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

        // destaddr.sin_family = AF_INET;
        // inet_aton(IP, &destaddr.sin_addr);

        open_ports = port_scanner.the_scanner();
        while (open_ports.size() != 4){
            cout << "One of the ports are not responding - Try again" << endl;
            exit(0);
        }
    }
    else if (argc == 6){
        //got the ports in as arguments
        udp_sock = open_socket();
        IP = argv[1];
        for (int i = 2; i < 6; i++){
            open_ports.insert(atoi(argv[i]));
        }
    }
    else {
        cout << "The program should be run with the command:" << endl;
        cout << "./puzzlesolver <IP address>" << endl;
        cout << "or\n./puzzlesolver <IP address> <port1> <port2> <port3> <port4>" << endl; 
        exit(0);
    }

    destaddr.sin_family = AF_INET;
    inet_aton(IP, &destaddr.sin_addr);

    int send_to_open_ports_counter = 0;
    send_to_open_ports(open_ports, IP, udp_sock);
    while (ports[EVIL_PORT] == 0 || ports[CHECKSUM_PORT] == 0 || ports[SIMPLE_PORT] == 0 || ports[ORACLE_PORT] == 0){
        if (send_to_open_ports_counter >= 10){
            cout << "One of the open ports is not responding - Please try again" << endl;
            exit(0);
        }
        send_to_open_ports(open_ports, IP, udp_sock);
        send_to_open_ports_counter++;
    }

    queue<string> info_for_oracle = get_info_for_oracle(open_ports, IP, udp_sock, destaddr.sin_addr);
    while (info_for_oracle.size() != 3){
        info_for_oracle = get_info_for_oracle(open_ports, IP, udp_sock, destaddr.sin_addr);
    }
    string secret_ports_comma_sep = info_for_oracle.front();
    info_for_oracle.pop();
    secret_ports_comma_sep += "," + info_for_oracle.front();
    info_for_oracle.pop();
    string secret_phrase = info_for_oracle.front();
    info_for_oracle.pop();
    
    prepare_for_knock(secret_ports_comma_sep, secret_phrase, IP, udp_sock);
    return 0;
}