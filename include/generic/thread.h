#ifndef OB_THREAD_H
#define OB_THREAD_H

#include <pcap.h>
#include <limits.h>
#include <stdbool.h>

struct dash_arguments {
    char* verbosity_level;
    char* interface;
    char* input_file;
    char* bpf_filter;
    char* max_packet_count;
    char* save_file;
    bool display_help;
    bool nocolor;
    bool noprompt;
    bool display_version;
};

struct passed_message {
    pcap_t* capture;
    pcap_dumper_t* save;
    pthread_mutex_t* console;
    bpf_u_int32 netmask;
    struct dash_arguments* cli;
    int min_read;
    int random_seed;
    long long max_packet_count;
    long long read_packet_count;
    bool can_use_bpf;
    bool nocolor;
    bool noprompt;
    uint8_t verbosity_level;
    char input_buffer[_POSIX_MAX_CANON];
};

void* loop_read_packets(void* args);
void read_message(unsigned char* capture_args, const struct pcap_pkthdr* header, const unsigned char* packet);
void read_input_stop_signal(int signal);
void register_signal_handler(void (*signal_function) (int), int signal);

#endif
