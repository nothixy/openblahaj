#include <time.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>

#ifdef HAVE_CONFIG_H
    #include "config.h"
#endif
#include "link/link.h"
#include "generic/time.h"
#include "generic/thread.h"
#include "generic/protocol.h"
#include "generic/terminal.h"

static pcap_t* global_capture;

static volatile sig_atomic_t interrupt_pcap_loop = 0;
extern struct sctp_reassembly* sctp_fragmented[1 << 16];

static void pcap_stop_signal(int signal)
{
    close(STDIN_FILENO);
    if (signal == SIGUSR1)
    {
        interrupt_pcap_loop = 1;
    }

    return;
}

static void pcap_exit_signal(int signal)
{
    close(STDIN_FILENO);
    if (signal == SIGUSR1)
    {
        interrupt_pcap_loop = 1;
        pcap_breakloop(global_capture);
    }

    return;
}

void read_input_stop_signal(int signal)
{
    if (signal == SIGINT || signal == SIGTERM)
    {
        close(STDIN_FILENO);
    }
    return;
}

/**
 * @brief Register a signal handler
 * @param signal_function The signal handler to call on SIGINT
 * @param signal The signal to receive
 */
void register_signal_handler(void (*signal_function)(int), int signal)
{
    struct sigaction sa;
    sigset_t mask;

    sigemptyset(&mask);

    memset(&sa, 0, sizeof(sa));

    sa.sa_mask = mask;
    sa.sa_flags = 0;
    sa.sa_restorer = NULL;
    sa.sa_handler = signal_function;

    sigaction(signal, &sa, NULL);
}

/**
 * @brief Pcap message handler callback (this is not meant to be called manually)
 * @param capture_args Pointer to a structure containing the capture options
 * @param header Pointer to a pcap header structure
 * @param packet Message buffer
 */
void read_message(unsigned char* capture_args, const struct pcap_pkthdr* header, const unsigned char* packet)
{
    void* args_address = capture_args;
    uint8_t* packet_copy = NULL;
    struct passed_message* args = (struct passed_message*) args_address;

    static int modulo = -1;

    ssize_t cursor = 0;
    // ssize_t bytes_printed = 0;

    jmp_buf catcher;

    int jump_error = 0;

    struct ob_protocol buffer = {
        .dump = NULL,
        .hdr = NULL,
        .orig = NULL,
        .length = header->caplen - cursor,
        .verbosity_level = args->verbosity_level,
        .reassembled = false,
        .packet_index = args->read_packet_count + 1,
        .catcher = &catcher,
    };

    args->read_packet_count += 1;

    /**
     * Receiving a SIGINT here will disallow reading another packet after this one
     */
    register_signal_handler(pcap_stop_signal, SIGUSR1);

    pthread_mutex_lock(args->console);

    if ((packet_copy = malloc(header->caplen * sizeof(uint8_t))) == NULL)
    {
        goto END;
    }

    memcpy(packet_copy, packet, header->caplen * sizeof(uint8_t));

    buffer.hdr = packet_copy;
    buffer.orig = packet_copy;

    buffer.link_type = pcap_datalink(args->capture);

    link_cast(&buffer);

    erase_prompt();

    if (modulo == -1)
    {
        modulo = rand() % 5;
    }

    if (!args->nocolor)
    {
        switch (modulo)
        {
            case 0:
                printf("\033[31m");
                break;

            case 1:
                printf("\033[32m");
                break;

            case 2:
                printf("\033[33m");
                break;

            case 3:
                printf("\033[34m");
                break;

            case 4:
            default:
                printf("\033[35m");
                break;
        }
    }

    modulo = (modulo + 1) % 5;

    switch (args->verbosity_level)
    {
        case OB_VERBOSITY_LEVEL_LOW:
            printf("Packet %lld ", args->read_packet_count);
            break;

        case OB_VERBOSITY_LEVEL_MEDIUM:
            printf("Packet %lld\n", args->read_packet_count);
            break;

        case OB_VERBOSITY_LEVEL_HIGH:
        default:
            printf("%-45s = %lld\n", "Packet", args->read_packet_count);
            break;
    }

    if (args->verbosity_level == OB_VERBOSITY_LEVEL_HIGH)
    {
        char timestamp[150];
        printf("%-45s = %s\n", "Time", get_timestamp_utc(&header->ts, timestamp));
    }

    if (buffer.length > 0)
    {
        jump_error = 0;
        if (buffer.dump == NULL)
        {
            goto END;
        }

        if ((jump_error = setjmp(*(buffer.catcher))) == 0)
        {
            (void) buffer.dump(&buffer);
        }
    }

END:
    if (!args->nocolor)
    {
        printf("\033[0m\033(B\033)0\017\033[?5l\0337\033[0;0r\0338");
    }
    if (jump_error != 0)
    {
        display_error(jump_error);
        if (args->verbosity_level == OB_VERBOSITY_LEVEL_HIGH)
        {
            printf("\n");
        }
        else
        {
            printf(" ");
        }
    }
    if (args->verbosity_level == OB_VERBOSITY_LEVEL_LOW)
    {
        printf("\n");
    }
    printf("-----------------------------------\n");
    printf("\033[0m");
    if (!args->noprompt)
    {
        prompt(args->input_buffer);
    }
    if (args->cli->interface)
    {
        set_title(OB_NAME " - %s [%ld packets received]", args->cli->interface, args->read_packet_count);
    }
    else
    {
        set_title(OB_NAME " - offline capture - %s [%ld packets received]", args->cli->input_file, args->read_packet_count);
    }
    pthread_mutex_unlock(args->console);
    free(buffer.orig);
    if (args->save != NULL)
    {
        pcap_dump((unsigned char*) args->save, header, packet);
    }
    if (interrupt_pcap_loop == 1)
    {
        pcap_breakloop(args->capture);
    }
    return;
}

void* loop_read_packets(void* args)
{
    struct passed_message* capture_args = args;
    int min_read = capture_args->min_read;

    int pcap_dispatch_status;
    sigset_t block;

    global_capture = capture_args->capture;

    sigemptyset(&block);
    sigaddset(&block, SIGINT);

    pthread_sigmask(SIG_BLOCK, &block, NULL);

    while (!interrupt_pcap_loop)
    {
        /**
         * Receiving a SIGINT here will terminate here and not wait for another
         * packet. It does not cause a memory leak because only stack memory is
         * used here, and the parent process will free all the heap memory
         */
        register_signal_handler(pcap_exit_signal, SIGUSR1);

        pcap_dispatch_status = pcap_dispatch(capture_args->capture, 1, read_message, (unsigned char*) capture_args);

        if (pcap_dispatch_status < min_read)
        {
            break;
        }

        if (capture_args->read_packet_count >= capture_args->max_packet_count && capture_args->max_packet_count != -1)
        {
            interrupt_pcap_loop = 0;
            break;
        }
    }

    /**
     * If we were not interrupted by the main thread, signal it
     */
    if (!interrupt_pcap_loop)
    {
        kill(getpid(), SIGINT);
    }

    return NULL;
}
