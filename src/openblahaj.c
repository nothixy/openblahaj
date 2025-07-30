#include <errno.h>
#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <termios.h>
#include <pcap/pcap.h>

#ifdef HAVE_CONFIG_H
    #include "config.h"
#endif
#include "network/ip4.h"
#include "generic/dash.h"
#include "transport/tcp.h"
#include "generic/thread.h"
#include "transport/sctp.h"
#include "generic/terminal.h"
#include "generic/constants.h"

/**
 * @brief List all interfaces and let the user select
 * @param args Pointer to a dash_arguments structure
 * @return - -1 on error
 * @return - 0 on sucess
 * @return - 2 on interfaces listed but user was not allowed to select
 */
static int pcap_setup_interface(struct dash_arguments* args)
{
    pcap_if_t* devsp;
    pcap_if_t* devsp_copy;
    size_t interface_len;
    int interface_count = 0;
    int interface_index = -1;
    char errbuf[PCAP_ERRBUF_SIZE];

    int return_code = 0;

    sigset_t signals;

    sigemptyset(&signals);
    sigaddset(&signals, SIGINT);
    sigaddset(&signals, SIGTERM);

    register_signal_handler(read_input_stop_signal, SIGINT);
    register_signal_handler(read_input_stop_signal, SIGTERM);

    pcap_findalldevs(&devsp, errbuf);

    devsp_copy = devsp;

    /**
     * Print all interfaces to the console
     */
    do
    {
        if (!args->list_interfaces)
        {
            printf("%-3d: %s", interface_count + 1, devsp_copy->name);
            if (devsp_copy->description != NULL)
            {
                printf(" [%s]", devsp_copy->description);
            }
#ifndef OB_BUILD_BLUETOOTH
            if (!strncmp(devsp_copy->name, "bluetooth", 9))
            {
                printf(" (Probably unsupported)");
            }
#endif
#ifndef OB_BUILD_DBUS
            if (!strncmp(devsp_copy->name, "dbus", 4))
            {
                printf(" (Probably unsupported)");
            }
#endif
        }
        else
        {
            printf("%s", devsp_copy->name);
        }
        printf("\n");
        ++interface_count;
    }
    while ((devsp_copy = devsp_copy->next) != NULL);

    if (args->list_interfaces)
    {
        return_code = 2;
        goto PCAP_SETUP_INTERFACE_END;
    }

    if (interface_count == 0)
    {
        fputs("No interface available\n", stderr);
        return -1;
    }

    /**
     * Let the user select an interface
     */
    do
    {
        printf("Choose an interface [1-%d]\n", interface_count);

        sigprocmask(SIG_UNBLOCK, &signals, NULL);

        if (scanf("%d", &interface_index) < 0)
        {
            pcap_freealldevs(devsp);
            return -1;
        }

        sigprocmask(SIG_BLOCK, &signals, NULL);

        if (interface_index < 0 || interface_index > interface_count)
        {
            interface_index = -1;
            fputs("Invalid number\n", stderr);
        }
    }
    while (interface_index == -1);

    interface_index -= 1;

    devsp_copy = devsp;

    for (int i = 0; i < interface_index; ++i)
    {
        devsp_copy = devsp_copy->next;
    }

    interface_len = strlen(devsp_copy->name);

    args->interface = malloc((interface_len + 1) * sizeof(char));
    if (args->interface == NULL)
    {
        fputs("Memory allocation error\n", stderr);
        pcap_freealldevs(devsp);
        return -1;
    }

    strcpy(args->interface, devsp_copy->name);

PCAP_SETUP_INTERFACE_END:
    pcap_freealldevs(devsp);

    return return_code;
}

/**
 * @brief Configure PCAP according to command-line arguments
 * @param args Pointer to a structure containing values of the arguments
 * @param capture Double pointer to the capture object, NULL at the beginning
 * @return - -1 on error
 * @return - 0 on success
 */
static int pcap_setup(struct dash_arguments* args, pcap_t** capture, struct passed_message* capture_args)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    bpf_u_int32 netaddr;
    int pcap_activate_status;
    struct bpf_program fp;
    int return_code = 0;

    capture_args->can_use_bpf = true;

    /**
     * Reading from a file
     */
    if (args->input_file != NULL)
    {
        *capture = pcap_open_offline(args->input_file, errbuf);
        if (*capture == NULL)
        {
            fprintf(stderr, "[ERR] pcap_open_offline(): %s\n", errbuf);
            return -1;
        }
        set_title(OB_NAME " - offline capture - %s", args->input_file);
        return 1;
    }

    /**
     * Reading from an unspecified interface
     */
    if (args->interface == NULL)
    {
        if ((return_code = pcap_setup_interface(args)) != 0)
        {
            return return_code;
        }
    }

    *capture = pcap_create(args->interface, errbuf);
    if (*capture == NULL)
    {
        fprintf(stderr, "[ERR] pcap_create(): %s\n", errbuf);
        return -1;
    }

    /**
     * Find network of interfacem needed by pcap_compile()
     */
    if (pcap_lookupnet(args->interface, &netaddr, &(capture_args->netmask), errbuf))
    {
        fprintf(stderr, "[WRN] pcap_lookupnet(): %s\n", errbuf);
        fputs("[WRN] BPF filters will be ignored\n", stderr);
        capture_args->can_use_bpf = false;
    }

    if (pcap_set_immediate_mode(*capture, 1) == PCAP_ERROR_ACTIVATED)
    {
        fputs("[ERR] pcap_set_immediate_mode(): failed\n", stderr);
    }

    if (pcap_set_promisc(*capture, 1))
    {
        fprintf(stderr, "[WRN] pcap_set_promisc()\n");
    }

    if ((pcap_activate_status = pcap_activate(*capture)) != 0)
    {
        if (pcap_activate_status == PCAP_ERROR_PERM_DENIED)
        {
            fputs("[ERR] pcap_activate(): failed : permission denied, please run as root or use setcap(7)\n", stderr);
            return -1;
        }

        if (pcap_activate_status < 0)
        {
            fprintf(stderr, "[ERR] pcap_activate(): failed: %s\n", pcap_strerror(pcap_activate_status));
            return -1;
        }

        fprintf(stderr, "[WRN] pcap_activate(): %s\n", pcap_strerror(pcap_activate_status));
    }

    if (args->save_file != NULL)
    {
        if ((capture_args->save = pcap_dump_open(*capture, args->save_file)) == NULL)
        {
            fprintf(stderr, "[ERR] pcap_dump_open(): %s\n", pcap_geterr(*capture));
            return -1;
        }
    }

    if (capture_args->can_use_bpf && args->bpf_filter != NULL)
    {
        if (pcap_compile(*capture, &fp, args->bpf_filter, 0, capture_args->netmask) != 0)
        {
            fprintf(stderr, "[ERR] pcap_compile(): %s\n", pcap_geterr(*capture));
            return -1;
        }

        if (pcap_setfilter(*capture, &fp) != 0)
        {
            fprintf(stderr, "[ERR] pcap_setfilter(): %s\n", pcap_geterr(*capture));
            return -1;
        }

        pcap_freecode(&fp);
    }

    set_title(OB_NAME " - %s", args->interface);

    /**
     * The function pcap_setnonblock() is not called here as it is not supported
     * for all interfaces, for example dbus-system / dbus-session on Linux
     * systems, bluetooth, etc.
     *
     * Here, signals will be used to stop the reading loop
     */

    return 0;
}

/**
 * @brief Setup and parse command-line arguments with dash
 * @param argc Pointer to argc, will be modified
 * @param argv argv, will be modified
 * @param args Pointer to a dash_arguments structure
 * @return - 0 on success
 * @return - -1 on error
 */
static int setup_arguments(int* argc, char** argv, struct dash_arguments* args)
{
    /**
     * List of recognized options
     */
    dash_Longopt options[] = {
        {
            .user_pointer = &(args->display_help),
            .opt_name = 'h',
            .longopt_name = "help",
            .description = "Show this help message"
        },
        {
            .user_pointer = &(args->verbosity_level),
            .opt_name = 'v',
            .longopt_name = "verbose",
            .param_name = "level",
            .description = "Set verbosity to $"
        },
        {
            .user_pointer = &(args->interface),
            .opt_name = 'i',
            .longopt_name = "interface",
            .param_name = "interface",
            .description = "Scan packets on $"
        },
        {
            .user_pointer = &(args->input_file),
            .opt_name = 'o',
            .longopt_name = "offline",
            .param_name = "file",
            .description = "Open $ for offline capture"
        },
        {
            .user_pointer = &(args->save_file),
            .opt_name = 's',
            .longopt_name = "save",
            .param_name = "file",
            .description = "Save capture to $"
        },
        {
            .user_pointer = &(args->bpf_filter),
            .opt_name = 'f',
            .longopt_name = "filter",
            .param_name = "filter",
            .description = "Show only lines matching $"
        },
        {
            .user_pointer = &(args->max_packet_count),
            .opt_name = 'l',
            .longopt_name = "limit",
            .param_name = "count",
            .description = "Read at most $ packets"
        },
        {
            .user_pointer = &(args->display_hostnames),
            .opt_name = 'H',
            .longopt_name = "hostnames",
            .description = "Display hostnames associated to IP addresses"
        },
        {
            .user_pointer = &(args->nocolor),
            .longopt_name = "nocolor",
            .description = "Don't print ascii color codes on console"
        },
        {
            .user_pointer = &(args->noprompt),
            .longopt_name = "noprompt",
            .description = "Don't display a prompt at the bottom of the scren"
        },
        {
            .user_pointer = &(args->list_interfaces),
            .longopt_name = "list-interfaces",
            .description = "List interfaces that " OB_TITLE " can listen on"
        },
        {
            .user_pointer = &(args->display_version),
            .opt_name = 'V',
            .longopt_name = "version",
            .description = "Show version"
        },
        {0}
    };

    /**
     * No argument is required here
     */
    const char* required_args[] = {
        NULL
    };

    if (!dash_arg_parser(argc, argv, options))
    {
        dash_print_usage(argv[0], OB_TITLE " - version " OB_VERSION, "", required_args, options, stderr);
        return -1;
    }

    if (args->display_help)
    {
        dash_print_usage(argv[0], OB_TITLE " - version " OB_VERSION, "", required_args, options, stdout);
        return 1;
    }

    if (args->display_version)
    {
        printf("%s - version %s\n", OB_TITLE, OB_VERSION);
        return -1;
    }

    return 0;
}

/**
 * @brief Free memory used by all fragmented packets
 */
static void free_fragmentated(void)
{
    for (uint32_t i = 0; i < (1 << 16); ++i)
    {
        struct tcp_reassembly_htable_element* elt = tcp_htable[i];
        while (elt != NULL)
        {
            struct tcp_reassembly* seq = elt->buffers;
            struct tcp_reassembly_htable_element* elt_next;
            while (seq != NULL)
            {
                struct tcp_reassembly* next = seq->next;
                free(seq->buffer);
                free(seq);
                seq = next;
            }
            elt_next = elt->next;
            free(elt);
            elt = elt_next;
        }
        tcp_htable[i] = NULL;
    }

    for (uint32_t i = 0; i < (1 << 16); ++i)
    {
        struct sctp_reassembly_htable_element* elt = sctp_htable[i];
        while (elt != NULL)
        {
            struct sctp_reassembly* seq = elt->buffers;
            struct sctp_reassembly_htable_element* elt_next;
            while (seq != NULL)
            {
                struct sctp_reassembly* next = seq->next;
                free(seq->buffer);
                free(seq);
                seq = next;
            }
            elt_next = elt->next;
            free(elt);
            elt = elt_next;
        }
        sctp_htable[i] = NULL;
    }

    for (uint32_t i = 0; i < (1 << 16); ++i)
    {
        struct ipv4_reassembly* cur = ipv4_fragmented[i];
        while (cur != NULL)
        {
            struct ipv4_reassembly* cur_sv = cur;
            cur_sv = cur->next;
            free(cur->buffer);
            free(cur);
            cur = cur_sv;
        }
        ipv4_fragmented[i] = NULL;
    }
}

int main(int argc, char* argv[])
{
    int return_code = EXIT_FAILURE;

    struct pcap_info* pcap = NULL;
    pcap_t* capture = NULL;
    long verbosity_level = 3;

    sigset_t signals_end;
    sigset_t block_sigusr1;
    int received_signal;

    pthread_t packet;
    pthread_t input = 0;

    pthread_mutex_t console;

    struct termios old_terminal_mode;
    struct termios terminal_mode;

    int pcap_setup_return;

    int argument_setup_return;

    struct dash_arguments args = {
        .interface = NULL,
        .input_file = NULL,
        .bpf_filter = NULL,
        .verbosity_level = NULL,
        .max_packet_count = NULL,
        .save_file = NULL,
        .nocolor = false,
        .noprompt = false,
        .display_help = false,
        .display_version = false,
        .display_hostnames = false
    };

    struct passed_message capture_args = {
        .max_packet_count = -1,
        .nocolor = false,
        .noprompt = false,
        .verbosity_level = 3,
        .input_buffer = {0},
        .can_use_bpf = true,
        .min_read = 0,
        .read_packet_count = 0,
        .capture = NULL,
        .save = NULL,
        .console = &console,
        .cli = &args,
        .display_hostnames = false
    };

    char errbuf[PCAP_ERRBUF_SIZE];

    sigemptyset(&signals_end);
    sigaddset(&signals_end, SIGINT);
    sigaddset(&signals_end, SIGTERM);
    sigprocmask(SIG_BLOCK, &signals_end, NULL);

    tcgetattr(STDIN_FILENO, &old_terminal_mode);
    terminal_mode = old_terminal_mode;
    terminal_mode.c_lflag &= (unsigned int) ~(ECHO | ICANON);

    /**
     * Init mutex for console printing
     */
    if (pthread_mutex_init(capture_args.console, NULL))
    {
        fprintf(stderr, "[ERR] Can't initialize mutex\n");
        goto END;
    }

    pthread_mutex_lock(capture_args.console);

    srand((unsigned int) time(NULL));

    /**
     * Read and parse command-line arguments
     */
    argument_setup_return = setup_arguments(&argc, argv, &args);
    if (argument_setup_return < 0)
    {
        goto END;
    }
    if (argument_setup_return > 0)
    {
        return_code = EXIT_SUCCESS;
        goto END;
    }

    if (!args.list_interfaces)
    {
        print_logo();
        set_title("%s", OB_NAME " - starting up");
    }

    if (args.verbosity_level)
    {
        char* end_ptr;
        verbosity_level = strtol(args.verbosity_level, &end_ptr, 10);
        if (args.verbosity_level == end_ptr || errno == ERANGE)
        {
            fprintf(stderr, "[ERR] Invalid verbosity level\n");
            goto END;
        }
    }

    if (args.max_packet_count)
    {
        char* end_ptr;
        capture_args.max_packet_count = strtoll(args.max_packet_count, &end_ptr, 10);
        if (args.max_packet_count == end_ptr || errno == ERANGE)
        {
            fprintf(stderr, "[ERR] Invalid max packet count\n");
            goto END;
        }

        if (capture_args.max_packet_count <= 0)
        {
            fprintf(stderr, "[ERR] Max packet count must be strictly positive\n");
            goto END;
        }
    }

    if (verbosity_level <= 0 || verbosity_level > 3)
    {
        fprintf(stderr, "[ERR] Invalid verbosity level %ld, allowed range is [1-3]\n", verbosity_level);
        goto END;
    }

    if (args.input_file != NULL && args.save_file != NULL)
    {
        fprintf(stderr, "[ERR] Saving to a file requires opening a live capture\n");
        goto END;
    }

    if (pcap_init(PCAP_CHAR_ENC_LOCAL, errbuf))
    {
        fprintf(stderr, "[ERR] pcap_init(): %s\n", errbuf);
        goto END;
    }

    /**
     * Set up all capture arguments
     */
    pcap_setup_return = pcap_setup(&args, &capture, &capture_args);

    if (pcap_setup_return < 0)
    {
        fprintf(stderr, "[ERR] pcap_setup() failed\n");
        goto END;
    }
    if (pcap_setup_return > 1)
    {
        return_code = EXIT_SUCCESS;
        goto END;
    }

    capture_args.capture = capture;
    capture_args.verbosity_level = (uint8_t) verbosity_level;
    capture_args.nocolor = args.nocolor;
    capture_args.noprompt = args.noprompt;
    capture_args.min_read = pcap_setup_return;
    capture_args.display_hostnames = args.display_hostnames;

    /**
     * Set terminal raw mode
     */
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &terminal_mode);

    pthread_create(&packet, NULL, loop_read_packets, (void*) &capture_args);

    if (!args.noprompt)
    {
        pthread_create(&input, NULL, loop_read_user_input, (void*) &capture_args);
    }
    else
    {
        pthread_mutex_unlock(capture_args.console);
    }

    /**
     * Block SIGUSR1 in the main thread
     */
    sigemptyset(&block_sigusr1);
    sigaddset(&block_sigusr1, SIGUSR1);

    pthread_sigmask(SIG_BLOCK, &block_sigusr1, NULL);

    /**
     * Wait for Ctrl+C
     */
    sigwait(&signals_end, &received_signal);

    set_title(OB_NAME " - exiting");

    /**
     * If we receive a signal after that, the user force-exited and we should not do any work
     */
    sigprocmask(SIG_UNBLOCK, &signals_end, NULL);

    pthread_kill(packet, SIGUSR1);

    if (!args.noprompt)
    {
        pthread_kill(input, SIGUSR1);
        pthread_join(input, NULL);
    }
    pthread_join(packet, NULL);

    return_code = EXIT_SUCCESS;
END:
    /**
     * Magic sequence to reset terminal encoding
     * https://www.in-ulm.de/~mascheck/various/alternate_charset/#solution
     */
    if (!capture_args.nocolor && !args.list_interfaces)
    {
        printf("\033[0m\033(B\033)0\017\033[?5l\0337\033[0;0r\0338");
    }
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &old_terminal_mode);

    free_fragmentated();

    if (capture != NULL)
    {
        pcap_close(capture);
    }
    if (capture_args.save != NULL)
    {
        pcap_dump_flush(capture_args.save);
        pcap_dump_close(capture_args.save);
    }
    if (capture_args.console != NULL)
    {
        pthread_mutex_unlock(capture_args.console);
        pthread_mutex_destroy(capture_args.console);
    }
    free(pcap);
    free(args.interface);
    free(args.input_file);
    free(args.bpf_filter);
    free(args.verbosity_level);
    free(args.max_packet_count);
    free(args.save_file);

    return return_code;
}
