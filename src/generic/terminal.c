#include <stdio.h>
#include <stddef.h>
#include <signal.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "generic/thread.h"
#include "generic/protocol.h"
#include "generic/terminal.h"

static const char bytes[] = " \
                                  :                          \n\
                                +++                          \n\
                              =+++=                          \n\
                             =***++                      ++= \n\
      <0><                  +=+**=                     =+++  \n\
                           +***+*+                    +*+=   \n\
                         =+*#**+#=                   +*+*    \n\
           -=--==--===-====-=+==+--         **     ++*++     \n\
     -=*====-====-=+===+==+++===+==--**-+======--=+***++=    \n\
  =+=++*++*-+=*++=+=++==+++=+*+*++++===-+=*#**+=*+==+#**++   \n\
 -+*=++*+++++++*+++*****+++=+*+++++++*=++=++*++====   ****+  \n\
  +++%#+*+**#*#+#++*+**+**+**+++++*+=++=*+#==+===        .+  \n\
   +++**+**+%*#+**+*****++*+*+*+*++++==+++-==                \n\
       ....:*+***++*#+*#++#*++*+=++++====                    \n\
       .. .........:.-+**%*+++*-=                            \n\
            .......::..::*##**+++               <0><         \n\
                              *++***                         \n\
                                  **=+                       \n\
                                                             ";

static const size_t blahaj_length = sizeof(bytes);

void print_logo(void)
{
    for (size_t i = 0; i < blahaj_length; ++i)
    {
        if (bytes[i] == '>' || bytes[i] == '<' || bytes[i] == '0')
        {
            printf("\033[31m");
        }
        else if ((bytes[i] == '.' ||  bytes[i] == ':') && i > 750)
        {
            printf("\033[0m");
        }
        else
        {
            printf("\033[34m");
        }

        printf("%c", bytes[i]);

        printf("\033[0m");
    }
    printf("\n");
}

inline void prompt(const char* buffer)
{
    printf("\ropenBLAHAJ > %s", buffer);
    fflush(stdout);
}

inline void erase_prompt(void)
{
    printf("\33[2K\r");
    fflush(stdout);
}

void set_title(const char* fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    printf("\033]30;");
    vprintf(fmt, args);
    printf("\a");
    fflush(stdout);
    va_end(args);
}

void display_error(int error)
{
    const char* err_str;
    if ((unsigned long) error >= sizeof(OB_ERROR_STR) / sizeof(char*))
    {
        err_str = "Unknown error";
    }
    else
    {
        err_str = OB_ERROR_STR[error];
    }
    printf("\033[1m[%s]\033[22m", err_str);
}

static bool handle_command(const char* buffer, struct passed_message* capture_args)
{
    if (!strncmp("/setfilter", buffer, 10))
    {
        struct bpf_program fp;
        if (!capture_args->can_use_bpf)
        {
            return true;
        }
        if (pcap_compile(capture_args->capture, &fp, &buffer[11], 0, capture_args->netmask))
        {
            fprintf(stderr, "[ERR] pcap_compile(): %s\n", pcap_geterr(capture_args->capture));
            return true;
        }

        if (pcap_setfilter(capture_args->capture, &fp))
        {
            fprintf(stderr, "[ERR] pcap_setfilter(): %s\n", pcap_geterr(capture_args->capture));
            return true;
        }
        pcap_freecode(&fp);
        return true;
    }
    else if (!strncmp("/countdown", buffer, 10))
    {
        capture_args->max_packet_count = atoi(&buffer[11]) + capture_args->read_packet_count;
        return true;
    }
    else if (!strncmp("/quit", buffer, 5))
    {
        return false;
    }
    else if (!strncmp("/help", buffer, 5))
    {
        printf("/setfilter `filter`\n");
        printf("/countdown `n`\n");
        printf("/help\n");
        printf("/quit\n");
        return true;
    }

    return true;
}

/**
 * @brief Constantly read user input
 * @param args Void pointer required by pthread_create(), unused
 * @return NULL
 */
void* loop_read_user_input(void* args)
{
    struct passed_message* capture_args = args;
    int index = 0;
    bool no_quit = true;

    prompt(capture_args->input_buffer);
    pthread_mutex_unlock(capture_args->console);

    while (read(STDIN_FILENO, &(capture_args->input_buffer)[index], 1) == 1)
    {
        pthread_mutex_lock(capture_args->console);
        if (capture_args->input_buffer[index] == 0x7F)
        {
            if (index == 0)
            {
                continue;
            }
            capture_args->input_buffer[index] = '\0';
            capture_args->input_buffer[index - 1] = '\0';
            index -= 1;
            erase_prompt();
        }
        else if (capture_args->input_buffer[index] == '\n')
        {
            capture_args->input_buffer[index] = '\0';
            index = 0;
            erase_prompt();
            no_quit = handle_command(capture_args->input_buffer, capture_args);
            if (!no_quit)
            {
                break;
            }
            memset(capture_args->input_buffer, 0, _POSIX_MAX_CANON);
        }
        else
        {
            if (index < _POSIX_MAX_CANON - 1)
            {
                index += 1;
            }
        }
        prompt(capture_args->input_buffer);
        pthread_mutex_unlock(capture_args->console);
    }

    if (!no_quit)
    {
        kill(getpid(), SIGINT);
    }

    return NULL;
}
