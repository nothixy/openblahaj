#ifndef OB_TERMINAL_H
#define OB_TERMINAL_H

#include <time.h>

void set_title(const char* fmt, ...);
void erase_prompt(void);
void prompt(const char* buffer);
void display_error(int error);
void* loop_read_user_input(void* args);
void print_logo(void);

#endif
