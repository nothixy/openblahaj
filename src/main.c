#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>

#include "openblahaj.h"

const uint64_t OB_MAGIC = 0x4C4F434F544F5250;

bool check_is_openblahaj();

int main(int argc, char* argv[])
{
    return ob_main(argc, argv);
}
