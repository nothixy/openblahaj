#include <dlfcn.h>
#include <stdio.h>
#include <nspr/prio.h>

#include "hooks/printbuf.h"

PRInt32 PR_Write(PRFileDesc *fd, const void *buf, PRInt32 amount)
{
    typeof(&PR_Write) real_PR_Write = dlsym(RTLD_NEXT, "PR_Write");
    printf("LOHE\n");
    int rc = real_PR_Write(fd, buf, amount);
    // printbuf(buf, amount, 443, 443, true);
    return rc;
}

PRInt32 PR_Read(PRFileDesc *fd, void *buf, PRInt32 amount)
{
    typeof(&PR_Read) real_PR_Read = dlsym(RTLD_NEXT, "PR_Read");
    printf("LOEH\n");
    int rc = real_PR_Read(fd, buf, amount);
    printbuf(buf, amount, 443, 443, true);
    return rc;
}
