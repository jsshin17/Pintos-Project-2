#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#include "filesys/off_t.h"
#include "userprog/process.h"
void syscall_init (void);
void exit(int);

#endif /* userprog/syscall.h */
