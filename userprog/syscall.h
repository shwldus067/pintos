#include "userprog/process.h"
#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

void syscall_init (void);
void halt(void);
void exit(int);
pid_t exec(const char*);
int write(int, const void *, unsigned);
int read (int, void *, unsigned);
int wait(pid_t);
int fibonacci(int);
int sum_of_four_int(int,int,int,int);
#endif /* userprog/syscall.h */
