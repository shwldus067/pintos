#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "userprog/pagedir.h"
#include "threads/vaddr.h"
#include "devices/shutdown.h"
#include "userprog/process.h"
#include "threads/thread.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "threads/malloc.h"
#include "threads/synch.h"

#define CHECKMARK false
 
static thread_func start_process NO_RETURN;
static bool load (const char *cmdline, void (**eip) (void), void **esp);

//project_2
struct semaphore mutex, writesema;
int readcount;

static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
	//project_2
	sema_init(&mutex,1);
	sema_init(&writesema,1);
	readcount=0;
	
	intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

bool is_valid_ptr (const void *addr){
		check("is valid func", CHECKMARK);
       if(addr && is_user_vaddr(addr)&&pagedir_get_page(thread_current()->pagedir, addr)){
			return true;
       }
        else{
           return false;
       }
}

void halt(void){
	check("halt", CHECKMARK);
	shutdown_power_off();
}

void exit(int status){
	check("exit",CHECKMARK);
	struct thread *current_thread=thread_current();
	struct file_list* cur=current_thread->file_elem;
	struct file_list* next;
	current_thread->exit_status=status;
	printf("%s: exit(%d)\n",current_thread->name, current_thread->exit_status);
	while(cur!=NULL){
		next=cur->ptr;
		file_close(cur->filedes);
		free(cur);
		cur=next;
	}
	thread_exit();
}

pid_t exec(const char *cmd_line){
	check("exec",CHECKMARK);
	struct thread *t=thread_current();
	pid_t tid= process_execute(cmd_line);
	return tid;
}

int wait(pid_t pid){
	check("wait",CHECKMARK);
	return process_wait(pid);
}


int read(int fd, void *buffer, unsigned size){
	check("read",CHECKMARK);	
	unsigned i;
	//project_2
	int result;
	struct thread* cur=thread_current();
	struct file_list* iterator=cur->file_elem;
	if(is_valid_ptr(buffer)&&is_valid_ptr(buffer+size)){
		if(fd==0||fd>=3){
			sema_down(&mutex);
			readcount++;
			if(readcount==1){
				sema_down(&writesema);
			}
			sema_up(&mutex);
	
			if(fd==0){
				for(i=0;i<size;i++){
					((char*)buffer)[i]=input_getc();
				}
				result=size;
			}
			else if(fd>=3){
				while(iterator!=NULL){
					if(iterator->desnum==fd){
						break;
					}		
					iterator=iterator->ptr;
				}
				if(iterator==NULL){
					exit(-1);
					result=-1;	
				}
				else{
					result=file_read(iterator->filedes,buffer,size);
				}
			}
	
			sema_down(&mutex);
			readcount--;
			if(readcount==0){
				sema_up(&writesema);
			}
			sema_up(&mutex);
		}
		else{
			result= -1;
		}
	}
	else{
		exit(-1);
		result=-1;
	}
	return result;
}

int write(int fd, const void *buffer, unsigned size){
	check("write",CHECKMARK);
	
	//project_2
	int result;
	struct thread* cur=thread_current();
	struct file_list* iterator=cur->file_elem;
	if(is_valid_ptr(buffer)&&is_valid_ptr(buffer+size)){	
		if(fd==1||fd>=3){
			sema_down(&writesema);
	
			if(fd==1){
				putbuf(buffer, size);
				result=size;
			}
			else if(fd>=3){
				while(iterator!=NULL){
					if(iterator->desnum==fd){
						break;
					}
					iterator=iterator->ptr;
				}
				if(iterator==NULL){
					exit(-1);
					result=-1;
				}
				else{
					if((iterator->filedes)->deny_write){
						file_deny_write(iterator->filedes);
					}
					result=file_write(iterator->filedes,buffer,size);
				}
			}
		
			sema_up(&writesema);
		}
		else{
			result=-1;
		}
	}
	else{
		exit(-1);
		result=-1;
	}
	return result;
}

int fibonacci(int num){
	check("fibonacci",CHECKMARK);
	if(num<=0){
		return 0;
	}
	else if(num==1||num==2){
		return 1;
	}
	else{
		int f1=1, f2=1;
		int i=0,sum=0;
		for(i=0;i<num-2;i++){
			sum=f1+f2;
			f2=f1;
			f1=sum;
		}
		return sum;
	}
}

int sum_of_four_int(int num1, int num2, int num3, int num4){
	check("sum of four int", CHECKMARK);
	return (num1+num2+num3+num4);
}


//project_2
bool create(const char *file, unsigned initial_size){
	check("create", CHECKMARK);
	if(file==NULL){
		exit(-1);
		return false;
	}
	bool success=filesys_create(file, initial_size);
	return success;
}
bool remove (const char *file){
	check("remove", CHECKMARK);
	if(file==NULL){
		exit(-1);
		return false;
	}
	bool success=filesys_remove(file);
	return success;
}
int open(const char *file){
	check("open", CHECKMARK);
	if(file==NULL){
		exit(-1);
		return -1;
	}
	struct file* openfile;
	struct thread* cur=thread_current();
	struct file_list* newflist;

	
	openfile=filesys_open(file);
	if(openfile==NULL){
		return -1;
	} 
	
	//if file is already open, deny to modify the file
	if(strcmp(cur->name, file)==0){
		file_deny_write(openfile);
	}	
	newflist=(struct file_list*)malloc(sizeof(struct file_list));
	newflist->filedes=openfile;
	newflist->desnum=cur->fd_num;
	cur->fd_num=cur->fd_num+1;
	
	newflist->ptr=cur->file_elem;
	cur->file_elem=newflist;

	return newflist->desnum;	
}
int filesize(int fd){
	check("filesize", CHECKMARK);
	struct thread* cur=thread_current();
	struct file_list* iterator=cur->file_elem;
	while(iterator!=NULL){
		if(iterator->desnum==fd){
			break;
		}
		iterator=iterator->ptr;
	}
	if(iterator==NULL){
		exit(-1);
	}
	return file_length(iterator->filedes);
}
void seek(int fd, unsigned position){
	 check("seek", CHECKMARK);
	struct thread* cur=thread_current();
	struct file_list* iterator=cur->file_elem;
	while(iterator!=NULL){
		if(iterator->desnum==fd){
			break;
		}
		iterator=iterator->ptr;
	}
	if(iterator==NULL)
		exit(-1);
	file_seek(iterator->filedes, position);
}
unsigned tell (int fd){
	 check("tell", CHECKMARK);
	struct thread* cur=thread_current();
	struct file_list* iterator=cur->file_elem;
	while(iterator!=NULL){
		if(iterator->desnum==fd){
			break;
		}
		iterator=iterator->ptr;
	}
	if(iterator==NULL)
		exit(-1);
	return file_tell(iterator->filedes);
}
void close(int fd){
	 check("close", CHECKMARK);
	struct thread* cur=thread_current();
	struct file_list* iterator=cur->file_elem;
	struct file_list* prev=NULL;
	while(iterator!=NULL){
		if(iterator->desnum==fd){
			break;
		}
		prev=iterator;
		iterator=iterator->ptr;
	}
	if(iterator==NULL){
		exit(-1);
	}
	else if(iterator!=NULL){
		if(prev!=NULL){
			prev->ptr=iterator->ptr;
		}
		else{
			cur->file_elem=iterator->ptr;
		}
		file_close(iterator->filedes);
		remove(iterator->filedes);
		free(iterator);
		cur->fd_num=cur->fd_num-1;
	}
}
static void
syscall_handler (struct intr_frame *f UNUSED) 
{
	
  int syscall_number=*(int *)(f->esp);
	switch(syscall_number){
	case SYS_HALT:
		if(is_valid_ptr(f->esp+4)==true){
			halt();
		}
		else{
			exit(-1);
		}
		break;
	
	case SYS_EXIT:
		if(is_valid_ptr(f->esp+4)==true){
			exit(*(int *)(f->esp+4));
		}
		else{
			exit(-1);
		}
		break;
	
	case SYS_EXEC:
		if(is_valid_ptr(f->esp+4)==true){
			f->eax=exec((const char *)*(int *)((f->esp)+4));
		}
		else{
			exit(-1);
		}
		break;
		
	case SYS_WAIT:
		if(is_valid_ptr(f->esp+4)==true){
			f->eax=wait((pid_t)*(int *)((f->esp)+4));
		}
		else {
			exit(-1);
		}
		break;
	
	case SYS_READ:
		if(is_valid_ptr(f->esp+4)==true&&is_valid_ptr(f->esp+8)==true&&is_valid_ptr(f->esp+12)){
			f->eax=read((int)*(int *)(f->esp+4),*(void **)(f->esp+8),(unsigned)*(unsigned *)(f->esp+12));
		}
		else{
			exit(-1);
		}
		break;
	
	case SYS_WRITE:
	if(is_valid_ptr(f->esp+4)==true&&is_valid_ptr(f->esp+8)==true&&is_valid_ptr(f->esp+12)){
			f->eax=write((int)*(int *)(f->esp+4),*(void **)(f->esp+8),(unsigned)*(unsigned *)(f->esp+12));
		}
		else{
			exit(-1);
		}
		break;
	case SYS_SUM:
		if(is_valid_ptr(f->esp+4)==true&&is_valid_ptr(f->esp+8)==true&&is_valid_ptr(f->esp+12)==true&&is_valid_ptr(f->esp+16)==true){
			f->eax=sum_of_four_int((int)*(int *)(f->esp+4),(int)*(int *)(f->esp+8),(int)*(int *)(f->esp+12), (int)*(int *)(f->esp+16));
		}
		else{
			exit(-1);
		}
		break;
	case SYS_FIBONACCI:{
		if(is_valid_ptr(f->esp+4)==true){
			f->eax=fibonacci((int)*(int *)(f->esp+4));
		}
		else{
			exit(-1);
		}
		break;
	}

	//project_2
	case SYS_CREATE:
		if(is_valid_ptr(f->esp+4)==true&&is_valid_ptr(f->esp+8)==true){
			f->eax=create((const char *)*(uint32_t *)(f->esp+4),(unsigned)*(uint32_t *)(f->esp+8));
		}
		else{
			exit(-1);
		}
		break;
	case SYS_REMOVE:
		if(is_valid_ptr(f->esp+4)==true){
			f->eax=remove((const char *)*(uint32_t *)(f->esp+4));
		}
		else{
			exit(-1);
		}
		break;
	case SYS_OPEN:
		if(is_valid_ptr(f->esp+4)==true){
			f->eax=open((const char *)*(uint32_t *)(f->esp+4));
		}
		else{
			exit(-1);
		}
		break;
	case SYS_FILESIZE:
		if(is_valid_ptr(f->esp+4)==true){
			f->eax=filesize((int)*(uint32_t *)(f->esp+4));
		}
		else{
			exit(-1);
		}
		break;
	case SYS_SEEK:
		if(is_valid_ptr(f->esp+4)==true&&is_valid_ptr(f->esp+8)==true){
			seek((int)*(uint32_t *)(f->esp+4),(unsigned)*(uint32_t *)(f->esp+8));
		}
		else{
			exit(-1);
		}
		break;
	case SYS_TELL:
		if(is_valid_ptr(f->esp+4)==true){
			f->eax=tell((int)*(uint32_t *)(f->esp+4));
		}
		else{
			exit(-1);
		}
		break;
	case SYS_CLOSE:
		if(is_valid_ptr(f->esp+4)==true){
			close((int)*(uint32_t *)(f->esp+4));
		}
		else{
			exit(-1);
		}
		break;	
  } 
//	 printf ("system call!\n");
 // thread_exit ();
}
