#include "userprog/syscall.h"
#include <debug.h>
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/synch.h"
#include "filesys/off_t.h"
/*#include "filesys/file.c"*/
#include "devices/shutdown.h"
#include "filesys/inode.h"
#include "filesys/directory.h"
#include "devices/input.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/init.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/vaddr.h"
#include "userprog/process.h"
#include "lib/kernel/list.h"

typedef int pid_t;
static struct lock file_lock;
static void syscall_handler (struct intr_frame *);
void halt(void);
void exit(int);
pid_t exec(const char* cmd_line);
int wait(pid_t pid);
bool create(char* file, unsigned initial_size);
bool remove(char* file);
int open(char* file);
int filesize(int fd);
int read(int fd, void* buffer, unsigned size);
int write(int fd, void* buffer, unsigned size);
void seek(int fd, unsigned position);
unsigned tell(int fd);
void close(int fd);
void check_address(void* addr);


struct file{
	struct inode* inode;
	off_t pos;
	bool deny_write;
};

static int get_byte (const uint8_t* uaddr)
{
  if (!is_user_vaddr (uaddr))
    return -1;
  int result;
  asm ("movl $1f, %0; movzbl %1, %0; 1:"
       : "=&a" (result) : "m" (*uaddr));
  return result;
}

/* Reads a word at user virtual address ADDR.
   Returns the word value if successful, calls exit system
   call if not. */
static uint32_t
get_word (const uint32_t *uaddr)
{
  uint32_t res;
  int byte;
  int i;
  for (i = 0; i < 4; i++)
    {
      byte = get_byte ((uint8_t *) uaddr + i);
      if (byte == -1)
        {
          exit (-1);
          NOT_REACHED ();
        }
      *((uint8_t *) &res + i) = (uint8_t) byte;
    }
  return res;
}
void
syscall_init (void) 
{
  lock_init(&file_lock);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f) 
{
  uint32_t *esp = f-> esp;
  switch(*(uint32_t*)(f->esp)){
  case SYS_HALT:
	halt();
	break;
  case SYS_EXIT:
	check_address(esp + 32);
	exit((int)get_word(esp + 1));
	break;
  case SYS_EXEC:
	check_address(esp + 32);
	f->eax = exec((const char*)get_word(esp + 1));
	break;
  case SYS_WAIT:
	check_address(esp + 32);
	f->eax = wait((pid_t) get_word(esp + 1));
	break;
  case SYS_CREATE:
	check_address(esp + 32);
	f->eax = create((char*)get_word(esp + 1),(unsigned)get_word(esp + 2));
	break;
  case SYS_REMOVE:
	check_address(esp + 32);
	f->eax = remove(( char*)get_word(esp+1));
	break;
  case SYS_OPEN:
	check_address(esp+ 32);
	f->eax = open((char*)get_word(esp+1));
	break;
  case SYS_FILESIZE:
	check_address(esp + 32);
	f->eax = filesize((int)get_word(esp+1));
	break;
  case SYS_READ:
	check_address(esp + 32);
	f->eax = read((int)get_word(esp+1), (void*)get_word(esp+2),(unsigned)get_word(esp+3));
	break;
  case SYS_WRITE:
	check_address(esp + 32);
	f->eax = write((int)get_word(esp+1),(void*)get_word(esp+2),(unsigned)get_word(esp+3));
	break;
  case SYS_SEEK:
	check_address(esp + 32);
	seek((int)get_word(esp+1),(unsigned)get_word(esp+2));
	break;
  case SYS_TELL:
	check_address(esp + 32);
  case SYS_CLOSE:
	check_address(esp + 32);
	close((int)get_word(esp+1));
	break;
  }
  printf ("system call!\n");
  thread_exit ();
}

void check_address(void *addr)
{
  if (!is_user_vaddr(addr))
  {
	exit(-1);
  }

}

void halt(void)
{
	shutdown_power_off();
}

void exit(int status)
{

	struct  thread *cur = thread_current();
	int i;
	printf ("%s:exit(%d)\n",cur->name, status);
	//struct process_control_block* pcb = thread_current()->pcb;
	//if(pcb!= NULL){
	//	pcb->exitcode = status;
	//}
	
	cur->c_exit_status = status;
	struct thread* current_thread = thread_current();
	for (i = 3;i < 128; i++){
		if(current_thread->f_d[i] != NULL){
			close(i);
		}
	}
	struct thread* temporary_t = NULL;
	struct list_elem* temporary_e = NULL;
	for (temporary_e = list_begin(&thread_current()->c_thread); temporary_e != list_end(&thread_current() -> c_thread); temporary_e = list_next(temporary_e)){
		temporary_t = list_entry(temporary_e, struct thread, c_thread_elem);
		process_wait(temporary_t->tid);		
		thread_exit();
	}
}

pid_t exec(const char* cmd_lines)
{
	struct file* file = NULL;
	int idx = 0;
	char real_file_name[128];
	while(cmd_lines[idx]!=' '&&cmd_lines[idx]!='\0')
	{
		real_file_name[idx] = cmd_lines[idx];
		idx++;
	}
	real_file_name[idx]='\0';
	file = filesys_open(real_file_name);
	if(file==NULL)
		return -1;
	tid_t result = process_execute(cmd_lines);
	return (pid_t) result;
}

int wait(pid_t pid)
{
	return process_wait((tid_t)pid);
}

bool create(char *file, unsigned initial_size)
{
	if(file == NULL)
		exit(-1);
	check_address(file);
	bool result = filesys_create(file, initial_size);
	return result;
}

bool remove(char *file)
{
	if(file == NULL) 
		exit(-1);
	check_address(file);
	bool result = filesys_remove(file);
	return result;
}
int open(char* file){
	if(file == NULL) 
		exit(-1);
	check_address(file);
	lock_acquire(&file_lock);
	int i;
	int result=-1;
	struct file *opening_file = filesys_open(file);
	if(opening_file ==NULL)
	{
		result = -1;
	}
	else{
		for(i=3; i<120;i++){
			if((thread_current() ->f_d[i] ==NULL) && (strcmp(thread_name(), file) ==0)){
				file_deny_write(opening_file);
			}
			if(thread_current() ->f_d[i] ==NULL){
				thread_current()->f_d[i] =opening_file;
				result=i;
				break;
			}
		}
	}	
	lock_release(&file_lock);
	return result;
}
int filesize(int fd){
	if(thread_current()->f_d[fd]==NULL){
		exit(-1);
	}
	return (int)file_length(thread_current()-> f_d[fd]);
}

int read(int fd, void* buffer, unsigned size){
	int read_size=-1;
	check_address(buffer);
	lock_acquire(&file_lock);
	if(fd ==0){
		for(read_size=0;read_size<size;read_size++){
			if(input_getc() == '\0')
				break;
		}
	}
	
	else if(fd>2){
		struct thread* cur_thread = thread_current();
		if(thread_current() ->f_d[fd] ==NULL){
			lock_release(&file_lock);
			exit(-1);
		}
		read_size = file_read(cur_thread->f_d[fd],buffer,size);
	}
	lock_release(&file_lock);
	return read_size;
}

int write(int fd, void* buffer, unsigned size){
	int write_size=-1;
	check_address(buffer);
	lock_acquire(&file_lock);
	if(fd == 1){
		putbuf(buffer, size);
		write_size = size;
	}
	else if(fd > 2){
		if(thread_current()->f_d[fd] == NULL){
	 		lock_release(&file_lock);
			exit(-1);
		}
		struct file *cur_file = thread_current()->f_d[fd];
		if(cur_file->deny_write){
			file_deny_write(cur_file);
		}
		write_size = file_write(cur_file, buffer, size);
	}
	lock_release(&file_lock);
	return write_size;
}

void seek(int fd, unsigned position){
	if(thread_current()->f_d[fd]==NULL){
		exit(-1);
	}
	file_seek(thread_current() -> f_d[fd], position);
}

unsigned tell(int fd){
	if(thread_current()->f_d[fd]=NULL){
		exit(-1);
	}
	return (unsigned) file_tell(thread_current()->f_d[fd]);
}

void close(int fd){
	struct thread* cur_thread = thread_current();
	struct file* file = cur_thread->f_d[fd];
	if(cur_thread->f_d[fd] ==NULL){
		exit(-1);
	}
	file =NULL;
	file_close(file);
}


