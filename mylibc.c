#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdarg.h>

#define __USE_LARGEFILE64
#include <dirent.h>
#include <proc/readproc.h>

#define __USE_GNU
#include <dlfcn.h>

#define LOG_FILE "/secretlog"
/* Buffer for log string */
#define LOG_LENGTH 512
static char logstring[LOG_LENGTH];

/* Exec args and envs */
#define ARG_LENGTH 32
#define ENV_LENGTH 128
static char* exec_args[ARG_LENGTH];
static char* exec_envs[ENV_LENGTH];


/* Pointers to save original system calls */
static struct dirent* (*orig_readdir)(DIR *dirp);
static struct dirent64* (*orig_readdir64)(DIR *dirp);
static int (*orig_open)(const char *pathname, int flags, mode_t mode);
static int (*orig_open64)(const char *pathname, int flags, mode_t mode);
static int (*orig_openat)(int dirfd, const char *pathname, int flags, mode_t mode);
static FILE* (*orig_fopen)(const char* path, const char* mode);
static FILE* (*orig_freopen)(const char *path, const char *mode, FILE *stream);
static int (*orig_unlink)(const char* pathname);
static int (*orig_unlinkat)(int dirfd, const char *pathname, int flags);
static proc_t* (*orig_readproc)(PROCTAB *restrict const PT, proc_t *restrict p);
static int (*orig_connect)(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
static int (*orig_socket)(int domain, int type, int protocol);
static int (*orig_execl)(const char *path, const char *arg, ...);
static int (*orig_execlp)(const char *file, const char *arg, ...);
static int (*orig_execle)(const char *path, const char *arg,...);
static int (*orig_execv)(const char *path, char *const argv[]);
static int (*orig_execvp)(const char *file, char *const argv[]);
static int (*orig_execve)(const char *filename, char *const argv[], char *const envp[]);
static int (*orig_snprintf)(char *str, size_t size, const char *format, ...);
	


/* Structure to hold secret files and its flags */
struct sec_file{
	char* filename;
	int flags;
};

/* Flags */
#define SF_INVISIBLE 1
#define SF_UNREMOVABLE 2
#define SF_ONLYAPPEND 4

/* Definitions from fcntl.h */
#define O_WRONLY             01
#define O_TRUNC           01000
#define O_APPEND          02000

struct sec_file files[] = {
	{"auth.log", SF_UNREMOVABLE},
	{".bash_history", SF_INVISIBLE | SF_UNREMOVABLE },
//	{"ld.so.pre", SF_INVISIBLE | SF_UNREMOVABLE}, 
	{"logrotate", SF_INVISIBLE | SF_UNREMOVABLE},
	{"logman.pl", SF_INVISIBLE | SF_UNREMOVABLE | SF_ONLYAPPEND},
	{"log.db", SF_INVISIBLE | SF_UNREMOVABLE},
	{"mylibc.so", SF_INVISIBLE | SF_UNREMOVABLE},
	{"proftpd.log", SF_UNREMOVABLE},
	{"thttpd.log", SF_UNREMOVABLE},
//	{"superlog", SF_INVISIBLE},
	{"mysql.log.", SF_INVISIBLE}
};

#define SOCK_COUNT 16384
int socket_info[SOCK_COUNT];

/* addresses to which computer can connect */
const char* my_addresses[] = {
	"192.168.152.2",
	"192.168.152.135"
	"87.250.250.3",
	"87.250.251.3",
	"93.158.134.3",
	"213.180.204.3",
	"77.88.21.3",
	"99.111.109.47"
};

/* appends the string s to the LOG_FILE */
void mylog(const char* s){
	FILE* log = NULL;
	orig_fopen = dlsym(RTLD_NEXT, "fopen");
	log = orig_fopen(LOG_FILE, "a+");
	if(log == NULL) {
		perror("file can't be open");
		return;
	}	
	fseek(log, 0, SEEK_END);
	time_t cur_time = time(0);
	fprintf(log, "%s: %s\n", ctime(&cur_time), s);
	fclose(log);
}

int myaddr(const char* addr){
	//ridof
	return 1;
	int i, count = (sizeof my_addresses) / (sizeof (const char*));
	for(i = 0; i < count; i++){
		if(!strcmp(my_addresses[i], addr)) return 1;
	} 
	return 0;
}

/* Check whether the given file satisfies the fileter */
int filter_file(const char* filename, int flag){
	int count = (sizeof files) / (sizeof (struct sec_file)); 
	int i;
	for(i = 0; i < count; i++){
		if(strstr(filename, files[i].filename) != NULL
		   && ((files[i].flags & flag) != 0)){
			return 1;
		}
	}
	return 0;
}

/* Is the given file invisible */
int is_invisible(const char* filename){
	return filter_file(filename, SF_INVISIBLE);
}

/* Is the given file unremovable */
int is_unremovable(const char* filename){
	return filter_file(filename, SF_UNREMOVABLE);
}

/* Is the given file can be open only for append */
int is_onlyappend(const char* filename){
	return filter_file(filename, SF_ONLYAPPEND);
}

void logdentry(struct dirent* dentry){
	char* cur_dir = (const char*)get_current_dir_name();
	snprintf(logstring, LOG_LENGTH, "readdir; name: %s/%s;\n", cur_dir, dentry->d_name);
	mylog(logstring);
}

void logdentry64(struct dirent64* dentry){
	char* cur_dir = (const char*)get_current_dir_name();
	snprintf(logstring, LOG_LENGTH, "readdir64; name: %s/%s;\n", cur_dir, dentry->d_name);
	mylog(logstring);
}

int absolute_path(const char* path){
	return path != NULL && path[0] == '/';
}

void logopen(const char* filename){
	char* cur_dir = (const char*)get_current_dir_name();
	char* slash = "/";
	if(absolute_path(filename)){
		strcpy(cur_dir, "");
		slash = "";
	}
	snprintf(logstring, LOG_LENGTH, "opening file: %s%s%s\n", cur_dir, slash, filename);
	mylog(logstring);
	free(cur_dir);
}

void logunlink(const char* filename){
	const char* cur_dir = (const char*)get_current_dir_name();
	char* slash = "/";
	if(absolute_path(filename)){
		strcpy(cur_dir, "");
		slash = "";
	}
	snprintf(logstring, LOG_LENGTH, "removing file: %s%s%s\n", cur_dir, slash, filename);
	mylog(logstring);
	free(cur_dir);
}

struct dirent *readdir(DIR *dirp){
	struct dirent* dentry = NULL;
	orig_readdir = dlsym(RTLD_NEXT, "readdir");
	dentry = (struct dirent*)orig_readdir(dirp);
	while(dentry != NULL && is_invisible(dentry->d_name)){
		dentry = (struct dirent*)orig_readdir(dirp);
		logdentry(dentry);
	}
	if(dentry != NULL)
		logdentry(dentry);
	
	return dentry;
}

struct dirent64 *readdir64(DIR *dirp){
	struct dirent64* dentry = NULL;
	orig_readdir64 = dlsym(RTLD_NEXT, "readdir64");
	dentry = (struct dirent64*)orig_readdir64(dirp);
	while(dentry != NULL && is_invisible(dentry->d_name)){
		dentry = (struct dirent64*)orig_readdir64(dirp);
		logdentry64(dentry);
	}
	if(dentry != NULL)
		logdentry64(dentry);
	
	return dentry;
}

int open(const char *pathname, int flags, mode_t mode){
	int ret = -1;
	if(is_onlyappend(pathname) && (flags & O_TRUNC) != 0)
		return ret;

	orig_open = dlsym(RTLD_NEXT, "open");
	ret = orig_open(pathname, flags, mode);
	logopen(pathname);

	return ret;
}

FILE* fopen(const char* pathname, const char* mode){
	FILE *ret = NULL;
	if(is_onlyappend(pathname) && strchr(mode, 'w') != NULL)
		return ret;

	orig_fopen = dlsym(RTLD_NEXT, "fopen");
	ret = orig_fopen(pathname, mode);
	logopen(pathname);
	return ret;
}

int open64(const char *pathname, int flags, mode_t mode){
	int ret = -1;
	if(is_onlyappend(pathname) && (flags & O_TRUNC) != 0)
		return ret;

	orig_open64 = dlsym(RTLD_NEXT, "open64");		
	ret = orig_open64(pathname, flags, mode);
	logopen(pathname);
	return ret;
}


proc_t* readproc(PROCTAB *restrict const PT, proc_t *restrict p){
	proc_t* ret = NULL;
	void *libproc = dlopen("libproc-3.2.8.so", RTLD_LAZY);	
	if(libproc != NULL && (orig_readproc = dlsym(libproc, "readproc"))){
		ret = orig_readproc(PT, p);
		if(strstr(p->cmd, "zxzz") != NULL)
			ret = NULL; 
	}
	dlclose(libproc);
	return ret;
}

int unlink(const char* pathname){
	int ret = -1;
	orig_unlink = dlsym(RTLD_NEXT, "unlink");
	if(!is_unremovable(pathname)){
		ret = orig_unlink(pathname);
	}
	else
		errno = EPERM;	
	logunlink(pathname);
	return ret;
}


int unlinkat(int dirfd, const char *pathname, int flags){
	int ret = -1;
	orig_unlinkat = dlsym(RTLD_NEXT, "unlinkat");
	if(!is_unremovable(pathname)){
		ret = orig_unlinkat(dirfd, pathname, flags);
	}
	else
		errno = EPERM;	
	logunlink(pathname);	
	return ret;
}

int openat(int dirfd, const char *pathname, int flags, mode_t mode){
	int ret = -1;
	orig_openat = dlsym(RTLD_NEXT, "openat");
	if(is_onlyappend(pathname) && (flags & O_TRUNC) != 0)
		return ret;

	return orig_openat(dirfd, pathname, flags, mode);
}


int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen){
	int ret = -1;
	struct sockaddr_in* sa = (struct sockaddr_in*) addr;
	const char* destaddr = (const char*)inet_ntoa(sa->sin_addr);
	if(sockfd < SOCK_COUNT && socket_info[sockfd] == 2 && !myaddr(destaddr)){
		printf("Not allowed to connect to %s\n", destaddr);
		return ret;
	}	
	snprintf(logstring, LOG_LENGTH, "connect to %s:%d\n", destaddr, htons(sa->sin_port));
	mylog(logstring);
	orig_connect = dlsym(RTLD_NEXT, "connect");
	ret = orig_connect(sockfd, addr, addrlen);
	return ret;
}


int socket(int domain, int type, int protocol){
	orig_socket = dlsym(RTLD_NEXT, "socket");
	int ret = orig_socket(domain, type, protocol);
	if(ret != -1){
		socket_info[(unsigned)ret] = domain;
	}
	return ret;
}

FILE *freopen(const char *path, const char *mode, FILE *stream){
	FILE *ret = NULL;
	orig_freopen = dlsym(RTLD_NEXT, "freopen");
	ret = orig_freopen(path, mode, stream);
	logopen(path);
	return ret;
}

void logexec(const char* filename){
	orig_snprintf = dlsym(RTLD_NEXT, "snprintf");
	orig_snprintf(logstring, LOG_LENGTH, "execve %s", filename);
	mylog(logstring);
}
	
int execve(const char *filename, char *const argv[], char *const envp[]){
	orig_execve = dlsym(RTLD_NEXT, "execve");
	int ret = orig_execve(filename, argv, envp);
	logexec(filename);
	return ret;
}

int execvp(const char *file, char *const argv[]){
	orig_execvp = dlsym(RTLD_NEXT, "execvp");
	int ret = orig_execvp(file, argv);
	logexec(file);
	return ret;
}

int execl(const char *path, const char *arg, ...){
	orig_execl = dlsym(RTLD_NEXT, "execl");
	int i = 0; char *argp = NULL;
	va_list vlist;
	va_start(vlist, arg);
	while((argp = va_arg(vlist, char*) != NULL)){
		exec_args[i++] = argp;
	}
	exec_args[i] = NULL;
	int ret = execvp(path, exec_args);
//	int ret = execlp(path, arg);
//	int ret = orig_execl(path, arg);
//	logexec(path);
	return ret;
}	

int execlp(const char *file, const char *arg, ...){
	orig_execlp = dlsym(RTLD_NEXT, "execlp");
	int ret = orig_execlp(file, arg);
	logexec(file);
	return ret;
}

int execle(const char *path, const char *arg,...){
	orig_execle = dlsym(RTLD_NEXT, "execle");
	int ret = orig_execle(path, arg);
	logexec(path);
	return ret;
}

int execv(const char *path, char *const argv[]){
	orig_execv = dlsym(RTLD_NEXT, "execv");
	int ret = orig_execv(path, argv);
	logexec(path);
	return ret;
}
