#ifndef __linux__
#error "This application is Linux-specific."
#endif /* !__linux__ */

#ifndef __i386__
#error "This application requires IA32 platform to run."
#endif /* !__i386__ */
 
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/stat.h>
#include <ctype.h>
#include <termios.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <sched.h>
#include <sys/mman.h>

#include "config.h"
#include "types.h"
#include "ioctls.h"
#include "messages.h"

static struct { _u8* name; _u32 num; } sclist[] = {
#include "sctab-list.h"
};

static _u8 local, sink_syscall, iamroot;
static _s32 tpid, syscall_result;
static _u32 child_umask, check_ret, rpar1, rpar2, rpar3;

#define LAIR_SIZE (16 * 4) /* Must be a multiple of 4 */
static _u32 secret_lair, secret_copy[LAIR_SIZE/4];
static _u8  secret_buried, skip_eip_check;

static struct termios clean_term, cur_term, canoe_term;

#define errorf(x...) fprintf(stderr,x)

#define fatal(x...)  do { \
    errorf("\n[-] FATAL: "); errorf(x); errorf("\n"); clean_exit(1); \
  } while (0)

#define pfatal(x)    do { \
    perror("\n[-] FATAL: " x); clean_exit(1); \
  } while (0)


static void usage(_u8* av0) {
  errorf("\n"
         "Usage: %s ( --local | --remote | --rawsock ) progname [ args... ]\n"
         "       %s --pid process_id\n"
	 "\n"
	 "Trace target specification:\n"
	 "  --local    - privilege elevation exploit / generic command-line tool\n"
	 "  --remote   - remote TCP or UDP network-based exploit / network tool\n"
	 "  --rawsock  - remote exploit requiring raw sockets / any UID 0 tool\n"
	 "  --pid      - prospective victim of an exploit (attach to a process)\n"
	 "\n", av0, av0);
  exit(1);
}		 


static void clean_exit(_s32 code) {
  static struct user_regs_struct r; 

  if (tpid > 0) { 
    /* We need to zero registers; otherwise, the current syscall will
       be carried out before SIGKILL, which is not always what we want. */
    ptrace(PTRACE_SETREGS, tpid, &r, 0); 
    kill(tpid, SIGKILL); 
  } 
  tcsetattr(0, 0, &clean_term); 
  exit(code); 
}


static _u8* getstring(_u32 ptr) {
  static _u8 gsret[MAXSTRING+8];
  _u32* wtab = (_u32*)gsret;
  _u32 cur = 0;
  
  while (cur < MAXSTRING/4) {
    errno = 0;
    wtab[cur] = ptrace(PTRACE_PEEKDATA, tpid, ptr, 0);
    if (errno) { wtab[cur] = 0; return gsret; }
    if (!(gsret[cur*4] && gsret[cur*4+1] && gsret[cur*4+2] &&
          gsret[cur*4+3])) return gsret;
    cur++; ptr += 4;
  }
  
  wtab[cur] = 0;
  return gsret;

}


static _u8* findpath(_u32 addr) {
  static _u8 fp[MAXSTRING*2+32],cwd[MAXSTRING], rp[PATH_MAX+1];
  _u8 *x = getstring(addr);
  
  if (!x[0]) return "<EMPTY PATH>";
  
  if (x[0] != '/') {
    _s32 rl;
    sprintf(fp,"/proc/%d/cwd",tpid);
    rl = readlink(fp,cwd,MAXSTRING-1);
    if (rl > 0) cwd[rl] = 0; else strcpy(cwd,"<UNKNOWN>");
    sprintf(fp,"%s/%s",cwd,x);
    x = fp;
  }
  
  /* We purposefully ignore the return value */
  memset(rp,0,sizeof(rp));
  realpath(x,rp);
  if (rp[0]) return rp; else return x;
  
}


static _u8* getfdpath(_u32 fd) {
  static _u8 tmp[128],fp[MAXSTRING+8];
  _s32 rl;
  
  sprintf(tmp,"/proc/%d/fd/%u",tpid,fd);
  rl = readlink(tmp,fp,MAXSTRING-1);
 
  if (rl > 0) fp[rl] = 0; else
    sprintf(fp,"<UNKNOWN FILE DESCRIPTOR %d>",fd);
    
  return fp;
  
}



static void create_child(_u8* prog, char** argv) {
  _s32 st;
  
  if ((tpid = fork()) < 0) pfatal("Cannot spawn child");

  if (!tpid) {
    if (ptrace(PTRACE_TRACEME, getppid(), 0, 0)) fatal("ptrace() failed");
    execvp(prog,argv);
    pfatal("Cannot execute program");
  }

  if (waitpid(tpid, &st, WUNTRACED) < 0 || !WIFSTOPPED(st)) {
    errorf("--- Error executing program ---\n");
    clean_exit(1);
  }
  
}


static _u8* find_sysname(_u32 num) {
  _u32 i = 0;
  
  while (sclist[i].num < num && sclist[i].name) i++;
  if (sclist[i].name && sclist[i].num == num) return sclist[i].name;
  return "<UNKNOWN>";
  
}


static _u8* find_ioctl(_u32 num,_u8* safe) {
  _u32 i = 0;
  
  *safe = 0;
  
  while (iolist[i].num < num && iolist[i].name) i++;
  if (iolist[i].name && iolist[i].num == num) {
    *safe = iolist[i].safe;
    return iolist[i].name;
  }
  
  return "<UNKNOWN>";
  
}


static void warn_banner(_u8 pri) {

  tcgetattr(0, &cur_term);
  tcsetattr(0, 0, &clean_term);
  errorf("\n\033[1;37m");

  if (!pri) errorf(".--------------------------.\n"
                   "| FAKEBUST - Security Note |\n"
		   "`--------------------------'\n");
		   
  else if (pri == 1) errorf("*******************************\n"
                            "* FAKEBUST - SECURITY WARNING *\n"
                            "*******************************\n");
			    
  else errorf("*****************************\n"
              "* FAKEBUST - ABUSE ALERT!!! *\n"
              "*****************************\n");

  errorf("\033[2;37m\n");
  
}


static void sighandler(_s32 sig) {
  fatal("Caught signal %d",sig);
}


#define D_ABORT  0
#define D_PERMIT 1
#define D_ALL    2
#define D_SINK   3
#define NOSINK   0x0DEFACED

static void handle_selection(_s8 def,_s32 defret) {
  _u8 ibuf[256];
  _s32 r;
  
  if (defret == NOSINK) {

    errorf("\033[1m"
           ".-----------------------------+-----------------------------.\n"
           "| 1) Abort program %3s        | 2) Permit action once %3s   |\n"
    	   "| 3) Permit future access %3s |                             |\n"
 	   "`-----------------------------+-----------------------------'\n"
	   "\n"
	   "Enter your selection: ",
	   def == 0 ? "(*)" : "   ",
	   def == 1 ? "(*)" : "   ",
	   def == 2 ? "(*)" : "   ");

  } else {
  
    errorf("\033[1m"
           ".-----------------------------+-----------------------------.\n"
           "| 1) Abort program %3s        | 2) Permit action once %3s   |\n"
    	   "| 3) Permit future access %3s | 4) Sink syscall! %3s        |\n"
 	   "`-----------------------------+-----------------------------'\n"
	   "\n"
	   "Enter your selection: ",
	   def == 0 ? "(*)" : "   ",
	   def == 1 ? "(*)" : "   ",
	   def == 2 ? "(*)" : "   ",
	   def == 3 ? "(*)" : "   ");
  
  }
  
reread_input:

  /* No echo */  
  tcsetattr(0, 0, &canoe_term);

  fcntl(0,F_SETFL,O_NONBLOCK);
  while (read(0,ibuf,sizeof(ibuf)) > 0);
  fcntl(0,F_SETFL,O_SYNC);

  r = read(0,ibuf,sizeof(ibuf));
  
  tcsetattr(0, 0, &cur_term);
  errorf("\033[0m");
  
  if (r <= 0) fatal("Unexpected EOF");

  /* Handle default */  
  if (ibuf[0] == '\n') ibuf[0] = '1' + def;
  
  switch (ibuf[0]) {
    case 0x1B: /* ESC */
    case '1': errorf("1 (abort)\n");  fatal("Program terminated"); 
    case '2': errorf("2 (permit)\n"); break;
    case '3': errorf("3 (allow all)\n"); break;
    case '4': if (defret != NOSINK) {
                errorf("4 (sink!)\n");
                sink_syscall = 1; 
		syscall_result = defret; 
		break;
	      } /* else fall through */
    default: goto reread_input;
  }
  
  /*
     //Create list of permitted syscalls and files
     XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
     XX        XXX      XXX      XXXXX      XXX
     XXXXX  XXXXX   XX   XX  XX   XXX   XX   XX
     XXXXX  XXXXX  XXXX  XX  XXX   XX  XXXX  XX
     XXXXX  XXXXX   XX   XX  XX   XXX   XX   XX
     XXXXX  XXXXXX      XXX      XXXXX      XXX
     XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
     
     Implement option 3!
     
   */

}



static void handle_selection_fork(void) {
  _u8 ibuf[256];
  _s32 r;
  
  errorf("\033[1m"
         ".--------------------------------+---------------------------------.\n"
         "| 1) Abort program               | 2) Trace child, kill parent (*) |\n"
	 "| 3) Trace parent, kill child    |                                 |\n"
	 "`--------------------------------+---------------------------------'\n"
	 "\n"
	 "Enter your selection: ");
  

reread_input:

  /* No echo */  
  tcsetattr(0, 0, &canoe_term);

  fcntl(0,F_SETFL,O_NONBLOCK);
  while (read(0,ibuf,sizeof(ibuf)) > 0);
  fcntl(0,F_SETFL,O_SYNC);

  r = read(0,ibuf,sizeof(ibuf));  
  tcsetattr(0, 0, &cur_term);
  errorf("\033[0m");
  
  if (r <= 0) fatal("Unexpected EOF");

  switch (ibuf[0]) {
    case 0x1B: /* ESC */
    case '1': errorf("1 (abort)\n"); fatal("Program terminated"); 
    case '2': errorf("2 (child)\n"); 
              sink_syscall = 1; syscall_result = 0; break;
    case '3': errorf("3 (parent)\n"); 
              sink_syscall = 1; syscall_result = tpid; break;
    default: goto reread_input;
  }

}




static _u8* clean_name(_u8* name) {  
  static _u8 rbuf[80];
  _u32 l = strlen(name),i;
  
  if (l > 60) {
    strncpy(rbuf,name,25);
    strcat(rbuf,"(...)");
    strcat(rbuf,name+l-25);
  } else strcpy(rbuf,name);
  
  l = strlen(rbuf);
  for (i=0;i<l;i++) if (rbuf[i] < ' ' || rbuf[i] > '~') rbuf[i]='?';
  return rbuf;
  
}


static _u8 isroot(void) {
  _u8 tmp[512], isroot = 0;
  FILE* x;
  sprintf(tmp,"/proc/%d/status",tpid);
  x = fopen(tmp,"r");
  if (!x) return iamroot; /* uh? */
  
  while (fgets(tmp,sizeof(tmp),x)) {
    if (!strncasecmp("Uid:",tmp,4)) {
      _u32 i;
      for (i=4;i<strlen(tmp);i++)
        if (tmp[i] == '0' && !isdigit(tmp[i-1])) { isroot=1; break; }
      break;
    }
  }
  
  fclose(x);
  return isroot;
  
}



static _u8* check_addr(_u32 fd) {

  struct stat st;
  static _u8 buf[1024];
  _u8 rep = 0;
  
  sprintf(buf,"/proc/%u/fd/%u", tpid, fd);
  if (stat(buf, &st) || !S_ISSOCK(st.st_mode)) 
    return "<UNKNOWN>";
  
  while (rep < 2) {
    FILE* f;
    f = fopen(rep ? "/proc/net/udp" : "/proc/net/tcp","r");
  
    while (fgets(buf,sizeof(buf),f)) {
      _u8 sa[4], da[4];
      _u32 sp, dp, ino;

      if (sscanf(buf,"%*d: %x:%x %x:%x %*x %*x:%*x %*x:%*x %*x %*x %*x %u",
              (_u32*)sa, &sp, (_u32*)da, &dp, &ino) < 5) continue;
	    
      // errorf("read ino = %d st.st_ino = %d\n",ino,st.st_ino);	    
	    
      if (ino != st.st_ino) continue;
    
      sprintf(buf,"%u.%u.%u.%u:%u <-> %u.%u.%u.%u:%u (%s)",
              sa[0], sa[1], sa[2], sa[3], sp,
              da[0], da[1], da[2], da[3], dp, rep ? "UDP" : "TCP");
      fclose(f);
      return buf;      
	    
    }
    
    fclose(f);
    rep++;
    
  }
  
  return "<UNKNOWN>";
  
  
}



#define CRET_NONE	0
#define CRET_ACCEPT	1
#define CRET_RECVFROM	2
  

static void soup_nazi(_u32 sysnum,struct user_regs_struct* r) {

  if (!secret_lair) 
    secret_lair = (1 + (r->esp / 4096)) * 4096 - LAIR_SIZE;

  /* We use syscall numbers rather than names to make porting more
     difficult... but seriously, it'd be a bad idea to hope for 
     /usr/include/asm/unistd.h to have an up-to-date list of what we
     might be interested in. */

  switch (sysnum) {

    /* Long list of syscalls we do not give a damn about, because they
       do not request access to interesting information, and have no
       other adverse effects: */
        
    case 1: /* exit */  		case 3: /* read */
    case 4: /* write */			case 6: /* close */
    case 7: /* waitpid */		case 12: /* chdir */
    case 13: /* time */			case 19: /* lseek */
    case 18: /* oldstat */
    case 20: /* getpid */		case 24: /* getuid */
    case 27: /* alarm */		case 28: /* oldfstat */
    case 29: /* pause */		case 31: /* stty */
    case 32: /* gtty */			case 33: /* access */
    case 34: /* nice */			case 35: /* ftime */
    case 36: /* sync */			case 41: /* dup */
    case 42: /* pipe */			case 43: /* times */
    case 45: /* brk */			case 47: /* getgid */
    case 48: /* signal */		case 49: /* geteuid */
    case 50: /* getegid */		case 55: /* fcntl */
    case 57: /* setpgid */		case 58: /* ulimit */
    case 59: /* oldoluname */		
    case 62: /* ustat */		case 63: /* dup2 */
    case 64: /* getppid */		case 65: /* getpgrp */
    case 66: /* setsid */		case 67: /* sigaction */
    case 68: /* sgetmask */		case 69: /* ssetmask */
    case 72: /* sigsuspend */		case 73: /* sigpending */    
    case 75: /* setrlimit */		case 76: /* getrlimit */
    case 77: /* getrusage */		case 78: /* gettimeofday */
    case 80: /* getgroups */		case 82: /* select */
    case 85: /* readlink */
    case 84: /* oldlstat */		case 86: /* uselib */
    case 89: /* readdir */		case 90: /* mmap */
    case 91: /* munmap */		case 92: /* truncate */
    case 93: /* ftruncate */		case 96: /* getpriority */
    case 97: /* setpriority */		case 99: /* statfs */
    case 100: /* fstatfs */		case 104: /* setitimer */
    case 105: /* getitimer */		case 106: /* stat */
    case 107: /* lstat */		case 108: /* fstat */
    case 109: /* olduname */		case 114: /* wait4 */
    case 116: /* sysinfo */		case 118: /* fsync */
    case 122: /* uname */		case 125: /* mprotect */
    case 130: /* get_kernel_syms */
    case 126: /* sigprocmask */		case 132: /* getpgid */
    case 133: /* fchdir */		case 135: /* sysfs */
    case 136: /* personality */		case 140: /* llseek */
    case 141: /* getdents */		case 142: /* newselect */
    case 143: /* flock */		case 144: /* msync */
    case 145: /* readv */		case 146: /* writev */
    case 147: /* getsid */		case 148: /* fdatasync */
    case 150: /* mlock */		case 151: /* munlock */
    case 152: /* mlockall */		case 153: /* munlockall */
    case 155: /* sched_getparam */	case 157: /* sched_getscheduler */
    case 158: /* sched_yield */		case 159: /* sched_get_pri_max */
    case 160: /* sched_get_pri_min */   case 161: /* sched_rr_get_interval */
    case 162: /* nanosleep */		case 163: /* mremap */
    case 165: /* getresuid */		case 167: /* query_module */
    case 168: /* poll */		case 171: /* getresgid */
    case 174: /* rt_sigaction */	case 175: /* rt_sigprocmask */
    case 176: /* rt_sigpending */	case 177: /* rt_sigtimedwait */
    case 178: /* rt_sigqueueinfo */	case 179: /* rt_sigsuspend */
    case 180: /* pread */		case 181: /* pwrite */
    case 183: /* getcwd */		case 184: /* capget */
    case 185: /* capset */		case 186: /* sigaltstack */
    case 187: /* sendfile */		case 188: /* getpmsg */
    case 189: /* putpmsg */		case 191: /* ugetrlimit */
    case 192: /* mmap2 */		case 193: /* truncate64 */
    case 194: /* ftruncate64 */		case 195: /* stat64 */
    case 196: /* lstat64 */		case 197: /* fstat64 */
    case 199: /* getuid32 */		case 200: /* getgid32 */
    case 201: /* geteuid32 */		case 202: /* getegid32 */
    case 205: /* getgroups32 */		case 209: /* getresuid32 */
    case 211: /* getresgid32 */		case 218: /* mincore */
    case 219: /* madvise */		case 220: /* getdents64 */
    case 221: /* fcntl64 */		case 224: /* gettid */
    case 225: /* readahead */		case 229: /* getxattr */
    case 230: /* lgetxattr */		case 231: /* fgetxattr */
    case 232: /* listxattr */		case 233: /* llistxattr */
    case 234: /* flistxattr */		case 239: /* sendfile64 */
    case 243: /* set_thread_area */	case 244: /* get_thread_area */
    case 250: /* alloc_hugepages */	case 251: /* free_hugepages */
    case 252: /* exit_group */		case 154: /* sched_setparam */
    case 172: /* prctl */		case 258: /* set_tid_address */

    /* You need privileges to switch UIDs in the first place... there's 
       little malice in voluntarily giving some of them up... */
    
    case 23: /* setuid */		case 70: /* setreuid */
    case 46: /* setgid */               case 71: /* setregid */
    case 81: /* setgroups */            case 138: /* setfsuid */
    case 139: /* setfsgid */            case 164: /* setresuid */
    case 170: /* setresgid */           case 203: /* setreuid32 */
    case 204: /* setregid32 */          case 206: /* setgroups32 */
    case 208: /* setresuid32 */         case 210: /* setresgid32 */
    case 213: /* setuid32 */            case 215: /* setfsuid32 */
    case 216: /* setfsgid32 */		case 214: /* setgid32 */
    
      break;

    case 119: /* sigreturn */			
    case 173: /* rt_sigreturn */
      skip_eip_check = 1;
      break;

    case 60: /* umask */
      child_umask = r->ebx & 0777;
      break;

handle_open:
      
    case 8: /* creat */
      r->ecx = O_RDWR;
      /* Fall through */
      
    case 5: { /* open */
    
        _u8* fn = findpath(r->ebx), exists = 1;
	struct stat st;
	
	if (stat(fn,&st)) exists=0;
	
        if (r->ecx & (O_WRONLY|O_RDWR)) {

          /* For writing */

          if (local) {
	  
            warn_banner(1);
	    
	    if (exists)
	      errorf(MSG1);
            else
	      errorf(MSG2);
	  } else {
            warn_banner(2);
	    
	    if (exists)
	      errorf(MSG3);
            else
	      errorf(MSG4);
          }	  
	  
          errorf("File name : %s\n",clean_name(fn));
	  
	  if (S_ISCHR(st.st_mode) || S_ISBLK(st.st_mode))
	    errorf("WARNING   : *** This is a special (device) file! ***\n");
          else if (st.st_nlink != 1)
	    errorf("WARNING   : *** This is a hard link! ***\n");
	  
	  errorf("\n");
          handle_selection(local ? D_PERMIT : D_ABORT, 31337);
	  
	} else {
	  _u32 i = 0;
	  
	  /* For reading */
	  
	  if ((st.st_mode & S_IXOTH) && 
	      (S_ISREG(st.st_mode) || S_ISDIR(st.st_mode))) return;

          while (read_ok[i]) {
	    if (!strcmp(fn,read_ok[i])) return;
	    i++;
	  }

          warn_banner(0);
          errorf(MSG5);

          errorf("File name : %s\n",clean_name(fn));
	  
	  if (S_ISCHR(st.st_mode) || S_ISBLK(st.st_mode))
	    errorf("WARNING   : *** This is a special (device) file! ***\n");
          else if (st.st_nlink != 1)
	    errorf("WARNING   : *** This is a hard link! ***\n");
	  
	  errorf("\n");
          handle_selection(D_PERMIT, 31337);
	    	  
	}
	
      }
 
      break;
      
    case 54: { /* ioctl */
     
        _u8 safe, *inam;      
        inam = find_ioctl((_u32)r->ecx,&safe);
      
        if (!safe) {
          _u8* fn = getfdpath(r->ebx);
  
          warn_banner(1);
          errorf(MSG6);
  
          errorf("Request   : %s\n"
                 "Req. code : 0x%04X\n"
                 "File name : %s\n\n",
	         inam,(_u32)r->ecx, clean_name(fn));

          handle_selection(D_PERMIT, 0);
	
        }
      
      }
      
      break;
      

    case 83: /* symlink */
    case 9: { /* link */

        _u8* fn = findpath(r->ebx), exists = 1;
	struct stat st;
	if (stat(fn,&st)) exists=0;

        if (local) {
          warn_banner(0);	    
          errorf(MSG7, sysnum == 9 ? "HARD " : "SYM");
        } else {      
          warn_banner(2);	    
          errorf(MSG8, sysnum == 9 ? "HARD " : "SYM");
        }

        errorf("File name : %s\n",clean_name(fn));
	  
	if (exists) {
          if (S_ISCHR(st.st_mode) || S_ISBLK(st.st_mode))
	    errorf("WARNING   : *** This is a special (device) file! ***\n");
          else if (st.st_nlink != 1)
            errorf("WARNING   : *** This is a hard link! ***\n");
	}
	
        fn = findpath(r->ecx);
        errorf("Link name : %s\n",clean_name(fn));
	
        errorf("\n");
        handle_selection(local ? D_PERMIT : D_ABORT, 0);
	
      }
      
      break;

    case 10: { /* unlink */

        _u8* fn = findpath(r->ebx);

        warn_banner(0);	    
        errorf(MSG9);

        errorf("File name : %s\n\n",clean_name(fn));
        handle_selection(D_SINK, 0);
	
      }
      break;

    case 11: { /* execve */
        _u8* fn = findpath(r->ebx), exists = 1;
	_u32 argp, envp, cv, i;
	struct stat st;
	if (stat(fn,&st)) exists=0;
	
	/* We are confused. Or the guy is. */
	if (!exists || !S_ISREG(st.st_mode) || access(fn,X_OK))
	  return;

        if (local) {
          warn_banner(1);	    
          errorf(MSG10);
        } else {
          warn_banner(2);	    
          errorf(MSG11);
	}

	argp = r->ecx;
	envp = r->edx;
	
	errorf("\033[1m");
	errorf("Program    : %s\n", clean_name(fn));

        i = 0;
        do {
          errno = 0;
          cv = ptrace(PTRACE_PEEKDATA, tpid, argp, 0);
	  if (errno) cv = 0;
	  
	  if (cv) {
	    _u8* x = getstring(cv);
	    errorf("  av[%d] = %s\n", i, clean_name(x));
	  }
	  
	  argp += 4; i++;
        } while (cv && i < 8);
	
	if (i == 8) errorf("  (...more parameters)\n");
          else if (!i) errorf("  <NO PARAMETERS>\n");

        errorf("\nNew environment:\n");

        i = 0;
        do {
          errno = 0;
          cv = ptrace(PTRACE_PEEKDATA, tpid, envp, 0);
	  if (errno) cv = 0;
	  
	  if (cv) {
	    _u8* x = getstring(cv);
	    _u8* y = strchr(x,'=');
	    
	    if (y) {
	      _u8* z;
	      *y=0; y++;      
	      z = getenv(x);
	      if (!z || strcmp(z,y)) {
	        *(y-1) = '=';
  	        errorf("  %s\n", clean_name(x));
		i++;
	      }
	    }
	  }
	  
	  envp += 4;
        } while (cv && i < 8);

        if (i == 8) errorf("  (...more additions...)\n");
          else if (!i) errorf("  <NO ADDITIONS>\n");
	
      }
      
      errorf("\033[0m");
      fatal("Trace ended at execve() call");;
      break;

    case 14: /* mknod */
    
      if (!(S_ISBLK(r->ecx) || S_ISCHR(r->ecx)))
        goto handle_open;
	  
      if (isroot()) {
        _u8* fn = findpath(r->ebx);
	
        warn_banner(2);	    
        errorf(MSG12);

        errorf("Device path : %s\n",clean_name(fn));
        errorf("Device ID   : %s(%u.%u)\n\n",
	  S_ISBLK(r->ecx) ? "block":"char", r->edx >> 8, r->edx & 0xff);
	  
        handle_selection(D_ABORT, 0);
	
      }
      
      break;

    case 94: /* fchmod */
    case 15: { /* chmod */

        _u8* fn = (sysnum == 94) ? getfdpath(r->ebx) : findpath(r->ebx);
        _u8 def = D_ABORT;
      
        if (r->ecx & (S_ISUID|S_ISGID)) {	
          warn_banner(2);	    
          errorf(MSG13);
        } else if (r->ecx & S_IWOTH) {
          warn_banner(2);	    
          errorf(MSG14);
        } else {
          if (local) {
            warn_banner(0);	    
            errorf(MSG15);
  	    def = D_PERMIT;
          } else {      
            warn_banner(1);	    
            errorf(MSG16);
            def = D_SINK;
          }
        }
	      
        errorf("File name   : %s\n",clean_name(fn));
        errorf("Permissions : 0%04o\n\n",r->ecx);
        handle_selection(def, 0);
	
      }
      
      break;

    case 207: /* fchown32 */
    case 95: /* fchown */
    case 16: /* lchown; technically, misleading */
    case 182: /* chown */
    case 198: /* lchown32 */
    case 212: /* chown32 */
    
      if (isroot()) {
        _u8* fn = ((sysnum == 95) || (sysnum == 207)) ? 
	           getfdpath(r->ebx) : findpath(r->ebx);
	
        warn_banner(2);	    
        errorf(MSG17);

        errorf("File path : %s\n",clean_name(fn));
        errorf("New owner : %u.%u\n\n",r->ecx,r->edx);
	
        handle_selection(D_ABORT, 0);

      }

      break;
      
    case 21: /* mount */

      if (isroot()) {
        _u8* fn = findpath(r->ebx);
	
        warn_banner(2);	    
        errorf(MSG18);

        errorf("Device      : %s\n",clean_name(fn));
        fn = findpath(r->ecx);
        errorf("Mount point : %s\n",clean_name(fn));
        fn = getstring(r->edx);
        errorf("Filesystem  : %s\n\n",clean_name(fn));
	
        handle_selection(D_ABORT, 0);

      }
    
      break;

    case 22: /* umount */
    case 52: /* umount2 */
    
      if (isroot()) {
        _u8* fn = findpath(r->ebx);
	
        warn_banner(2);	    
        errorf(MSG19);

        errorf("Mount point : %s\n\n",clean_name(fn));
        handle_selection(D_ABORT, 0);

      }

      break;

    case 79: /* settimeofday */
      /* Pushing it a bit, but hey... */

    case 25: /* stime */

      if (isroot()) {
        _u32 nt;
	
	errno = 0;
	nt = ptrace(PTRACE_PEEKDATA, tpid, r->ebx, 0);
	if (errno) nt = 0;
	
	
        warn_banner(2);	    
        errorf(MSG20);

        if (nt) {
	  _u8* x = ctime((time_t*)&nt);
	  if (*(x+strlen(x)-1) == '\n') *(x+strlen(x)-1) = 0;
	  errorf("New time    : %s\n",x);
          errorf("Time offset : %+d seconds\n\n",nt - (_u32)time(0));
	}
	
        handle_selection(D_SINK, 0);

      }

      break;

    case 26: /* ptrace */
    
      if (r->ebx != PTRACE_ATTACH) return;

      warn_banner(2);	    
    
      errorf(MSG21);
      
      errorf("Request    : PTRACE_ATTACH\n"
             "Target PID : %d\n\n", r->ecx);
	       
      handle_selection(D_ABORT, -ESRCH);
      break;

    case 30: { /* utime */
    
        _u32 at, mt;
	_u8* fn;
	
	/* NULL update is harmless */
	if (!r->ecx) return;
	
	fn = findpath(r->ebx);
	
	errno = 0;
	at = ptrace(PTRACE_PEEKDATA, tpid, r->ecx, 0);
	mt = ptrace(PTRACE_PEEKDATA, tpid, r->ecx + 4, 0);
	if (errno) at = 0;

        if (local) {	 	
          warn_banner(1);
          errorf(MSG22);
        } else {
          warn_banner(2);
          errorf(MSG23);
        }

        errorf("File name   : %s\n",clean_name(fn));
       
        if (at) {
	  _u8* x = ctime((time_t*)&at);
	  if (*(x+strlen(x)-1) == '\n') *(x+strlen(x)-1) = 0;
	  errorf("Access time : %s (%+d sec)\n",x, at - (_u32)time(0));

	  x = ctime((time_t*)&mt);
	  if (*(x+strlen(x)-1) == '\n') *(x+strlen(x)-1) = 0;
	  errorf("Mod. time   : %s (%+d sec)\n",x, mt - (_u32)time(0));

	}
	
	errorf("\n");
        handle_selection(D_SINK, 0);

      }

      break;

    case 238: /* tkill */
    case 37: /* kill */

      if (!r->ecx) return;

      warn_banner(1);	    
    
      errorf(MSG24);
      
      errorf("Target PID : %d\n"
             "Signal     : %d\n\n", r->ebx, r->ecx);
	       
      handle_selection(D_SINK, 0);
      break;

    case 38: { /* rename */

        _u8* fn = findpath(r->ebx);
	
        if (local) {
          warn_banner(1);
          errorf(MSG25);
        } else {      
          warn_banner(2);	    
          errorf(MSG26);
        }

        errorf("Current name : %s\n",clean_name(fn));
	  
        fn = findpath(r->ecx);
        errorf("New name     : %s\n",clean_name(fn));
	
        errorf("\n");
        handle_selection(local ? D_PERMIT : D_ABORT, 0);
	
      }
      
      break;
    
    case 39: { /* mkdir */

        _u8* fn = findpath(r->ebx);

        if (local) {
	
	  if ((r->ecx & ~child_umask) & S_IWOTH) {
            warn_banner(1);
            errorf(MSG27);
	  } else {
            warn_banner(0);
            errorf(MSG28);
	  }
        } else {      
          warn_banner(2);	    
          errorf(MSG29);
        }

        errorf("Directory  : %s\n"
	       "Eff. perms : 0%03o\n\n",
	       clean_name(fn), r->ecx & ~child_umask);
	  
        handle_selection(local ? D_PERMIT : D_ABORT, 0);
	
      }
      
      break;

    case 40: { /* rmdir */

        _u8* fn = findpath(r->ebx);

        if (local) {	
          warn_banner(0);
          errorf(MSG30);
        } else {      
          warn_banner(1);	    
          errorf(MSG31);
        }

        errorf("Directory : %s\n\n",clean_name(fn));
        handle_selection(D_PERMIT, 0);
	
      }
      
      break;

    case 51: /* acct */
    
      if (isroot()) {
        warn_banner(2);	    
        if (r->ebx) {
	  _u8* fn = findpath(r->ebx);
          errorf(MSG32, clean_name(fn));
        } else {
          errorf(MSG33);
	}
	handle_selection(D_SINK, 0);
      }
      
      break;

    case 61: /* chroot */
    case 217: /* pivot_root */

      if (isroot()) {
        _u8* fn = findpath(r->ebx);
        warn_banner(2);	    

        errorf(MSG34, clean_name(fn));
	handle_selection(D_SINK, 0);
      }
      
      break;

    case 74: /* sethostname */
    case 121: /* setdomainname */

      if (isroot()) {
        _u8* fn = getstring(r->ebx);
        warn_banner(2);	    

        errorf(MSG35, clean_name(fn));
	handle_selection(D_SINK, 0);
      }
      
      break;

    case 87: /* swapon */

      if (isroot()) {
        _u8* fn = findpath(r->ebx);
        warn_banner(2);	    

        errorf(MSG36, clean_name(fn));
	handle_selection(D_ABORT, 0);
      }
      
      break;

    case 88: /* reboot (d'oh!) */

      if (isroot()) {

        warn_banner(2);	    

        errorf(MSG37);
	handle_selection(D_SINK, 0);
      }
      
      break;
      
    case 101: /* ioperm */

      if (isroot() && r->edx) {

        warn_banner(2);	    

        errorf(MSG38);
	       
	errorf("First port : 0x%03x\n"
               "Last port  : 0x%03x\n\n",
	       r->ebx, r->ebx + r->ecx);
	       
	handle_selection(D_ABORT, 0);
	
      }
      
      break;


    case 102: { /* SOCKETCALL family */
        _u32 p[5];
      
        errno = 0;
        p[0] = ptrace(PTRACE_PEEKDATA, tpid, r->ecx, 0);      
        if (errno) return; /* Sheesh */
        p[1] = ptrace(PTRACE_PEEKDATA, tpid, r->ecx + 4, 0);      
        p[2] = ptrace(PTRACE_PEEKDATA, tpid, r->ecx + 8, 0);      
        p[3] = ptrace(PTRACE_PEEKDATA, tpid, r->ecx + 12, 0);      
        p[4] = ptrace(PTRACE_PEEKDATA, tpid, r->ecx + 16, 0);      
    
        switch (r->ebx) {
      
          case 1: /* SYS_SOCKET */
	
  	    /* Those combinations can be safely handled when specific
	       packets are received or sent later on. Raw sockets and 
	       other obscure protocols should be detected early, because
	       of the possibility for mapped network I/O and so on. */
	     
   	    if ((p[0] == PF_UNIX || p[0] == PF_LOCAL || p[0] == PF_INET ||
	        p[0] == PF_INET6) && (p[1] == SOCK_STREAM || 
	        p[1] == SOCK_DGRAM || p[1] == SOCK_SEQPACKET || 
	        p[1] == SOCK_RDM)) return;
	
	    if (p[0] == PF_PACKET || p[1] == SOCK_RAW || 
                p[1] == SOCK_PACKET) {
	      if (isroot()) {
                if (local) {
                  warn_banner(2);	    
                  errorf(MSG39);
	        } else {
                  warn_banner(1);	    
                  errorf(MSG40);
	        }
	       
	        errorf("Protocol family : %d\n"
	               "Protocol type   : %d/%d\n\n", p[0], p[1], p[2]);		       
	        handle_selection(D_ABORT,31337);

              }
	    
	    } else {

              warn_banner(1);	    
              errorf(MSG41);
	       
              errorf("Protocol family : %d\n"
                     "Protocol type   : %d/%d\n\n", p[0], p[1], p[2]);		       
              handle_selection(D_ABORT,31337);
	    
	    }

            break;

          case 2: /* SYS_BIND */

            /* Tylko AF_UNIX */	   
	    if ((ptrace(PTRACE_PEEKDATA, tpid, p[1], 0) & 0xFF) == AF_UNIX) {
	
              _u8* fn = findpath(p[1] + 2 /* sa common */);
	      if (fn[0] == '<') return; /* Private namespace */
	      
              if (local) {	
                warn_banner(0);
                errorf(MSG42);
	      } else {
                warn_banner(1);
                errorf(MSG43);
	      }
	      
	      errorf("Socket name : %s\n\n", clean_name(fn));
	      handle_selection(local ? D_PERMIT : D_ABORT, 0);
	      
	    }
	    
	    break;
	    
	  case 3: { /* SYS_CONNECT */
	    _u8 af;
	    
	    errno = 0;
	    af = ptrace(PTRACE_PEEKDATA, tpid, p[1], 0);
	    if (errno) return;
	    
	    switch (af) {
	    
	      case AF_UNSPEC: 
	        break;
	    
	      case AF_UNIX: {
	          _u8* fn = findpath(p[1] + 2);
		  _u32 i = 0;

                  if (fn[0] == '<') fn = findpath(p[1] + 3);

                  while (read_ok[i]) {
	            if (!strcmp(fn,read_ok[i])) return;
            	    i++;
	          }
		  
                  if (local) {	
                    warn_banner(0);
                    errorf(MSG44);
  	          } else {
                    warn_banner(1);
                    errorf(MSG45);
	          }
		  
		  errorf("Socket : %s\n\n", clean_name(fn));
                  handle_selection(D_PERMIT, 0);
		  
		}
		
		break;

	      case AF_INET: {
	          // Port at p[1] + 2 (2 bytes)
	          // Address at p[1] + 4
	          _u16 pt = ptrace(PTRACE_PEEKDATA, tpid, p[1] + 2, 0);
		  _u32 ad = ptrace(PTRACE_PEEKDATA, tpid, p[1] + 4, 0);
		  _u8* a = (_u8*)&ad;

                  if (local) {	
                    warn_banner(2);
                    errorf(MSG46);
  	          } else {
                    warn_banner(0);
                    errorf(MSG47);
			   
	          }
		  
		  
		  errorf("Target host : %u.%u.%u.%u\n"
		         "Target port : %u%s\n\n", a[0], a[1], a[2], a[3], 
			 ntohs(pt),
			 ntohs(pt) == 53 ? " (DNS query)" : "" );
			 
                  handle_selection(local ? D_ABORT : D_PERMIT, 0);
		  
		} 
		
		break;
		
	      case AF_INET6: {
	          // Port at p[1] + 2 (2 bytes)
		  // Address at p[1] + 8 (16 bytes)

	          _u16 pt = ptrace(PTRACE_PEEKDATA, tpid, p[1] + 2);
		  _u32 ad[4];
		  _u8* a = (_u8*)&ad;

		  ad[0] = ptrace(PTRACE_PEEKDATA, tpid, p[1] + 8);
		  ad[1] = ptrace(PTRACE_PEEKDATA, tpid, p[1] + 12);
		  ad[2] = ptrace(PTRACE_PEEKDATA, tpid, p[1] + 16);
		  ad[3] = ptrace(PTRACE_PEEKDATA, tpid, p[1] + 20);

                  if (local) {	
                    warn_banner(2);
                    errorf(MSG48);
  	          } else {
                    warn_banner(0);
                    errorf(MSG49);
	          }
		  
		  errorf("Target host : %02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X (IPv6)\n"
		         "Target port : %u\n\n", 
			 a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7],
			 a[8], a[9], a[10], a[11], a[12], a[13], a[14], a[15],
			 ntohs(pt));
			 
                  handle_selection(local ? D_ABORT : D_PERMIT, 0);
		  
		} 
		
		break;
	  
	      default:

                warn_banner(2);
                errorf(MSG50, af);

                handle_selection(D_ABORT, 0);
		
	    }
	    
          }
	  
	  break;
	  
        case 5: /* SYS_ACCEPT - We will prompt for it on return */
	  check_ret = CRET_ACCEPT;
          break;
	  
	case 11: /* SYS_SENDTO */
	  if (p[4]) { /* p[4] - struct sockaddr (dest) */
	    _u8 af;

            errno = 0;
	    af = ptrace(PTRACE_PEEKDATA, tpid, p[4], 0);
	    if (errno) af = 0;
	    
	    if (local) {
              warn_banner(2);
              errorf(MSG51);
	    } else if (af != AF_INET && af != AF_INET6 && af != AF_UNIX) {
              warn_banner(2);
              errorf(MSG52);
	    } else {
              warn_banner(1);
              errorf(MSG53);
            }
	    
	    errorf("Descriptor  : %d\n",p[0]);
	    
	    /* On network sockets, do some guessing */
	    if (af != AF_UNIX) {
  	      _u8* sn = check_addr(p[0]);
	      
	      if (sn[0] == '<') { /* RAW? Or something else? */
	        _u8 tos;
	        errno = 0;
         	if (af == PF_PACKET) p[1] += 14;	    
	        tos = ptrace(PTRACE_PEEKDATA, tpid, p[1], 0);
	        
	        if (!errno && tos >= 0x45 && tos <= 0x4F) {
	          _u8 sa[4], da[4];
	  	
	    	  *(_u32*)sa = ptrace(PTRACE_PEEKDATA, tpid, p[1] + 12, 0);
		  *(_u32*)da = ptrace(PTRACE_PEEKDATA, tpid, p[1] + 16, 0);
		
		  if (!errno) 
		    errorf("Packet data : %u.%u.%u.%u -> %u.%u.%u.%u (RAW)\n",
		           sa[0],sa[1],sa[2],sa[3],da[0],da[1],da[2],da[3]);
		   else errorf("Packet data : N/A (bad packet?)\n");
	        } else errorf("Packet data : N/A\n");
	      
	      /* TCP or UDP - boring */
	      } else errorf("Socket data : %s\n", sn);
	    }  
	    
	    /* Interpret toaddr */
	    switch (af) {

	      case AF_UNIX: {
	          _u8* fn = findpath(p[4] + 2);
		  _u32 i = 0;

                  if (fn[0] == '<') fn = findpath(p[4] + 3);

                  while (read_ok[i]) {
	            if (!strcmp(fn,read_ok[i])) return;
            	    i++;
	          }
		  
		  errorf("Target sock : %s\n", fn);
		  
		}  
		break;

	      case AF_INET: {
	          // Port at p[4] + 2 (2 bytes)
	          // Address at p[4] + 4
	          _u16 pt = ptrace(PTRACE_PEEKDATA, tpid, p[4] + 2, 0);
		  _u32 ad = ptrace(PTRACE_PEEKDATA, tpid, p[4] + 4, 0);
		  _u8* a = (_u8*)&ad;

		  errorf("Target host : %u.%u.%u.%u\n"
		         "Target port : %u%s\n", a[0], a[1], a[2], a[3], 
			 ntohs(pt), htons(pt) == 53 ? " (DNS query)" : "" );
			 
		} 
		
		break;
		
	      case AF_INET6: {
	          // Port at p[4] + 2 (2 bytes)
		  // Address at p[4] + 8 (16 bytes)
	          _u16 pt = ptrace(PTRACE_PEEKDATA, tpid, p[4] + 2);
		  _u32 ad[4];
		  _u8* a = (_u8*)&ad;

		  ad[0] = ptrace(PTRACE_PEEKDATA, tpid, p[4] + 8);
		  ad[1] = ptrace(PTRACE_PEEKDATA, tpid, p[4] + 12);
		  ad[2] = ptrace(PTRACE_PEEKDATA, tpid, p[4] + 16);
		  ad[3] = ptrace(PTRACE_PEEKDATA, tpid, p[4] + 20);

		  errorf("Target host : %02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X (IPv6)\n"
		         "Target port : %u\n", 
			 a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7],
			 a[8], a[9], a[10], a[11], a[12], a[13], a[14], a[15],
			 ntohs(pt));
			 
		} 
		
		break;

	      default:
	        errorf("*** UNKNOWN PROTOCOL FAMILY %d - TARGET UNKNOWN ***\n",af);
	    
	    }

	    if (p[1] > 0) {
	      _u8 last16[17];
  	      _u32 len = ((p[2] + 15) / 16 * 16), cur = 0;
	    
	      if (len > 64) {
	        len = 64;
   	        errorf("\nPayload (first 64 bytes):\n");
	      } else errorf("\nPayload:\n");
	    
              errno = 0;
	    
	      while (cur < len) {
	        _u8 x = 0;
	        if (!errno) x = ptrace(PTRACE_PEEKDATA, tpid, p[1] + cur, 0);
	        if (errno) {
	          errorf("   "); 
   	          last16[cur % 16] = ' ';
                } else {
	          errorf("%02X ", x);
  	          last16[cur % 16] = (x < ' ' || x > '~') ? '.' : x;
	        }
	        cur++;
	        if (!(cur % 16)) {
	          last16[16] = 0;
	          errorf(" | %s\n",last16);
	        }
	      }
	    
	    }

            errorf("\n");

            handle_selection(local ? D_ABORT : D_PERMIT, 0);
	    
          }

	  break;

        case 12: /* SYS_RECVFROM */

            check_ret = CRET_RECVFROM;
            rpar1 = p[0];
            rpar2 = p[1];

            if (!(rpar3 = p[4])) {
              _u32 i;

              /* Check for overlap between buffer p[1] (length p[2]) 
                 and secret_lair: */

              if ((p[1] >= secret_lair && p[1] < secret_lair + LAIR_SIZE) ||
                  (p[1] + p[2] - 1 >= secret_lair && p[1] + p[2] - 1 <= 
                   secret_lair + LAIR_SIZE)) return;

              secret_buried = 1;

              for (i=0;i<LAIR_SIZE/4;i++)
                secret_copy[i] = ptrace(PTRACE_PEEKDATA, tpid, 
                                 secret_lair + i * 4, 0);

              /* Modify p[4] to point to secret_lair */
              ptrace(PTRACE_PEEKDATA, tpid, r->ecx + 16, secret_lair);

              /* Modify p[5] to point to integer at the end of lair */
              ptrace(PTRACE_PEEKDATA, tpid, r->ecx + 20, secret_lair + 
                      LAIR_SIZE - 4);

              /* Modify the integer to incidate lair size ohne the integer */
              ptrace(PTRACE_PEEKDATA, tpid, secret_lair + LAIR_SIZE - 4, 
                      LAIR_SIZE - 4);

            }
            
            break;
	  
          case 4: /* SYS_LISTEN */	 case 6: /* SYS_GETSOCKNAME */
	  case 7: /* SYS_GETPEERNAME */	 case 8: /* SYS_SOCKETPAIR */
	  case 9: /* SYS_SEND */	 case 10: /* SYS_RECV */
	  case 13: /* SYS_SHUTDOWN */	 case 14: /* SYS_GETSOCKOPT */
	  case 15: /* SYS_SETSOCKOPT */
	    break;

          default: goto unknown_syscall;
        }
      }
      
      break;
      
    case 103: /* syslog */

      if (isroot()) {

        warn_banner(1);	    

        errorf(MSG54);
	       
        errorf("Access type : ");
	
	switch (r->ebx) {
	  case 0: errorf("CLOSE LOG (0)\n\n"); break;
	  case 1: errorf("OPEN LOG (1)\n\n"); break;
	  case 2: errorf("READ FROM LOG (2)\n\n"); break;
	  case 3: errorf("READ LOG (3)\n\n"); break;
	  case 4: errorf("READ/CLEAR LOG (4)\n\n"); break;
	  case 5: errorf("CLEAR LOG (5)\n\n"); break;
	  case 6: errorf("DISABLE CONSOLE OUTPUT (6)\n\n"); break;
	  case 7: errorf("ENABLE CONSOLE OUTPUT (7)\n\n"); break;
	  case 8: errorf("SET CONSOLE LOG LEVEL (8)\n\n"); break;
          default: errorf("<UNKNOWN> (%d)\n\n",r->ebx);
	}

	handle_selection(D_SINK, 0);
	
      }
      
      break;

    case 110: /* iopl */

      if (isroot() && r->ebx) {

        warn_banner(2);	    

        errorf(MSG55);
	       
	handle_selection(D_ABORT, 0);
	
      }
      
      break;

    case 111: /* vhangup */

      if (isroot()) {

        warn_banner(2);	    

        errorf(MSG56);
	handle_selection(D_SINK, 0);
      }
      
      break;


    case 113: /* vm86old */
    case 166: /* vm86 */
    case 123: /* modify_ldt */

      warn_banner(2);	    

      errorf(MSG57);
      handle_selection(D_SINK, 0);
      
      break;

    case 115: /* swapoff */

      if (isroot()) {
        warn_banner(2);	    

        errorf(MSG58);
	       
	handle_selection(D_ABORT, 0);
      }
      
      break;
    
    case 117: /* ipc */
    
      switch (r->ebx) {
        case 1: /* SEMOP */
	case 2: /* SEMGET */
	case 3: /* SEMCTL */
	case 4: /* SEMTIMEDOP */
	case 13: /* MSGGET */
	case 14: /* MSGCTL */
	case 23: /* SHMGET */
	case 24: /* SHMCTL */
	case 22: /* SHMDT */
	  break;

     /*

     XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
     XX        XXX      XXX      XXXXX      XXX
     XXXXX  XXXXX   XX   XX  XX   XXX   XX   XX
     XXXXX  XXXXX  XXXX  XX  XXX   XX  XXXX  XX
     XXXXX  XXXXX   XX   XX  XX   XXX   XX   XX
     XXXXX  XXXXXX      XXX      XXXXX      XXX
     XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX

     For the sake of covering all bases, it would be good to check
     SHMCTL, SEMCTL and MSGCTL for an attempt to delete or chmod
     shared segments.

     */

	case 11: /* MSGSND */

          warn_banner(2);	    
          errorf(MSG59);

          errorf("Queue ID  : 0x%x\n"
	         "Msg. size : %d bytes\n", r->ecx, r->esi);
		 
	  if (r->esi > 0) {
	    _u8 last16[17];
	    _u32 len = ((r->esi + 15) / 16 * 16), cur = 0;
	    
	    if (len > 64) {
	      len = 64;
   	      errorf("\nPayload (first 64 bytes):\n");
	    } else errorf("\nPayload:\n");
	    
            errno = 0;
	    
	    while (cur < len) {
	      _u8 x = 0;
	      if (!errno) x = ptrace(PTRACE_PEEKDATA, tpid, r->esi + cur, 0);
	      if (errno) {
	        errorf("   "); 
   	        last16[cur % 16] = ' ';
              } else {
	        errorf("%02X ", x);
	        last16[cur % 16] = (x < ' ' || x > '~') ? '.' : x;
	      }
	      cur++;
	      if (!(cur % 16)) {
	        last16[16] = 0;
	        errorf(" | %s\n",last16);
	      }
	    }
	    
	  }

          errorf("\n");
  	  handle_selection(D_ABORT, 0);
		 
          break;

	case 12: /* MSGRCV */

          warn_banner(1);	    
          errorf(MSG60);

          errorf("Queue ID  : 0x%x\n"
	         "Msg. size : %d bytes\n\n", r->ecx, r->esi);
		 
  	  handle_selection(D_ABORT, 0);		 
          break;

        case 21: /* SHMAT */

          warn_banner(2);
          errorf(MSG61);

          errorf("Block ID  : 0x%x\n\n", r->ecx);
		 
  	  handle_selection(D_ABORT, 0);		 
          break;
	
	default:

          warn_banner(2);	    

          errorf(MSG62, r->ebx, r->ecx);
 	       
  	  handle_selection(D_ABORT, 0);
	
      }
	    
      break;
      
    case 124: /* adjtimex */
    
      if (isroot()) {
      
        _u32 mod;
	
	errno = 0;
	mod = ptrace(PTRACE_POKEDATA, tpid, r->ebx, 0);
	if (errno) return;
      
        warn_banner(2);	    

        errorf(MSG63,mod);
 	       
        handle_selection(D_SINK, 0);
  
      }
      
      break;
      
    case 127: /* create_module */
    case 128: /* init_module */
    
      if (isroot()) {
        _u8* x = getstring(r->ebx);
	
        warn_banner(2);	    

        errorf(MSG64, clean_name(x));
	       
        handle_selection(D_ABORT, 0);
      }
      
      break;

    case 129: /* delete_module */
    
      if (isroot()) {
        _u8* x = getstring(r->ebx);
	
        warn_banner(2);	    

        errorf(MSG65, clean_name(x));
	       
        handle_selection(D_ABORT, 0);
      }
      
      break;

    case 149: { /* sysctl */
        _u32 nam, naml, nv;
	
        errno = 0;
	nam  = ptrace(PTRACE_PEEKDATA, tpid, r->ebx, 0);
        naml = ptrace(PTRACE_PEEKDATA, tpid, r->ebx + 4, 0);
        nv   = ptrace(PTRACE_PEEKDATA, tpid, r->ebx + 4*4, 0);
        if (errno) return;
        
        if (nv && naml) {

          warn_banner(2);	    
 
          errorf(MSG66);
		 
	  if (naml > 10) naml = 10;
	  
	  errorf("Setting code : ");
		 
	  for (nv = 0; nv < naml; nv++) {
	    _u32 x;
	    errno = 0;
	    x = ptrace(PTRACE_PEEKDATA, tpid, nam, 0);
	    if (errno) break;
	    errorf(".%d",x);
	    nam += 4;
	  }
	    
	  errorf("\n\n");
	  
          handle_selection(D_ABORT, 0);
	
        }
      }
      
      break;    

    case 156: /* sched_setscheduler */
    
      if (isroot()) {
        if (r->ecx != SCHED_OTHER) {

          warn_banner(1); 
          errorf(MSG67);

	} else if (r->ebx != tpid) {

          warn_banner(1); 
          errorf(MSG68);


	} else return;

        errorf("Target PID : %d\n"
               "Priority   : %d\n\n", r->ebx, r->ecx);

        handle_selection(D_SINK, 0);
	
      }
      
      break;
     
    case 228: /* fsetxattr */
    case 237: /* fremovexattr */
    case 226: /* setxattr */
    case 227: /* lsetxattr */
    case 235: /* removexattr */
    case 236: /* lremovexattr */
    
      if (isroot()) {
        _u8* fn = (sysnum == 228 || sysnum == 237) ? 
	          getfdpath(r->ebx) : findpath(r->ebx);
		  
        warn_banner(2);	    
        errorf(MSG69, clean_name(fn));
	       
	handle_selection(D_ABORT, 0);
		  
      }
    
      break;
      
    case 2: /* fork */
    case 190: /* vfork */
    
      if (local) {
        warn_banner(1);
        errorf(MSG70);
      } else {
        warn_banner(2);
        errorf(MSG71);
      }
      
      handle_selection_fork();
      break;

    case 120: /* clone */

      warn_banner(2);
      errorf(MSG72);
	     
      fatal("Program performed illegal operation");
	       
      break;

unknown_syscall:

    /* 223 security
       169 nfsservctl
       137 afs_syscall
       131 quotactl
 
       socketcalls: sendmsg, recvmsg */
      
    default: 
    
      if (local) {
        warn_banner(1);
        errorf(MSG73);
      } else {
        warn_banner(2);
        errorf(MSG74);
      }

      errorf("Syscall number : %u\n"
             "Syscall name   : %s\n\n",
	     sysnum, find_sysname(sysnum));

      { _u8* x;
        _s32 v;
	
	errorf("  EBX = 0x%08X ", r->ebx);
	x = getstring(v = r->ebx);
	if (v > -1000000 && v < 1000000) errorf("[%d] ",v);
        if (x[0]) errorf("\"%s\"",clean_name(x));

	errorf("\n  ECX = 0x%08X ", r->ecx);
	x = getstring(v = r->ecx);
	if (v > -1000000 && v < 1000000) errorf("[%d] ",v);
        if (x[0]) errorf("\"%s\"",clean_name(x));

	errorf("\n  EDX = 0x%08X ", r->edx);
	x = getstring(v = r->edx);
	if (v > -1000000 && v < 1000000) errorf("[%d] ",v);
        if (x[0]) errorf("\"%s\"",clean_name(x));
      }	

      errorf("\n\n");	
           
      handle_selection(local, 0);

  }
  
}




static void handle_return(struct user_regs_struct* r) {

  switch (check_ret) {
  
    case CRET_ACCEPT: 
    
      if (((_s32)r->eax) > 0) {
        _u8* sn = check_addr(r->eax);

        warn_banner(2);
        errorf(MSG75, r->eax,sn);
    	handle_selection(D_ABORT,NOSINK);

      }
      
      break;

    case CRET_RECVFROM:

      if ((_s32)r->eax > 0) {
        _u8 af;
        _u32 soad = rpar3 ? rpar3 : secret_lair;

        errno = 0;
        af = ptrace(PTRACE_PEEKDATA, tpid, soad, 0);
        if (errno) af = 0;

        if (local) {
          warn_banner(2);
          errorf(MSG76);

        } else {
          warn_banner(1);
          errorf(MSG77);
        }

        errorf("Descriptor  : %d\n",rpar1);

        /* On network sockets, do some guessing */
        if (af != AF_UNIX) {
          _u8* sn = check_addr(rpar1);
	  
          if (sn[0] == '<') { /* RAW? Or something else? */
            _u8 tos;
            errno = 0;
	    
	    if (af == PF_PACKET) rpar2 += 14;	    
            tos = ptrace(PTRACE_PEEKDATA, tpid, rpar2, 0);
	    
            if (!errno && tos >= 0x45 && tos <= 0x4F) {
              _u8 sa[4], da[4];

              *(_u32*)sa = ptrace(PTRACE_PEEKDATA, tpid, rpar2 + 12, 0);
              *(_u32*)da = ptrace(PTRACE_PEEKDATA, tpid, rpar2 + 16, 0);

              if (!errno)
                errorf("Packet data : %u.%u.%u.%u -> %u.%u.%u.%u (RAW)\n",
                       sa[0],sa[1],sa[2],sa[3],da[0],da[1],da[2],da[3]);
              else errorf("Packet data : N/A (bad packet?)\n");
            } else errorf("Packet data : N/A\n");
         
          /* TCP or UDP - boring */
          } else errorf("Socket data : %s\n", sn);
        }

        if (!rpar3 && !secret_buried) 
          errorf("*** NO SOCKET SOURCE ADDRESS DATA - TRICKERY? ***\n");
        else /* Interpret toaddr */ switch (af) {

          case AF_UNIX: {
              _u8* fn = findpath(soad + 2);
              _u32 i = 0;

              if (fn[0] == '<') fn = findpath(soad + 3);

              while (read_ok[i]) {
                if (!strcmp(fn,read_ok[i])) return;
                i++;
              }

              errorf("Source sock : %s\n", fn);

            }
            break;

          case AF_INET: {
              // Port at soad + 2 (2 bytes)
              // Address at soad + 4
              _u16 pt = ptrace(PTRACE_PEEKDATA, tpid, soad + 2, 0);
              _u32 ad = ptrace(PTRACE_PEEKDATA, tpid, soad + 4, 0);
              _u8* a = (_u8*)&ad;

              errorf("Source host : %u.%u.%u.%u\n"
                     "Source port : %u%s\n", a[0], a[1], a[2], a[3],
                     ntohs(pt), htons(pt) == 53 ? " (DNS query)" : "" );
            }

            break;

          case AF_INET6: {
              // Port at soad + 2 (2 bytes)
              // Address at soad + 8 (16 bytes)
              _u16 pt = ptrace(PTRACE_PEEKDATA, tpid, soad + 2);
              _u32 ad[4];
              _u8* a = (_u8*)&ad;

              ad[0] = ptrace(PTRACE_PEEKDATA, tpid, soad + 8);
              ad[1] = ptrace(PTRACE_PEEKDATA, tpid, soad + 12);
              ad[2] = ptrace(PTRACE_PEEKDATA, tpid, soad + 16);
              ad[3] = ptrace(PTRACE_PEEKDATA, tpid, soad + 20);

              errorf("Source host : %02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X (IPv6)\n"
                     "Source port : %u\n",
                     a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7],
                     a[8], a[9], a[10], a[11], a[12], a[13], a[14], a[15],
                     ntohs(pt));

            }

            break;
	    
          case AF_PACKET:
            errorf("*** RAW PACKET RECEIPT - SOURCE UNKNOWN ***\n");
	    break;

          default:
            errorf("*** UNKNOWN PROTOCOL FAMILY %d - SOURCE UNKNOWN ***\n",af);

        }

        if (rpar2 > 0) {
          _u8 last16[17];
          _u32 len = ((r->eax + 15) / 16 * 16), cur = 0;
	    
          if (len > 64) {
            len = 64;
            errorf("\nPayload (first 64 bytes):\n");
          } else errorf("\nPayload:\n");
	    
          errno = 0;
	    
          while (cur < len) {
            _u8 x = 0;
            if (!errno) x = ptrace(PTRACE_PEEKDATA, tpid, rpar2 + cur, 0);
            if (errno) {
              errorf("   "); 
              last16[cur % 16] = ' ';
            } else {
              errorf("%02X ", x);
              last16[cur % 16] = (x < ' ' || x > '~') ? '.' : x;
            }
            cur++;
            if (!(cur % 16)) {
              last16[16] = 0;
              errorf(" | %s\n",last16);
            }
          }
	    
        }

        /* We displayed all there was to display. Now, let's
           restore memory if we messed up. */
      
        if (secret_buried) {
          _u32 i;

          secret_buried = 0;
          for (i=0;i<LAIR_SIZE/4;i++)
            ptrace(PTRACE_POKEDATA, tpid, secret_lair + i * 4, 
                   secret_copy[i]);

        }

        errorf("\n");
	handle_selection(D_ABORT,NOSINK);

      }

      break;
 
 
    default: fatal("UNIBUS FATAL TRAP PROGRAM LOST SORRY");
    
  }
  

 
}



static void trace_loop(void) {
  _u32 sig = 0;
  _s32 st;
  _u8  sysret = 0;

  _u32 sc_ad = 0, sc_num = 0;
  

  while (1) {
    if (ptrace(PTRACE_SYSCALL,tpid,0,sig))
      pfatal("PTRACE_SYSCALL failed");

    if (waitpid(tpid, &st, WUNTRACED) < 0)
      pfatal("waitpid failed");
      
    if (WIFEXITED(st)) {
      kill(tpid, SIGKILL);
      errorf("+++ Program exited with code %d +++\n", WEXITSTATUS(st));
      clean_exit(1);
    } else 
    if (WIFSIGNALED(st)) {
      kill(tpid, SIGKILL);
      errorf("--- Program died on signal %d +++\n", WTERMSIG(st));
      clean_exit(1);
    } else
    if (WIFSTOPPED(st)) {
      sig = WSTOPSIG(st);
      if (sig == SIGTRAP) sig = 0;
    } else fatal("Strange outcome of waitpid (status = %d)",st);

    if (!sig) {
      struct user_regs_struct r;
      ptrace(PTRACE_GETREGS, tpid, 0, &r);
    
      if (!sysret) {
        if (r.eax != 0xffffffda)
	  fatal("EAX mismatch on syscall entry?");  

        soup_nazi((_u32)r.orig_eax, &r);
	
	if (sink_syscall) {
	  r.orig_eax = 0;
          ptrace(PTRACE_SETREGS, tpid, 0, &r);
	}
	
	printf("EIP=%08x\n", r.eip);

	sc_ad  = r.eip;
	sc_num = r.orig_eax;	
        sysret = 1;

      } else {
      
        if ((!skip_eip_check && r.eip != sc_ad) || sc_num != r.orig_eax)
          fatal("Syscall return EIP/EAX mismatch (EIP %x/%x, EAX %d/%d)",
            sc_ad, (_u32)r.eip, sc_num, (_u32)r.orig_eax);

        skip_eip_check = 0;		

        if (check_ret) {
	  handle_return(&r);
	  check_ret = 0;
	} else if (sink_syscall) {
	  r.eax = syscall_result;
          ptrace(PTRACE_SETREGS, tpid, 0, &r);
	  sink_syscall = 0;
	}

        sysret = 0;
      
      }
    }
    
  }

}


int main(int argc,char** argv) {

  errorf("Malelficus Dynamic Analaysis - based on Michal Zalewski's fakebust");
  
  setbuffer(stdout,0,0);  
  
  if (argc < 3) usage(argv[0]);

  signal(SIGTERM,sighandler);
  signal(SIGHUP,sighandler);
  signal(SIGINT,sighandler);
  signal(SIGQUIT,sighandler);
  signal(SIGABRT,sighandler);
  signal(SIGBUS,sighandler);
  signal(SIGSEGV,sighandler);

  tcgetattr(0, &clean_term);
  memcpy(&canoe_term,&clean_term,sizeof(struct termios));    
  canoe_term.c_lflag = ~(ICANON|ECHO);

  child_umask = umask(0);
  umask(child_umask);

  if (!strcmp(argv[1],"--pid") && argc == 3) {
    _s32 i = atoi(argv[2]);

    local = 1;
    iamroot = (geteuid() == 0);

    if (i < 2) fatal("Invalid PID specification.");
    tpid = i;

    if (ptrace(PTRACE_ATTACH, tpid, 0, 0)) 
      pfatal("Cannot attach");

    if (waitpid(tpid, &i, WUNTRACED) < 0 || !WIFSTOPPED(i)) {
      errorf("--- Error attaching to process ---\n");
      clean_exit(1);
    }
    
    errorf("+++ Successfully attached to PID %d +++\n", tpid);

  } else {
  
    if (!strcmp(argv[1],"--local")) {
      if (!(getuid() && geteuid() && getgid() && getegid()))
        fatal("Use unprivileged account to test local exploits.");
      local = 1;
    } else if (!strcmp(argv[1],"--remote")) {
      if (!(getuid() && geteuid() && getgid() && getegid()))
        fatal("Use unprivileged account or specify --rawsock if UID 0 is needed.");
    } else if (!strcmp(argv[1],"--rawsock")) {
      if (getuid() && geteuid() && getgid() && getegid())
        fatal("Use --remote for unprivileged runs instead.");
      iamroot = 1;
    } else usage(argv[0]);
  
    create_child(argv[2],argv+2);
    
  }

  trace_loop();
  
  exit(0);

}

