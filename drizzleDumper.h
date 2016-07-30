/*
 * drizzleDumper Code By Drizzle.Risk
 * file: drizzleDumper.h
 */

#include <stdlib.h>
#include <stdio.h>
#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <linux/user.h>

#ifdef HAVE_STDINT_H
#include <stdint.h>    /* C99 */
typedef uint8_t             u1;
typedef uint16_t            u2;
typedef uint32_t            u4;
typedef uint64_t            u8;
typedef int8_t              s1;
typedef int16_t             s2;
typedef int32_t             s4;
typedef int64_t             s8;
#else
typedef unsigned char       u1;
typedef unsigned short      u2;
typedef unsigned int        u4;
typedef unsigned long long  u8;
typedef signed char         s1;
typedef signed short        s2;
typedef signed int          s4;
typedef signed long long    s8;
#endif

/*
 * define kSHA1DigestLen
 */
enum { kSHA1DigestLen = 20,
       kSHA1DigestOutputLen = kSHA1DigestLen*2 +1 };

/*
 * define DexHeader
 */
typedef struct DexHeader {
    u1  magic[8];           /* includes version number */
    u4  checksum;           /* adler32 checksum */
    u1  signature[kSHA1DigestLen]; /* SHA-1 hash */
    u4  fileSize;           /* length of entire file */
    u4  headerSize;         /* offset to start of next section */
    u4  endianTag;
    u4  linkSize;
    u4  linkOff;
    u4  mapOff;
    u4  stringIdsSize;
    u4  stringIdsOff;
    u4  typeIdsSize;
    u4  typeIdsOff;
    u4  protoIdsSize;
    u4  protoIdsOff;
    u4  fieldIdsSize;
    u4  fieldIdsOff;
    u4  methodIdsSize;
    u4  methodIdsOff;
    u4  classDefsSize;
    u4  classDefsOff;
    u4  dataSize;
    u4  dataOff;
} DexHeader;

//#define ORIG_EAX 11
static const char* static_safe_location = "/data/local/tmp/";
static const char* suffix = "_dumped_";

typedef struct {
  uint32_t start;
  uint32_t end;
} memory_region;

uint32_t get_clone_pid(uint32_t service_pid);
uint32_t get_process_pid(const char* target_package_name);
char *determine_filter(uint32_t clone_pid, int memory_fd);
int find_magic_memory(uint32_t clone_pid, int memory_fd, memory_region *memory ,const char* file_name);
int peek_memory(int memory_file, uint32_t address);
int dump_memory(const char *buffer , int len , char each_filename[]);
int attach_get_memory(uint32_t pid);
