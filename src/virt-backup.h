/* Libvirt's virGetBlockInfo API is supported since 0.8.1 AFAIK */
#define LIBVIR_MIN_BLOCKINFO_VER 8001

#ifndef COMPRESSION_LEVEL
  #define COMPRESSION_LEVEL 5
#endif

#ifndef BUFFER_SIZE
  #define BUFFER_SIZE 10485760 /* 10 MiB */
#endif

#define _LARGEFILE64_SOURCE

#include <errno.h>
#include <stdio.h>
#include <malloc.h>
#include <time.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <pwd.h>
#include <grp.h>
#include <libvirt/libvirt.h>
#include <libxml/parser.h>
#include <libxml/xpath.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/types.h>
#include <attr/xattr.h>
#include <getopt.h>

#undef HAVE_LZMA
#define HAVE_LZMA HAVE_LIBLZMA

#ifndef HOST_NAME_MAX
  #define HOST_NAME_MAX 255
#endif

#ifdef HAVE_SENSORS
#include "sensors.h"
#define LM_SENSORS_SYS_PATH "/sys/class/hwmon/"
#define TEMPDIV 1000 // The value is 1000x bigger than real value
#include <dirent.h>
#include <sys/types.h>
char *sensor_drv;
char *sensor_action;
#endif

#ifdef HAVE_LZMA
#include <lzma.h>
#else
#undef DEBUG_LZMA
#undef COMPRESSION_LEVEL
#endif

#if LIBVIR_VERSION_NUMBER >= LIBVIR_MIN_BLOCKINFO_VER
  #define LIBVIR_HAVE_BLOCKINFO
#endif

unsigned long flags;

#define FLAG_INCLUDE_ACTIVE 1
#define FLAG_USE_BLOCK_API  2
#define FLAG_SENSOR_ENABLE  4
#define FLAG_SENSOR_AVERAGE 8
#define FLAG_SENSOR_HAVEMAX 16
#define FLAG_NO_COMPRESS    32
#define FLAG_LOCAL          64
#define FLAG_DEBUG          128

#define MAX_TEMP_SHIFT      8

typedef struct tFiles {
	char *domain;
	char *type;
	char *name;
	unsigned long long size;
	char *selinux;
	char *ownership;
	char *compression;
} tFiles;
