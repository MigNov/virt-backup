/* Uncomment to enable debugging messages from all source files */
//#define DEBUG_ALL

#define _XOPEN_SOURCE 500

#include <errno.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <getopt.h>
#include <dirent.h>
#include <inttypes.h>
#include <sys/types.h>
#include <string.h>
#include <pci/pci.h>
#include <time.h>

#ifdef DEBUG_ALL
#define DEBUG
#define DEBUG_AMD
#define DEBUG_COMMON
#define DEBUG_INTEL
#define DEBUG_PCI
#endif

/* MSR related stuff */
#define EMSROK                  0
#define EMSRNOCPU               1000
#define EMSRNOSUP               1001
#define EMSRNODATA              1002
#define EMSRNOPERM              1003
#define EMSRUERROR              1099

/* Intel related stuff */
#define IA32_THERM_STATUS       0x19c
#define IA32_PLATFORM_ID        0x17
#define IA32_TEMPERATURE_TARGET 0x1a2

/* AMD related PCI stuff */
#define AMD_PCI_VENDOR_ID               0x1022
#define AMD_PCI_NORTHBRIDGE_TEMP_REG    0xa4
#define AMD_PCI_REQUIRED_CLASS          PCI_CLASS_BRIDGE_HOST
#define AMD_PCI_REQUIRED_DEVFN          3

/* Function prototypes */
/* Common */
int CPUGetModel(int *bIntel);
int CPUGetCount();
int MSRRead(int cpu, uint32_t reg, uint64_t *value);
int CPUIDRead(unsigned int ax, unsigned int *p);
char *MSRGetError(int err);
/* PCI */
struct pci_dev **pci_getDeviceList(int *numDevices, int class, int vendor_id, int func);
/* CPU Types getTemp() prototypes */
int iAMDGetTempK10(int average);
int iIntelGetTemp(int average);
