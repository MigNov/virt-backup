bin_PROGRAMS = virt-backup
virt_backup_CFLAGS = -Wall
virt_backup_SOURCES = blockutils.c virt-backup.c sensors-common.c sensors-pci.c sensors-amd.c sensors-intel.c virt-backup.h sensors.h
if USE_PKGCONFIG
  virt_backup_CPPFLAGS = `@PKGCONFIG@ libxml-2.0 --cflags`
endif
