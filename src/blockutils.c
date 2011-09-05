#include <time.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <blkid/blkid.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "virt-backup.h"

#ifdef DEBUG
#define DPRINTF(fmt, ...) \
do { fprintf(stderr, "blockutils: " fmt , ## __VA_ARGS__); } while (0)
#else
#define DPRINTF(fmt, ...) \
do {} while(0)
#endif

char *getfstype(char *dev)
{
    blkid_cache cache = NULL;
    blkid_dev bdev;
    blkid_tag_iterate iter;
    const char *type, *value;
    char *ret = NULL;

    if (blkid_get_cache(&cache, NULL) != 0)
        return NULL;

    bdev = blkid_get_dev(cache, dev, BLKID_DEV_NORMAL);
    if (!bdev)
        return NULL;

    iter = blkid_tag_iterate_begin(bdev);
    while (blkid_tag_next(iter, &type, &value) == 0) {
        if (strcmp(type, "TYPE") == 0) {
            ret = (char *) malloc( strlen(value) * sizeof(char) );
            strcpy(ret, value);
            break;
        }
    }
    blkid_tag_iterate_end(iter);

    DPRINTF("Device %s fstype is %s\n", dev, ret);

    return ret;
}

int unmount_dev(char *dev)
{
    int res = -EBUSY, num = 0;
    DPRINTF("Unmounting %s\n", dev);
    while (res != 0) {
      num++;
      res = (umount(dev) == -1 ? -errno : 0);

      /* Set timeout to 10 seconds */
      if (num == 10) 
          break;

      sleep(1);
    }
    if (res == 0)
        rmdir(dev);
    DPRINTF("%s unmount result: %d (in %d sec)\n", dev, res, num);
    return res;
}

char *mount_dev(char *dev, char *fstype, int *error)
{
    time_t tm = time(NULL);
    char *tempdir;

    /* If no fstype is specified we try to get it */
    if (fstype == NULL)
        fstype = getfstype(dev);

    /* If still no fstype specified then the device probably doesn't exist */
    if (fstype == NULL) {
        if (error != NULL)
            *error = -ENOENT;

        return NULL;
    }

    tempdir = (char *)malloc( 1024 * sizeof(char) );
    snprintf(tempdir, 1024, "/tmp/%d-%s", (int)tm, fstype);
    mkdir(tempdir, 0755);
    DPRINTF("Mounting %s to %s\n", dev, tempdir);
    if (mount(dev, tempdir, fstype, MS_MGC_VAL, NULL) == -1) {
        int err = errno;
        DPRINTF("An error occured while mounting: %s\n", strerror(err));
        if (error != NULL)
            *error = -err;
        return NULL;
    }

   if (error != NULL)
        *error = 0;

    DPRINTF("Got temporary directory: %s\n", tempdir);
    return tempdir;
}

char *check_dev_mountpoint(char *dev)
{
    char tmp[4096], tmp2[512], mp[1024];
    char *ret = NULL;
    FILE *fp;

    if (access(dev, F_OK) != 0) {
        DPRINTF("Physical device %s doesn't exist\n", dev);
        return NULL;
    }

    fp = fopen("/etc/mtab", "r");
    if (fp == NULL) {
        DPRINTF("Cannot open /etc/mtab to check mounts\n");
        return NULL;
    }
    while (!feof(fp)) {
        if (fgets(tmp, 4096, fp) != NULL) {
            if (strstr(tmp, dev) != NULL) {
                snprintf(tmp2, 512, "%s %%s", dev);
                sscanf(tmp, tmp2, &mp);
                ret = (char *)malloc( strlen(mp) + 1 * sizeof(char) );
                strcpy(ret, mp);
                break;
            }
        }
    }
    fclose(fp);

    if (strlen(mp) > 0)
        DPRINTF("%s is mounted at %s\n", dev, mp);
    else {
        DPRINTF("%s is not mounted\n", dev);
        ret = NULL;
    }

    return ret;
}

unsigned long long getTotalSize(char *path)
{
    unsigned long long res;
    struct statvfs stat;

    statvfs(path, &stat);
    res = ((unsigned long long)stat.f_bsize * (unsigned long long)stat.f_blocks);

    DPRINTF("%s: block size=%lu, blocks total=%lu, size total=%llu KiB (%lld MiB)\n",
            path, stat.f_bsize, stat.f_blocks, res / 1024, res / 1048576);
    return res;
}

unsigned long long getVFSSize(char *dev)
{
    unsigned long long ret = 0;
    int err, do_unmount = 0;
    char *mp;

    if ((mp = check_dev_mountpoint(dev)) == NULL) {
        do_unmount = 1;
        mp = mount_dev(dev, NULL, &err);
        if (mp == NULL)
            return 0;
    }

    ret = getTotalSize(mp);

    /* Do not unmount if it was already mounted before */
    if (do_unmount)
        unmount_dev(mp);

    DPRINTF("Physical device %s size: %lld bytes\n", dev, ret);

    return ret;
}

