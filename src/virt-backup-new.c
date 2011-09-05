/* Those directives are passed to the compiler through the Makefile */
#define APPVERSION "0.0.2"
//#define DEBUG
//#define DEBUG_LZMA
//#define HAVE_LZMA
//#define HAVE_SENSORS

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#define STRMUS(a) (unsigned char *)a

#include "virt-backup.h"
#include <getopt.h>

#ifdef LIBVIR_HAVE_BLOCKINFO
int use_libvir_blockinfo_api = 1;
#endif

unsigned int gBufferSize = BUFFER_SIZE;
unsigned int gCompressionLevel = COMPRESSION_LEVEL;
unsigned long long getVFSSize(char *dev);
char *path, *uri, *action, *pathTo, *domains;

#ifdef DEBUG
#define DPRINTF(fmt, ...) \
do { fprintf(stderr, "debug: " fmt , ## __VA_ARGS__); } while (0)
  #ifdef DEBUG_LZMA
    #define DPRINTF_LZMA(fmt, ...) \
    do { fprintf(stderr, "LZMA debug: " fmt , ## __VA_ARGS__); } while (0)
  #else
    #define DPRINTF_LZMA(fmt, ...) \
    do {} while(0)
  #endif
#else
#define DPRINTF(fmt, ...) \
do {} while(0)
  #ifdef DEBUG_LZMA
    #define DPRINTF_LZMA(fmt, ...) \
    do { fprintf(stderr, "LZMA debug: " fmt , ## __VA_ARGS__); } while (0)
  #else
    #define DPRINTF_LZMA(fmt, ...) \
    do {} while(0)
  #endif
#endif

#ifdef HAVE_SENSORS
time_t old_time = 0;
time_t time_sec = 0;
#endif

typedef struct sfiles {
    char *domain;
    char *type;
    char *name;
    unsigned long long size;
    char *selinux;
    char *ownership;
    char *compression;
} sfiles;

unsigned long long physmem()
{
    unsigned long long ret = 0;
    const long pagesize = sysconf(_SC_PAGESIZE);
    const long pages = sysconf(_SC_PHYS_PAGES);

    if ( (pagesize != -1) || (pages != -1) )
       ret = (unsigned long long)(pagesize) * (unsigned long long)(pages);

    return ret;
}

int getFlagSet(unsigned long flags, int flag) {
    return (flags & flag) ? 1 : 0;
}

int getMaximumTemperature(unsigned long flags) {
    if (!getFlagSet(flags, FLAG_SENSOR_HAVEMAX))
        return 0;

    return flags >> MAX_TEMP_SHIFT;
}

void doSensorAction(char *sensor_action, int val, int elapsed) {
    char *tmp;

    if (sensor_action == NULL)
        return;

    tmp = strdup(sensor_action);
    if (strstr(tmp, ":") != NULL) {
        int i = 0;
        char *str1, *token;
        char *action = NULL, *params = NULL;

        for (str1 = tmp; ; str1 = NULL) {
           token = strtok(str1, ":");
           if (token == NULL)
               break;

           if (i++ == 0)
               action = token;
           else
               params = token;
        }

        if (flags & FLAG_DEBUG)
            printf("doSensorsAction: action = %s, params = %s\n", action, params);

        /* Builtin sleep command, syntax is "sleep:seconds" */
        if (strcmp(action, "sleep") == 0) {
            int val;
            char *endptr;

            errno = 0;
            val = strtol(params, &endptr, 10);
            if ((val > 0) && (errno == 0)) {
                if (flags & FLAG_DEBUG)
                    printf("Sleeping for %d seconds...\n", val);
                sleep( val );
            }
        }
        else
            fprintf(stderr, "Unsupported action '%s'\n", action);
    }
    else {
        /* Treat this as an executable */
        if (access(tmp, F_OK | X_OK) != 0)
            fprintf(stderr, "Command %s is not executable\n", tmp);
        else {
            char cmd[1024] = { 0 };
            snprintf(cmd, sizeof(cmd), "%s %d %d", tmp, val, elapsed);
            if (flags & FLAG_DEBUG)
                printf("Running '%s' ($1 = therm value, $2 = time elapsed since "
                       "last time therm value exceeded)\n", cmd);
            system(cmd);
        }
    }
}

unsigned int setMaximumTemperature(char *str) {
    int val;
    char *endptr;

    errno = 0;
    val = strtol(str, &endptr, 10);
    return ((val > 0) && (errno == 0)) ? FLAG_SENSOR_HAVEMAX | ( val << MAX_TEMP_SHIFT ) : 0;
}

int isLocalConnection(virConnectPtr cp)
{
    char local[HOST_NAME_MAX] = { 0 };

    DPRINTF("%s: Hostname: %s\n", __FUNCTION__, virConnectGetHostname(cp));
    gethostname(local, HOST_NAME_MAX);
    DPRINTF("%s: Localhost: %s\n", __FUNCTION__, local);

    return (strcmp(local, virConnectGetHostname(cp)) == 0);
}

char *getSELinuxPolicy(char *fileName)
{
    ssize_t xalen;
    char *value;
    int size = 255;

    value = (char *)malloc( size * sizeof(char) );
    xalen = lgetxattr (fileName, "security.selinux", value, size);
    if (xalen < 0)
        return NULL;
    value = realloc( value, xalen * sizeof(char) );
    return value;
}

int setSELinuxPolicy(char *fileName, char *value)
{
    ssize_t xalen;

    xalen = lsetxattr (fileName, "security.selinux", value, strlen(value), 0);
    if (xalen < 0)
        return errno;
    return 0;
}

char *getOwnership(char *fileName)
{
    char buf[1024] = { 0 }, *value;
    struct stat st;
    struct passwd *pw;
    struct group *gr;

    stat(fileName, &st);
    DPRINTF("Got ownership of %s: UID=%d, GID=%d\n", fileName, st.st_uid, st.st_gid);
    pw = getpwuid(st.st_uid);
    gr = getgrgid(st.st_gid);
    snprintf(buf, 1024, "%s:%s", pw->pw_name, gr->gr_name);
    DPRINTF("Owner: %s, group: %s\n", pw->pw_name, gr->gr_name);
    value = (char *)malloc( strlen(buf) + 1 * sizeof(char));
    strncpy(value, buf, strlen(buf));
    return value;
}

int setOwnership(char *fileName, char *value)
{
    int len, res;
    char *group, *user;
    struct passwd *pw;
    struct group *gr;

    group = strchr(value, ':') + 1;
    len = (strlen(value) - strlen(group)) - 1;
    user = (char *)malloc( (len + 1) * sizeof(char) );
    memset(user, 0, len+1);
    strncpy(user, value, len);

    pw = getpwnam(user);
    if (pw == NULL) {
        DPRINTF("Username doesn't exist on the system\n");
        return -EINVAL;
    }
    gr = getgrnam(group);
    if (gr == NULL) {
        DPRINTF("Group doesn't exist on the system\n");
        return -EINVAL;
    }
    DPRINTF("User %s UID is %d\n", user, pw->pw_uid);
    DPRINTF("Group %s GID is %d\n", group, gr->gr_gid);
    res = chown(fileName, pw->pw_uid, gr->gr_gid);
    if (res < 0)
        res = errno;

    DPRINTF("Chown(%s) result is %d (%s)\n", fileName, res, strerror(res));
    return res;
}

void timeVal(int val, char *buf)
{
    int size = 16;
    int h, m, s;

    if (val >= 3600) {
        h = val / 3600;
        val -= (h * 3600);
    } else
        h = 0;

    if (val >= 60) {
        m = val / 60;
        val -= (m * 60);
    } else
        m = 0;

    s = val;

    snprintf(buf, size, "%02d:%02d:%02d", h, m, s);
}

unsigned long long getFileSize(char *fileName)
{
    int fd;
    unsigned long long fileSize;

    fd = open(fileName, O_RDONLY | O_LARGEFILE);
    if (fd < 0) {
        DPRINTF("getFileSize: Error when opening %s for reading (%d)\n", fileName, errno);
        return 0;
    }
    fileSize = (unsigned long long)lseek64(fd, 0, SEEK_END);
    close(fd);

    return fileSize;
}

#ifdef HAVE_SENSORS
int read_sensors_directly(int average) {
    int bIntel;

    CPUGetModel(&bIntel);
    if (bIntel)
        return iIntelGetTemp(average);
    else
        return iAMDGetTempK10(average);
}

int get_sensor_reading(char *sensorName, int average)
{
    DIR *dir;
    struct dirent *ent;
    int fd, val, num, max = 0, count = 1024;
    char tmp[1024];

    if (strcmp(sensorName, "builtin") == 0) {
        val = read_sensors_directly(average);
        if (val < 0)
            DPRINTF("Invalid data using builtin therm monitor: %s\n", strerror(-val));
        else
            return val;
    }

    dir = opendir(LM_SENSORS_SYS_PATH);
    if (dir == NULL)
        return read_sensors_directly(average);
    val = 0;
    num = 0;
    while ((ent = readdir(dir)) != NULL) {
        if ((strlen(ent->d_name) > 0) && (ent->d_name[0] == '.'))
            continue;

        snprintf(tmp, count, "%s/%s/device/name", LM_SENSORS_SYS_PATH,
                              ent->d_name);

        fd = open(tmp, O_RDONLY);
        if (fd > 0) {
            memset(tmp, 0, count);
            read(fd, tmp, count);
            close(fd);

            if ((strlen(tmp) > 0) && (tmp[strlen(tmp) - 1] == '\n'))
                tmp[strlen(tmp) - 1] = 0;

            if (strcmp(tmp, sensorName) == 0) {
                snprintf(tmp, count, "%s%s/device/temp1_input", LM_SENSORS_SYS_PATH,
                                     ent->d_name);

                fd = open(tmp, O_RDONLY);
                if (fd > 0) {
                    memset(tmp, 0, count);
                    read(fd, tmp, count);
                    close(fd);

                    /* If we don't want average we get the highest temperature */
                    if (!average) {
                        
                        val = (atoi(tmp) / TEMPDIV);
                        if (val > max)
                            max = val;
                    }

                    val += (atoi(tmp) / TEMPDIV);
                    num++;
                }
            }
        }
    }

    /* Calculate average */
    if (average && num)
        val /= num;
    else
    if (!average)
        val = max;

    closedir(dir);
    return val;
}
#endif

#ifdef HAVE_LZMA
lzma_options_lzma *options(int preset, int extreme)
{
       uint32_t upreset = preset;

       if (extreme)
                upreset |= LZMA_PRESET_EXTREME;

       lzma_options_lzma *options = malloc(sizeof(lzma_options_lzma));
        *options = (lzma_options_lzma){
                .dict_size = LZMA_DICT_SIZE_DEFAULT,
                .preset_dict =  NULL,
                .preset_dict_size = 0,
                .lc = LZMA_LC_DEFAULT,
                .lp = LZMA_LP_DEFAULT,
                .pb = LZMA_PB_DEFAULT,
                .persistent = 0,
                .mode = LZMA_MODE_NORMAL,
                .nice_len = 64,
                .mf = LZMA_MF_BT4,
                .depth = 0,
        };
        if (lzma_lzma_preset(options, upreset)) {
                fprintf(stderr, "LZMA: Error in setting up preset\n");
                return NULL;
        }

        return options;
}

int xz_process_data(char *inputFile, char *outputFile, int decompress, unsigned int chunk_size, int overwrite)
{
    lzma_stream stream = LZMA_STREAM_INIT;
    lzma_ret ret;
    lzma_action action = LZMA_RUN;
    static lzma_filter filters[2];
    static uint8_t *in_buf, *out_buf;
    int retval = -1, i;
    float percent, old_percent;
    int in_fd, out_fd, num, end;
    unsigned long long fileSize, divisor;
    unsigned long long origSize, newSize;
    time_t startTime;
    char fsBuf[128], tStr[16];
    int transferred, one_percent;
    char sensorVal[32]; 
#ifdef HAVE_SENSORS
    int lastTemp, tmp;
#endif

    DPRINTF("xz_process_data('%s', '%s', %d, %d, %d) called\n", inputFile, outputFile,
             decompress, chunk_size, overwrite);

    if ((access(outputFile, F_OK) == 0) && (!overwrite)) {
        DPRINTF_LZMA("File %s exists and overwrite not enabled\n", outputFile);
        return 1;
    }

    in_buf = malloc( chunk_size * sizeof(uint8_t) );
    if (in_buf == NULL)
        return -ENOMEM;
    out_buf = malloc( chunk_size * sizeof(uint8_t) );
    if (out_buf == NULL) {
        free(in_buf);
        return -ENOMEM;
    }

    if (decompress)
        ret = lzma_stream_decoder(&stream, physmem() / 3,
                  LZMA_TELL_UNSUPPORTED_CHECK | LZMA_CONCATENATED);
    else {
        lzma_check check = LZMA_CHECK_CRC64;
        filters[0].id = LZMA_FILTER_LZMA2;
        filters[0].options = options(gCompressionLevel, 0);
        filters[1].id = LZMA_VLI_UNKNOWN;

        ret =  lzma_stream_encoder(&stream, filters, check);
    }

    if ( ret != LZMA_OK )
    {
        DPRINTF_LZMA("Failed to init lzma stream %scoder (%d)\n",
                          decompress ? "de" : "en", (int)ret);
	free(in_buf);
        free(out_buf);
        return -EIO;
    }

    in_fd = open(inputFile, O_RDONLY | O_LARGEFILE | O_SYNC);
    if (in_fd < 0) {
        free(in_buf);
        free(out_buf);
        return -EEXIST;
    }

    fileSize = (unsigned long long)lseek64(in_fd, 0, SEEK_END);
    lseek64(in_fd, 0, SEEK_SET);

    snprintf(fsBuf, 128, "%lld", fileSize);
    divisor = 1;
    if (strlen(fsBuf) > 5) {
        for (i = 5; i < strlen(fsBuf); i++)
            divisor *= 10;
    }

    fileSize /= divisor;

    out_fd = open(outputFile, O_WRONLY | O_LARGEFILE | O_CREAT
                  |  O_TRUNC | O_SYNC, 0644);
    if (out_fd < 0) {
        free(in_buf);
        free(out_buf);
        close(in_fd);
        return -EIO;
    }

    percent = old_percent = -1;

    end = 0;
    stream.next_in = in_buf;
    if ((num = read(in_fd, in_buf, chunk_size)) < 0)
        end = 1;
    DPRINTF_LZMA("Buffer size is: %d bytes\n", num);
    stream.avail_in = num;

    stream.next_out = out_buf;
    stream.avail_out = chunk_size;

    one_percent = (int)((unsigned long long)fileSize / 100);

#ifdef HAVE_SENSORS
    lastTemp = 0;
#endif
    startTime = time(NULL);
    for ( ; ; )
    {
        if ( (stream.avail_in == 0) || end )
        {
            if ((num = read(in_fd, in_buf, chunk_size)) <= 0) {
                DPRINTF_LZMA("Setting up end = 1\n");
                end = 1;
            }
            DPRINTF_LZMA("Read new stream: %d bytes\n", num);
            stream.next_in = in_buf;
            stream.avail_in = num;

            if (end)
                action = LZMA_FINISH;
        }
        ret = lzma_code(&stream, action);

        if ( stream.avail_out == 0 )
        {
            DPRINTF_LZMA("Flushing buffer: %d bytes\n", chunk_size - stream.avail_out);
            if (write(out_fd, out_buf, chunk_size - stream.avail_out) < 0)
               DPRINTF_LZMA("Error when writing: %d\n", errno);

            memset(out_buf, 0, chunk_size);
            stream.next_out = out_buf;
            stream.avail_out = chunk_size;
        }

        DPRINTF_LZMA("Total in: %lld, out: %lld\n", stream.total_in, stream.total_out);

        /* Calculate how much percent we have already done */
        transferred = (int)((unsigned long long)stream.total_in / divisor);
        percent = (float)(transferred / (float)one_percent);
        /* We won't allow percent be higher than 100 (may get higher when using big chunk_size) */
        if (percent > 100.00)
            percent = 100.00;

        /* Workaround but it's working and comparing as floats can't make it working */
        if (percent != old_percent) {
            unsigned long long rate, speed;

            rate = time(NULL) - startTime;
            if (rate < 1)
                rate = 1;
            speed = ((unsigned long long)stream.total_in / rate);
            if (speed == 0)
                speed = 1;

            timeVal(time(NULL) - startTime, tStr);

#ifdef HAVE_SENSORS
            if (sensor_drv != NULL)
                lastTemp = get_sensor_reading(sensor_drv, getFlagSet(flags, FLAG_SENSOR_AVERAGE));
            if (lastTemp > 0)
                snprintf(sensorVal, 32, ", temp = %d °C", lastTemp);
            else
                memset(sensorVal, 0, 32);
#else
            memset(sensorVal, 0, 32);
#endif

            printf("Processing %s -> %s: %3.2f%% (time = %s, speed = %llu KiB/s%s)\n", inputFile, outputFile,
                   percent, tStr, speed / 1024, sensorVal);

#ifdef HAVE_SENSORS
            tmp = getMaximumTemperature(flags);
            if ((tmp > 0) && (lastTemp > 0) && (lastTemp > tmp)) {
                   if (old_time > 0)
                       time_sec = time(NULL) - old_time;
                   old_time = time(NULL);
                   if (getFlagSet(flags, FLAG_DEBUG))
                       printf("Temperature: %d °C is higher than maximum allowed %d °C\n", lastTemp, tmp);
                   doSensorAction(sensor_action, lastTemp, (int)time_sec);
            }
#endif

            old_percent = percent;
        }

        DPRINTF_LZMA("Stream.avail_out: %d (ret = %d)\n", stream.avail_out, (int)ret);

        if (ret != LZMA_OK)
        {
             int stop = ret != LZMA_NO_CHECK
                        && ret != LZMA_UNSUPPORTED_CHECK;

             if (stop) {
                 DPRINTF_LZMA("Found a stop signature\n");
                 DPRINTF_LZMA("About to write %d bytes\n", chunk_size - stream.avail_out);
                 if (stream.avail_out < chunk_size)
                     DPRINTF_LZMA("Stream.avail_out: %d, IO_BUFFER_SIZE: %d\n",
                     stream.avail_out, chunk_size);
                 if (write(out_fd, out_buf, chunk_size - stream.avail_out) < 0)
                     DPRINTF_LZMA("Error when writing to output file: %d\n", errno);
                 retval = 0;
                 break;
             }

             if (ret == LZMA_STREAM_END) {
                if (stream.avail_in == 0 && !end) {
                     memset(in_buf, 0, chunk_size);
                     if ((num = read(in_fd, in_buf, chunk_size)) <= 0)
                        end = 1;
                     DPRINTF_LZMA("Read: %d bytes\n", num);
                     stream.next_in = in_buf;
                    stream.avail_in = num;
                }
             }
        }
   }

    free(in_buf);
    free(out_buf);
    close(out_fd);
    close(in_fd);
    lzma_end(&stream);

    origSize = getFileSize(inputFile);
    DPRINTF("%s size: %lld\n", inputFile, origSize);

    newSize = getFileSize(outputFile);
    /* This is most likely the physical device/partition */
    if (newSize < 0)
        newSize = getVFSSize(outputFile);

    DPRINTF("%s size: %lld\n", outputFile, newSize);
    percent = newSize / (float)(origSize / 100);
    DPRINTF("LZMA %scompression done, original size = %lld, newSize = %lld (%.2f%%)\n",
            decompress ? "de" : "", origSize, newSize, percent);

    return retval;
}

void write_header(int sock, unsigned char *header)
{
	char sz[64] = { 0 };

	snprintf(sz, sizeof(sz), "%ld-%s", strlen(header), header);
	write(sock, sz, strlen(sz));
}

void write_data(int sock, int size, unsigned char *data)
{
	char sz[64] = { 0 };

	snprintf(sz, sizeof(sz), "%"PRIi32, size);
	write(sock, sz, strlen(sz));
	write(sock, data, size);
}

void appendFile(char *fileName, unsigned char *buf, uint32_t len)
{
	int in_fd;

    in_fd = open(fileName, O_WRONLY | O_CREAT | O_LARGEFILE | O_APPEND, 0644);
    if (in_fd < 0)
        return;
	write(in_fd, buf, len);
	close(in_fd);
}

int xz_estimate_size(char *inputFile, uint32_t chunk_size)
{
	int MAX_FORKS = 10;
    lzma_stream stream = LZMA_STREAM_INIT;
    lzma_action action = LZMA_RUN;
    lzma_ret ret;
    static lzma_filter filters[2];
    static uint8_t *in_buf;
	static uint8_t *out_buf;
    int retval = -1, i;
	uint64_t fileSize;
	int in_fd, pfdR[MAX_FORKS][2], pfdW[MAX_FORKS][2];
	fd_set rfds;
	int nForks = 2;

	printf("xz_estimate_size('%s', 0x%"PRIx32") called\n", inputFile, chunk_size);

	unlink("/tmp/test.tmp");
    in_fd = open(inputFile, O_RDONLY | O_LARGEFILE | O_SYNC);
    if (in_fd < 0) {
        free(in_buf);
        free(out_buf);
        return -EEXIST;
    }

    fileSize = (uint64_t)lseek64(in_fd, 0, SEEK_END);
	close(in_fd);

	for (i = 0; i < nForks; i++) {
		if (pipe(pfdR[i]) == -1)
			fprintf(stderr, "ERROR IN PIPE 1\n");
		if (pipe(pfdW[i]) == -1)
			fprintf(stderr, "ERROR IN PIPE 2\n");
		/* We process everything in the child */
		if (fork() == 0) {
			fd_set rfds;
			char buf[64] = { 0 };
			char tmp[64] = { 0 };

			close(pfdR[0]);
			close(pfdW[1]);
			printf("[IN CHILD %d] %d: size = 0x%" PRIx64" bytes\n", i + 1, getpid(), fileSize);

			//if (i == 0)
			//	sleep(15);

			lzma_check check = LZMA_CHECK_CRC64;
			filters[0].id = LZMA_FILTER_LZMA2;
			filters[0].options = options(gCompressionLevel, 0);
			filters[1].id = LZMA_VLI_UNKNOWN;

			if (lzma_stream_encoder(&stream, filters, check) != LZMA_OK) {
				DPRINTF_LZMA("Failed to init LZMA stream encoder\n");
				snprintf(buf, sizeof(buf), "%dE", getpid());
				write(pfdR[i][1], buf, strlen(buf));
				_exit(1);
			}

			in_buf = malloc( chunk_size * sizeof(uint8_t) );
			if (in_buf == NULL) {
				snprintf(buf, sizeof(buf), "%dE", getpid());
				write(pfdR[i][1], buf, strlen(buf));
				_exit(2);
			}
			out_buf = malloc( chunk_size * sizeof(uint8_t) );
			if (out_buf == NULL) {
				free(in_buf);
				snprintf(buf, sizeof(buf), "%dE", getpid());
				write(pfdR[i][1], buf, strlen(buf));
				_exit(3);
			}

			snprintf(buf, sizeof(buf), "%dW", getpid());
			write(pfdR[i][1], buf, strlen(buf));

			int len = -1, state = -1, dpid = -1, header_size = -1;
			while ((len = read(pfdW[i][0], buf, sizeof(buf))) > 0) {
				printf("[IN CHILD %d] BUF: %s\n", i+1, buf);

				header_size = atoi(buf) + 1;
				state = buf[ header_size ];
				memcpy(tmp, buf + 2, header_size - 2);
				dpid = atoi(tmp);
				printf("[IN CHILD %d] STATE: %c, dpid = %d, my pid = %d\n", i+1, state, dpid, getpid());

				if (dpid == getpid()) {
					if (state == 'Q') {
						snprintf(buf, sizeof(buf), "%dQ", getpid());
						write(pfdR[i][1], buf, strlen(buf));
						break;
					}

					if (state == 'R') {
						unsigned char *cBuf = NULL;
						unsigned long size, cLen;
						memcpy(tmp, buf + header_size + 1, sizeof(tmp));
						size = atoi(tmp);
						snprintf(tmp, sizeof(tmp), "%d", size);
						cBuf = (unsigned char *)malloc( size * sizeof(unsigned char) );
						memset(cBuf, 0, size * sizeof(unsigned char) );
						memcpy(cBuf, buf + header_size + 1 + strlen(tmp), size);
						cBuf[ len - (header_size + 1 + strlen(tmp)) ] = 'A';
						cLen = len - (header_size + 1 + strlen(tmp));
						cLen += read(pfdW[i][0], cBuf + cLen, size - cLen);
						appendFile("/tmp/test.tmp", cBuf, cLen);
						printf("\n\n[IN CHILD %d] DATA (%d): %s\n\n", i+1, cLen, cBuf);
						snprintf(buf, sizeof(buf), "%dD", getpid());
						write(pfdR[i][1], buf, strlen(buf));
					}
				}
			}

			close(pfdW[i][1]);

			free(out_buf);
			free(in_buf);
			_exit(0);
		}
	}

	FD_ZERO(&rfds);
	for (i = 0; i < nForks; i++)
		FD_SET(pfdR[i][0], &rfds);
	char buf[32] = { 0 }, tmp[32] = { 0 }, a[2] = { 0 };
	int len = -1, done = 0, cpid = -1, state = -1, num = -1, pp[2];
	unsigned char rbuf[1 << 10];

    in_fd = open(inputFile, O_RDONLY | O_LARGEFILE | O_SYNC);
    if (in_fd < 0)
        return -EIO;

	while (select(pfdR[nForks-1][0] + 1, &rfds, NULL, NULL, NULL) != -1) {
		for (i = 0; i < nForks; i++) {
			if (FD_ISSET(pfdR[i][0], &rfds)) {
				pp[0] = pfdR[i][0];
				pp[1] = pfdW[i][1];
				break;
			}
		}
		if ((len = read(pp[0], buf, sizeof(buf))) > 0) {
			state = buf[len - 1];
			memcpy(tmp, buf, len - 1);
			cpid = atoi(tmp);
			printf("[IN PARENT] CHILD %d IS HAVING STATE '%c'\n", cpid, state);
			printf("[IN PARENT] BUF: '%s' ([PARENT PID = %d)\n", buf, getpid());

			if (state == 'D') {
				if ((uint64_t) lseek64(in_fd, 0, SEEK_CUR) >= fileSize) {
					snprintf(tmp, sizeof(tmp), "%dQ", cpid);
					write_header(pp[1], tmp);
				}
				else
					state = 'W';
			}
			if (state == 'W') {
				snprintf(tmp, sizeof(tmp), "%dR", cpid);
				write_header(pp[1], tmp);
				num = read(in_fd, rbuf, 1 << 10);
				if (num > 0)
					write_data(pp[1], num, rbuf);
			}
			if ((state == 'Q') || (state == 'E'))
				done++;

			if (done == nForks) /* Number of forks */
				break;
		}
	}

	close(in_fd);

	int status;
	wait(&status);

	printf("WAITING DONE: %d\n", WEXITSTATUS(status));
	return retval;
}
#endif

char *replace(char *str, char *what, char *with)
{
    int size, idx;
    char *new, *part, *old;

    DPRINTF("About to replace %d bytes with %d bytes\n", strlen(what), strlen(with));
    DPRINTF("Original string at %p (%d bytes)\n", str, strlen(str));
    part = strstr(str, what);
    if (part == NULL)
    {
        DPRINTF("Cannot find partial token (%s)\n", what);
        return str;
    }
    DPRINTF("Have first part at %p, %d bytes\n", part, strlen(part));

    size = strlen(str) - strlen(what) + strlen(with);
    new = (char *)malloc( size * sizeof(char) );
    DPRINTF("New string size allocated to %d bytes\n", size);
    old = strdup(str);
    DPRINTF("Duplicated string str at %p to old at %p\n", str, old);
    idx = strlen(str) - strlen(part);
    DPRINTF("Setting idx %d of old at %p to 0\n", idx, old);
    old[idx] = 0;
    DPRINTF("Old string (%p) idx %d set to 0\n", old, idx);
    strcpy(new, old);
    strcat(new, with);
    strcat(new, part + strlen(what) );
    DPRINTF("About to return new at %p\n", new);
    free(old);
    DPRINTF("Part and old freed\n");
    return new;
}

unsigned long long getFreeSpace(char *path)
{
    unsigned long long res;
    struct statvfs stat;

    statvfs(path, &stat);
    res = ((unsigned long long)stat.f_bsize * (unsigned long long)stat.f_bavail);

    DPRINTF("%s: block size=%lu, blocks avail=%lu, size avail=%llu KiB\n",
            path, stat.f_bsize, stat.f_bavail, res / 1024);
    return res;
}

unsigned long long getBlockInfo(virDomainPtr dp, char *path, int isFile)
{
    DPRINTF("Entering getBlockInfo(%s)\n", path);

#ifndef LIBVIR_HAVE_BLOCKINFO
        /* Only version 0.8.1 and above support virDomainGetBlockInfo API */
        DPRINTF("virDomainGetBlockInfo not supported by this version of libvirt.\n");

        if (isFile) {
            DPRINTF("Using getFileSize() instead...\n");
            return getFileSize(path);
        }
        else {
            DPRINTF("Block device found, checking VFS size ...\n");
            return getVFSSize(path);
        }
#else
    if (use_libvir_blockinfo_api) {
        virDomainBlockInfo bip;
        unsigned long long phys;

        DPRINTF("Got block device path: %s (%s)\n", path, isFile ? "file" : "block");
        if (virDomainGetBlockInfo(dp, path, &bip, 0) == 0) {
            DPRINTF("Capacity: %llu MiB\n", bip.capacity / 1048576);
            DPRINTF("Allocation: %llu MiB\n", bip.allocation / 1048576);
            DPRINTF("Physical: %llu MiB\n", bip.physical / 1048576);
            phys = bip.physical;
        }

        return phys;
    }
    else {
        DPRINTF("virDomainGetBlockInfo API usage not enabled.\n");

        if (isFile) {
            DPRINTF("Using getFileSize() instead...\n");
            return getFileSize(path);
        }
        else {
            DPRINTF("Block device found, checking VFS size ...\n");
            return getVFSSize(path);
        }
    }
#endif
    /* Should never go there */
    return -EINVAL;
}

int copyFile(char *src, char *dst, int chunk_size, int overwrite)
{
    unsigned char *buf;
    int rd, fd1, fd2, percent, oldpercent = -1;
    unsigned long long fileSize = 0, writtenSize = 0, rate;
    time_t startTime;

    DPRINTF("copyFile('%s', '%s', %d, %d) called\n", src, dst, chunk_size, overwrite);

    if ((access(dst, F_OK) == 0) && (!overwrite)) {
        DPRINTF("File %s exists and overwrite not enabled\n", dst);
        return 1;
    }

    fd1 = open(src, O_RDONLY | O_LARGEFILE);
    if (fd1 < 0) {
        DPRINTF("Error when opening %s for reading (%d)\n", src, errno);
        return -EIO;
    }
    fileSize = (unsigned long long)lseek64(fd1, 0, SEEK_END);
    lseek64(fd1, 0, SEEK_SET);
    DPRINTF("File %s opened for reading (%lld KiB)\n", src, fileSize / 1024);
    fd2 = open(dst, O_WRONLY | O_CREAT | O_LARGEFILE | O_SYNC | O_TRUNC, 0644);
    if (fd2 < 0) {
        DPRINTF("Error when opening %s for writing (%d)\n", dst, errno);
        return -EIO;
    }
    DPRINTF("File %s opened for writing\n", dst);

    startTime = time(NULL);

    buf = malloc( chunk_size * sizeof(unsigned char) );
    while  ((rd = read(fd1, buf, chunk_size)) == chunk_size) {
        if (write(fd2, buf, rd) < 0)
             DPRINTF("Error when copying file: %d\n", errno);
        writtenSize += rd;
        //DPRINTF("WrittenSize: %lld, totalSize: %lld\n", writtenSize, fileSize);
        percent = (int)((unsigned long long)writtenSize / ((unsigned long long)fileSize / 100));
        if ((percent != oldpercent)/* && (percent % 5 == 0)*/) {
            unsigned long long speed, eTime;

            rate = time(NULL) - startTime;
            if (rate < 1)
                rate = 1;
            speed = ((unsigned long long)writtenSize / rate);
            if (speed == 0)
                speed = 1;
            eTime = (unsigned long long)(fileSize - writtenSize);
            if (eTime == 0)
                eTime = 1;

            eTime /= (unsigned long long)speed;
            DPRINTF("Copied %02d%% at %lld KiB/s, ETA: %lld sec\n", percent,
                    speed / 1024, eTime);
            oldpercent = percent;
        }

        if (writtenSize > fileSize) break;
    }

    if ((rd > 0) && (writtenSize < fileSize))
        if (write(fd2, buf, rd) < 0)
           DPRINTF("Error when copying file: %d\n", errno);

    DPRINTF("Write done\n");
    free(buf);
    DPRINTF("Buffer freed\n");

    close(fd2);
    close(fd1);
    rate = time(NULL) - startTime;
    if (rate < 1)
        rate = 1;
    rate /= 1024;
    if (rate < 1)
        rate = 1;
    DPRINTF("Finished in %d seconds\n", (int)(time(NULL) - startTime));
    DPRINTF("Average data copy rate: %llu KiB\n", (unsigned long long)fileSize
            / rate);

    return 0;
}

struct sfiles *getRestoreXml(char *xmlFile, int *numFiles)
{
    xmlDocPtr doc;
    xmlNodePtr cur, cur2;
    int num = -1;
    xmlChar *key;
    struct sfiles *files;
    char compression[16];

    doc = xmlParseFile(xmlFile);
    if (doc == NULL ) {
        fprintf(stderr,"Document not parsed successfully. \n");
        return NULL;
    }

    cur = xmlDocGetRootElement(doc);	
    if (cur == NULL) {
        fprintf(stderr,"empty document\n");
        xmlFreeDoc(doc);
        return NULL;
    }
	
    if (xmlStrcmp(cur->name, (const xmlChar *) "files")) {
        fprintf(stderr,"document of the wrong type, root node != files\n");
        xmlFreeDoc(doc);
        return NULL;
    }

    strncpy(compression, (const char *)xmlGetProp(cur, STRMUS("compression")), 16);

    files = malloc ( sizeof(struct sfiles) );
    if (!files)
        return NULL;

    cur = cur->xmlChildrenNode;
    while (cur != NULL) {
        if ((!xmlStrcmp(cur->name, (const xmlChar *)"file"))) {
            cur2 = cur->xmlChildrenNode;
            while (cur2 != NULL) {
                if ((xmlStrcmp(cur2->name, (const xmlChar *)"text"))) {
                    key = xmlNodeListGetString(doc, cur2->xmlChildrenNode, 1);

                    if ((!xmlStrcmp(cur2->name, (const xmlChar *)"domain")))
                        files[num].domain = strdup( (char *)key );
                    if ((!xmlStrcmp(cur2->name, (const xmlChar *)"type")))
                        files[num].type = strdup( (char *)key );
                    if ((!xmlStrcmp(cur2->name, (const xmlChar *)"name"))) 
                        files[num].name = strdup( (char *)key );
                    if ((!xmlStrcmp(cur2->name, (const xmlChar *)"size"))) {
                        char *endptr;
                        files[num].size = strtoull( (char *)key, &endptr, 10);
                    }
                    if ((!xmlStrcmp(cur2->name, (const xmlChar *)"ownership")))
                        files[num].ownership = strdup( (char *)key );
                    if ((!xmlStrcmp(cur2->name, (const xmlChar *)"selinux")))
                        files[num].selinux = strdup( (char *)key );

                    xmlFree(key);
                }
                cur2 = cur2->next;
            }
 	}
        else {

            /* Append the compression data */
            if (num >= 0)
                files[num].compression = strdup(compression);

            num++;
            files = realloc( files, (num+1) * sizeof(sfiles) );
        }

	cur = cur->next;
    }

    if (numFiles != NULL)
       *numFiles = num;

    xmlFreeDoc(doc);
    return files;
}

int dumpBlockDevices(virDomainPtr dp, int inactive, unsigned long long *tSize, char *savePath, int compress)
{
    xmlParserCtxtPtr xp;
    xmlDocPtr doc;
    xmlXPathContextPtr context;
    xmlXPathObjectPtr result;
    xmlNodeSetPtr nodeset;
    unsigned long long size = 0, sFree = 0, mSize = 0, decSize = 0;
    int flags = (inactive) ? VIR_DOMAIN_XML_INACTIVE : 0;
    char *xml = NULL, *file = NULL, **imageFiles = NULL, tmpFile[1024] = { 0 };
    int i, numFiles = 0, sizeDivisor = 0, startIdx = 0, *isFile = NULL;
    FILE *fp;

    xml = virDomainGetXMLDesc(dp, flags);

    xp = xmlCreateDocParserCtxt( (xmlChar *)xml );
    if (!xp) {
        DPRINTF("Cannot create DocParserCtxt\n");
        return -ENOMEM;
    }
    doc = xmlCtxtReadDoc(xp, (xmlChar *)xml, NULL, NULL, 0);
    if (!doc) {
        DPRINTF("Cannot get xmlDocPtr\n");
        return -ENOMEM;
    }

    context = xmlXPathNewContext(doc);
    if (!context) {
        printf("Cannot get new XPath context\n");
        return -ENOMEM;
    }

    /* Find devices backed up by the image files */
    result = xmlXPathEvalExpression( (xmlChar *)"//domain/devices/disk/source/@file", context);
    if (!result) {
        xmlXPathFreeContext(context);
        printf("Cannot evaluate expression\n");
        goto out_phys;
    }
    if(xmlXPathNodeSetIsEmpty(result->nodesetval)){
        xmlXPathFreeObject(result);
        xmlXPathFreeContext(context);
        DPRINTF("No backing file for %s\n", virDomainGetName(dp));
        goto out_phys;
    }
    nodeset = result->nodesetval;
    numFiles = nodeset->nodeNr;
    imageFiles = (char **)malloc( numFiles * sizeof(char *) );
    isFile = (int *)malloc( numFiles * sizeof(int) );
    for (i = 0; i < nodeset->nodeNr; i++) {
        file = (char *)xmlNodeListGetString(doc, nodeset->nodeTab[i]->xmlChildrenNode, 1);
        mSize = getBlockInfo(dp, file, 1);
        if (mSize <= 0) continue;
        DPRINTF("Image file %s size: %lld bytes / %lld MiB\n", file, mSize, mSize / 1048576);
        imageFiles[i] = (char *)malloc( strlen(file) + 1 * sizeof(char) );
        memset(imageFiles[i], 0, strlen(file) + 1);
        isFile[i] = 1;
        strcpy(imageFiles[i], file);
        free(file);
        size += mSize;
    }

out_phys:
    xmlXPathFreeObject(result);

    /* Find devices backed up by the physical devices but only if user's using root account */
    if (getuid() == 0) {
        result = xmlXPathEvalExpression( (xmlChar *)"//domain/devices/disk/source/@dev", context);
        if (!result) {
            xmlXPathFreeContext(context);
            printf("Cannot evaluate expression\n");
            goto out;
        }
        if(xmlXPathNodeSetIsEmpty(result->nodesetval)){
            xmlXPathFreeObject(result);
            xmlXPathFreeContext(context);
            DPRINTF("No physical device for %s\n", virDomainGetName(dp));
            goto out;
        }
        nodeset = result->nodesetval;

        /* If imageFiles is not allocated yet, i.e. the domain was not having any image file
           storage we have to allocate the image structure otherwise we need to reallocate */
        if (imageFiles == NULL) {
            startIdx = 0;
            numFiles = nodeset->nodeNr;
            imageFiles = (char **)malloc( numFiles * sizeof(char *) );
            isFile = (int *)malloc( numFiles * sizeof(int) );
        }
        else {
            startIdx = numFiles;
            numFiles += nodeset->nodeNr;
            imageFiles = (char **)realloc( imageFiles, numFiles * sizeof(char *) );
            isFile = (int *)realloc( isFile, numFiles * sizeof(int) );
        }

        for (i = startIdx; i < numFiles; i++) {
            file = (char *)xmlNodeListGetString(doc, nodeset->nodeTab[i-startIdx]->xmlChildrenNode, 1);
            mSize = getBlockInfo(dp, file, 0);
            if (mSize <= 0) continue;
            DPRINTF("Device %s size: %lld bytes / %lld MiB\n", file, mSize, mSize / 1048576);
            imageFiles[i] = (char *)malloc( strlen(file) + 1 * sizeof(char) );
            memset(imageFiles[i], 0, strlen(file) + 1);
            isFile[i] = 0;
            strcpy(imageFiles[i], file);
            free(file);
            size += mSize;
        }
        xmlXPathFreeObject(result);
    }

    xmlFreeDoc(doc);
    xmlCleanupParser();
out:
    if (tSize != NULL)
        *tSize = size;

    for (i = 0; i < numFiles; i++) {
        if (!imageFiles[i] || !strlen(imageFiles[i]))
            continue;

        char *fileName;
        fileName = strrchr(imageFiles[i], '/') + 1;

        snprintf(tmpFile, 1024, "%s/%s", savePath, fileName);
        if (access(tmpFile, F_OK) == 0)
        {
            mSize = getFileSize(tmpFile);
            DPRINTF("File already exists: %s (%llu KiB)\n", tmpFile, mSize / 1024);
            decSize += mSize;
        }
    }

#ifndef HAVE_LZMA
    if (compress) {
        compress = 0;
        fprintf(stderr, "No LZMA support compiled. Compress not available.\n");
    }
#endif

#ifdef HAVE_LZMA
    if (compress == 1)
        /* TODO: Implement some proper calculations instead of guessing */
        sizeDivisor = gCompressionLevel / 2;
    else
#endif
        sizeDivisor = 1;

    /* Check size with decremented size of existing images against the amount of free space */
    if ((sFree = getFreeSpace(savePath)) < ((size / sizeDivisor) - decSize))
    {
        DPRINTF("Not enough space to save image(s) for %s\n", virDomainGetName(dp) );
        DPRINTF("Free space on %s device: %llu KiB\n", savePath, sFree / 1024);
        DPRINTF("Total size of images for %s: %llu KiB\n", virDomainGetName(dp), size / 1024);
        DPRINTF("  %llu more KiB(s) are needed to backup %s\n", (size - sFree) / 1024,
                virDomainGetName(dp) );
        return -ENOSPC;
    }

    snprintf(tmpFile, 1024, "%s/original-files.xml", savePath);
    fp = fopen(tmpFile, "a");
    for (i = 0; i < numFiles; i++)
    {
        if (!imageFiles[i] || !strlen(imageFiles[i]))
            continue;

        char *fileName, *filePath;
        fileName = strrchr(imageFiles[i], '/') + 1;
        filePath = strdup(imageFiles[i]);
        filePath[strlen(filePath) - strlen(fileName) - 1] = 0;

        DPRINTF("Processing %s ...\n", imageFiles[i]);

        fprintf(fp, " <file>\n");
        fprintf(fp, "  <domain>%s</domain>\n", virDomainGetName(dp));
        fprintf(fp, "  <type>%s</type>\n", isFile[i] ? "file" : "block");
        fprintf(fp, "  <name>%s</name>\n", isFile[i] ? fileName : imageFiles[i]);
        fprintf(fp, "  <size>%lld</size>\n", isFile[i] ?
                    getFileSize(imageFiles[i]) : getVFSSize(imageFiles[i]));
        fprintf(fp, "  <ownership>%s</ownership>\n", getOwnership(imageFiles[i]));
        fprintf(fp, "  <selinux>%s</selinux>\n", getSELinuxPolicy(imageFiles[i]));
        fprintf(fp, " </file>\n");

        snprintf(tmpFile, 1024, "%s/%s", savePath, fileName);
        if (!compress) {
            DPRINTF("Copying %s to %s ...\n", imageFiles[i], tmpFile);
            if (copyFile(imageFiles[i], tmpFile, gBufferSize, 1) < 0)
                DPRINTF("Error when copying %s to %s\n", imageFiles[i], tmpFile);
            DPRINTF("copyFile done\n");
        }
        #ifdef HAVE_LZMA
        else if (compress == 1) {
            DPRINTF("Compressing %s to %s ...\n", imageFiles[i], tmpFile);
            if (xz_process_data(imageFiles[i], tmpFile, 0, gBufferSize, 1) < 0)
                DPRINTF("Error when processing compression\n");
            DPRINTF("Compression done\n");
        }
        #endif
        else {
            DPRINTF("Error: Unsupported option (bug)\n");
            return -ENOTSUP;
        }

        if (isFile[i]) {
            snprintf(tmpFile, 1024, "%%PATH%%/%s", fileName);
            xml = replace(xml, imageFiles[i], tmpFile);
            free(imageFiles[i]);
        }
    }
    fclose(fp);

    snprintf(tmpFile, 1024, "%s/%s.xml", savePath, virDomainGetName(dp));
    DPRINTF("Saving XML to %s\n", tmpFile);

    fp = fopen(tmpFile, "w");
    if (!fp)
       return -EIO;

    fprintf(fp, "%s", xml);
    fclose(fp);

    return 0;
}

void getDomainFiles(virConnectPtr cp, int maxActive, int maxInactive, char *savePath, int compress, char *domains)
{
    int i;
    int *idsA;
    char **names;
    virDomainPtr dp;
    unsigned long long size;
    FILE *fp;
    char tmpFile[1024];

    snprintf(tmpFile, 1024, "%s/original-files.xml", savePath);
    fp = fopen(tmpFile, "w");
    fprintf(fp, "<files compression=\"%s\">\n", compress ? "lzma" : "none");
    fclose(fp);

    if (maxActive > 0) {
        idsA = malloc( maxActive * sizeof(int) );
        if ((maxActive = virConnectListDomains(cp, &idsA[0], maxActive)) < 0) {
            free(idsA);
            DPRINTF("Failed when getting active domains list\n");
        }
        else
        for (i = 0; i < maxActive; i++) {
            dp = virDomainLookupByID(cp, idsA[i]);
            if (dp) {
                DPRINTF("Got domain %s (ID = %d)\n", virDomainGetName(dp), idsA[i]);
                size = 0;
                dumpBlockDevices(dp, 0, &size, savePath, compress);
                DPRINTF("Total size for %s: %llu KiB\n", virDomainGetName(dp), size / 1024);
                virDomainFree(dp);
            }
        }
        free(idsA);
    }

    if (maxInactive > 0) {
        if (domains == NULL) {
            names = malloc( maxInactive * sizeof(char *) );
            if ((maxInactive = virConnectListDefinedDomains(cp, names, maxInactive)) < 0) {
                free(names);
                DPRINTF("Failed when getting inactive domain list\n");
            }
        }
        else {
            char *saveptr1, *token, *str1;
            int i;

            DPRINTF("Domains list defined: %s\n", domains);

            names = malloc( sizeof(char *) );
            for (i = 1, str1 = domains; ; i++, str1 = NULL) {
               token = strtok_r(str1, ",", &saveptr1);
               if (token == NULL)
                   break;
               names = realloc( names, i * sizeof(char *));
               names[i - 1] = malloc( strlen(token) * sizeof(char) );
               strcpy(names[i - 1], token);
            }
            maxInactive = i - 1;
        }
        for (i = 0; i < maxInactive; i++) {
            dp = virDomainLookupByName(cp, names[i]);
            if (dp) {
                DPRINTF("Got domain %s\n", virDomainGetName(dp));
                size = 0;
                dumpBlockDevices(dp, 1, &size, savePath, compress);
                DPRINTF("Total size for %s: %llu KiB\n", virDomainGetName(dp), size / 1024);
                virDomainFree(dp);
            }
        }
        free(names);
    }

    fp = fopen(tmpFile, "a");
    fprintf(fp, "</files>\n");
    fclose(fp);
}

int restoreStorageImages(char *pathFrom, char *pathTo, struct sfiles *files, int from, int to)
{
    int i, idx = 0;
    unsigned long long avail;
    char xpathFrom[1024];
    char xpathTo[1024];

    DPRINTF("Restoring storage images (%d - %d)\n", from, to);
    for (i = from; i < to; i++) {
        if (strcmp(files[i].type, "file") == 0) {
            DPRINTF("File %s is being restored, compression used: %s\n", files[i].name, files[i].compression);

            snprintf(xpathFrom, 1024, "%s/%s", pathFrom, files[i].name);
            snprintf(xpathTo, 1024, "%s/%s", pathTo, files[i].name);
        }
        else
        if (strcmp(files[i].type, "block") == 0) {
            if (getuid() == 0) {
                char *fileName;
                fileName = strrchr(files[i].name, '/') + 1;

                DPRINTF("Physical device %s is being restored, compression used: %s\n", files[i].name,
                        files[i].compression);

                if ((avail = getVFSSize(files[i].name)) < files[i].size) {
                    fprintf(stderr, "Physical device %s doesn't have enough space to be restored.\nSpace "
                            "required: %lld MiB, space available: %lld MiB. space missing: %lld KiB\n",
                            files[i].name, files[i].size / 1048576, avail / 1048576,
                            (files[i].size - avail) / 1024);
                    idx = i;
                    goto out;
                }

                snprintf(xpathFrom, 1024, "%s/%s", pathFrom, fileName);
                snprintf(xpathTo, 1024, "%s", files[i].name);
            }
            else {
                DPRINTF("Physical device %s restore requested but used is not root. Terminating ...\n",
                        files[i].name);

                idx = i;
                goto out;
            }
        }
        else {
            fprintf(stderr, "Error: Unknown storage type (%s)\n", files[i].type);

            idx = i;
            goto out;
        }

        if (strcmp(files[i].compression, "lzma") == 0) {
#ifndef HAVE_LZMA
            DPRINTF("LZMA support is not compiled. Cannot restore storage images\n");
#else
            xz_process_data(xpathFrom, xpathTo, 1, gBufferSize, 1);
#endif
        }
        else {
            copyFile(xpathFrom, xpathTo, gBufferSize, 1);
        }

        setSELinuxPolicy(xpathTo, files[i].selinux);
        setOwnership(xpathTo, files[i].ownership);

        DPRINTF("Done for %s [destination: %s]\n", xpathFrom, xpathTo);
    }

out:
    /* If it failed we need to do cleanup */
    if (idx > 0) {
        for (i = from; i < idx; i++) {
            if (strcmp(files[i].type, "file") == 0) {
                snprintf(xpathTo, 1024, "%s/%s", pathTo, files[i].name);
                if (access(xpathTo, F_OK) == 0) {
                    DPRINTF("Cleaning up %s...\n", xpathTo);
                    unlink(xpathTo);
                }
            }
        }
    }

    return (idx == 0);
}

int restoreGuests(virConnectPtr cp, char *pathFrom, char *path, struct sfiles *files, int num)
{
    int i, from, to;
    unsigned long long spaceRequired = 0;
    unsigned long long sFree;
    char *domainName = "", xmlFile[1024];

    from = 0;
    for (i = 0; i < num; i++) {
        if (strcmp(domainName, files[i].domain) != 0) {
            /* If domain name is not set we use current instead */
            if (strlen(domainName) == 0)
                domainName = files[i].domain;

            to = i;
            if (from != to) {
                DPRINTF("Size of %s's images: %lld MiB\n", domainName, spaceRequired / 1048576);
                DPRINTF("Got new domain: %s (images %d-%d)\n", files[i].domain, from, to);
                if ((sFree = getFreeSpace(path)) < spaceRequired) {
                    DPRINTF("Not enough space to restore images for %s on %s\n", domainName, path);
                }
                else {
                    DPRINTF("Space check OK\n");

                    if (restoreStorageImages(pathFrom, path, files, from, to) == 0) {
                        /* Restoring storage images failed, skip it */
                        continue;
                    }
                    snprintf(xmlFile, 1024, "%s/%s.xml", pathFrom, domainName);
                    if (access(xmlFile, F_OK) != 0)
                        fprintf(stderr, "Cannot open libvirt XML definition file (%s)\n", xmlFile);
                    else {
                        int fd, size;
                        char *buf;

                        DPRINTF("Using libvirt XML definition file: %s\n", xmlFile);
                        size = getFileSize(xmlFile);
                        buf = (char *)malloc( size * sizeof(char) );
                        fd = open(xmlFile, O_RDONLY);
                        if (read(fd, buf, size) < 0)
                            DPRINTF("Read error in %s: %d\n", __FUNCTION__, errno);
                        close(fd);

                        virDomainDefineXML(cp, buf);
                        free(buf);
                    }
                    domainName = files[i].domain;
                    spaceRequired = 0;
                }
            }
            from = i;
        }
        if (strcmp(files[i].type, "file") == 0)
            spaceRequired += files[i].size;
        else
        if (strcmp(files[i].type, "block") != 0)
            fprintf(stderr, "Error: Unknown storage type (%s)\n", files[i].type);
    }
    domainName = strlen(domainName) > 0 ? domainName : files[0].domain;
    DPRINTF("Size of %s's images: %lld MiB\n", domainName, spaceRequired / 1048576);
    if ((sFree = getFreeSpace(path)) < spaceRequired) {
        DPRINTF("Not enough space to restore images for %s on %s\n", domainName, path);
    }
    else {
        DPRINTF("Space check OK for last domain\n");
        if (restoreStorageImages(pathFrom, path, files, from, i) == 0) {
            /* Restoring storage images failed, skip it */
            goto out;
        }
        snprintf(xmlFile, 1024, "%s/%s.xml", pathFrom, domainName);
        if (access(xmlFile, F_OK) != 0)
            fprintf(stderr, "Cannot open libvirt XML definition file (%s)\n", xmlFile);
        else {
            int fd, size;
            char *buf;

            DPRINTF("Using libvirt XML definition file: %s\n", xmlFile);
            size = getFileSize(xmlFile);
            buf = (char *)malloc( size * sizeof(char) );
            fd = open(xmlFile, O_RDONLY);
            if (read(fd, buf, size) < 0)
                DPRINTF("Read error in %s: %d\n", __FUNCTION__, errno);
            close(fd);

            buf = replace(buf, "%PATH%", path);

            virDomainDefineXML(cp, buf);
            free(buf);
        }
    }

out:
    return 0;
}

void usage(char *name)
{
    fprintf(stderr, "Usage: %s backup  --destination-path destpath [--hypervisor-uri uri] [--include-active] [--domain-list domains]"
#ifdef LIBVIR_HAVE_BLOCKINFO
            " [--use-block-info-api]"
#endif
#ifdef HAVE_LZMA
            " [--compression] [--compression-level level]"
#endif
            "\n"
                    "       %s restore --source-path srcpath --destination-path destpath [--hypervisor-uri uri]\n"
#ifdef HAVE_SENSORS
            "\nAlso you can use following sensors related options: [--therm-sensor sensor] [--therm-max-temp maxTemp]\n"
            "[--therm-average] [--therm-action action]. Name of the sensor have to be matched in the entries of the\n"
            "sysfs path or you can use experimental builtin sensors support using the sensor name 'builtin'. For the\n"
            "therm-action you could use either builtin actions (only 'sleep:seconds' is supported now, e.g. 'sleep:10'\n"
            "for sleeping for 10 seconds) or you can specify an executable to be run, the executable will be run with\n"
            "2 arguments, first to specify therm value it was triggered for and second to specify the time elapsed\n"
            "since last time the therm value exceeded the maximum value. Action is triggered *only* when therm-max-temp\n"
            "temperature reached."
#endif
            "\nYou can also use --block-size=100M to override the block size to be used for copy/compression operations.\n",
            name,
            name
);
    exit(EXIT_FAILURE);
}

char *getLibvirtAPIVersion(unsigned long number)
{
    char *ret;
    int major, minor, release;

    major = number / 1000000;
    minor = number / 1000;
    release = number - ((major * 1000000) + (minor * 1000));

    ret = malloc( 8 * sizeof(char) );
    snprintf(ret, 8, "%d.%d.%d", major, minor, release);
    return ret;
}

void dumpFlags(unsigned long flags) {
    if (!(flags & FLAG_DEBUG))
        return ;

    printf("\nDumping flag information:\n");
    printf("\tInclude active (--include-active): %s\n",
        flags & FLAG_INCLUDE_ACTIVE ? "True" : "False");
#ifdef LIBVIR_HAVE_BLOCKINFO
    printf("\tUse libvirt blockinfo API (--use-block-info-api): %s\n",
        flags & FLAG_USE_BLOCK_API ? "True" : "False");
#endif
    printf("\tLocal connection used: %s\n",
        flags & FLAG_LOCAL ? "True" : "False");
#ifdef HAVE_LZMA
    printf("\nCompression disabled (--no-compression): %s\n",
        flags & FLAG_NO_COMPRESS ? "True" : "False");
#endif

#ifdef HAVE_SENSORS
    printf("\tEnable sensors: %s\n",
        flags & FLAG_SENSOR_ENABLE ? "True" : "False");
    if (flags & FLAG_SENSOR_ENABLE) {
        printf("\tSensor driver (--therm-sensor): %s\n", sensor_drv);
        printf("\tUse average temperature (--therm-average): %s\n",
            flags & FLAG_SENSOR_AVERAGE ? "True" : "False");
        printf("\tMaximum temperature set (--therm-max-temp): %s\n",
            flags & FLAG_SENSOR_HAVEMAX ? "True" : "False");
        if (flags & FLAG_SENSOR_HAVEMAX)
            printf("\t  Maximum temperature: %d °C\n", getMaximumTemperature(flags));
    }
#endif

    printf("\n");
}

unsigned int argvToSize(char *arg)
{
    int unit, multiplicator = 1;

    if ((arg == NULL) || (strlen(arg) == 0))
        return BUFFER_SIZE;

    unit = arg[strlen(arg)-1];
    switch (arg[strlen(arg)-1]) {
        case 'k':
        case 'K':
            multiplicator = 1 << 10;
            break;
        case 'M':
            multiplicator = 1 << 20;
            break;
        case 'G':
            multiplicator = 1 << 30;
            break;
    }
    arg[strlen(arg) - 1] = 0;

    return atoi(arg) * multiplicator;
}

long parseArgs(int argc, char * const argv[], char *action) {
    int option_index = 0, c;
    unsigned int retVal = 0;
    struct option long_options[] = {
        {"source-path", 1, 0, 's'},
        {"destination-path", 1, 0, 'p'},
        {"hypervisor-uri", 1, 0, 'u'},
        {"domain-list", 1, 0, 'd'},
        {"include-active", 0, 0, 'a'},
#ifdef LIBVIR_HAVE_BLOCKINFO
        {"use-block-info-api", 0, 0, 'b'},
#endif
#ifdef HAVE_LZMA
        {"no-compression", 0, 0, 'n'},
        {"compression-level", 1, 0, 'c'},
#endif
#ifdef HAVE_SENSORS
        {"therm-sensor", 1, 0, 't'},
        {"therm-average", 0, 0, 'e'},
        {"therm-max-temp", 1, 0, 'm'},
        {"therm-action", 1, 0, 'o'},
#endif
        {"buffer-size", 1, 0, 'z'},
        {"debug", 0, 0, 'g'},
        {0, 0, 0, 0}
    };

#ifdef HAVE_SENSORS
    char *optstring = "s:z:p:d:u:aegb:nc:s:m:t:o:";
#else
    char *optstring = "s:z:p:d:u:agb:nc:t:";
#endif

    while (1) {
        c = getopt_long(argc, argv, optstring,
                   long_options, &option_index);
        if (c == -1)
            break;

        switch (c) {
            case 's':
                path = optarg;
                break;
            case 'p':
                if (strcmp(action, "backup") == 0)
                    path = optarg;
                else
                    pathTo = optarg;
                break;
            case 'u':
                uri = optarg;
                break;
            case 'z':
                gBufferSize = argvToSize(optarg);
                break;
            case 'a':
                retVal |= FLAG_INCLUDE_ACTIVE;
                break;
            case 'd':
                domains = optarg;
                break;
#ifdef LIBVIR_HAVE_BLOCKINFO
            case 'b':
                retVal |= FLAG_USE_BLOCKAPI;
                break;
#endif
#ifdef HAVE_LZMA
            case 'n':
                retVal |= FLAG_NO_COMPRESS;
                break;
            case 'c':
                if (((optarg == NULL) || (strlen(optarg) == 0)) || ((optarg[0] < '0') && (optarg[0] > '9' ))) {
                    fprintf(stderr, "Error: Invalid compression level specified, have to be 0 to 9\n");
                    exit(1);
                }
                gCompressionLevel = atoi(optarg);

                /* If buffer size was not overriden yet we alter it */
                if (gBufferSize == BUFFER_SIZE) {
                    switch (gCompressionLevel) {
                        case 0: gBufferSize = 6 * (1 << 20);
                                break;
                        case 1: gBufferSize = 6 * (1 << 20);
                                break;
                        case 2: gBufferSize = 10 * (1 << 20);
                                break;
                        case 3: gBufferSize = 20 * (1 << 20);
                                break;
                        case 4: gBufferSize = 30 * (1 << 20);
                                break;
                        case 5: gBufferSize = 60 * (1 << 20);
                                break;
                        case 6: gBufferSize = 100 * (1 << 20);
                                break;
                        case 7: gBufferSize = 200 * (1 << 20);
                                break;
                        case 8: gBufferSize = 400 * (1 << 20);
                                break;
                        case 9: gBufferSize = 800 * (1 << 20);
                                break;
                    }

                    DPRINTF("Buffer size not overriden, using %d MiB.\n", gBufferSize / (1 << 20));
                }

                break;
#endif
#ifdef HAVE_SENSORS
            case 't':
                retVal |= FLAG_SENSOR_ENABLE;
                sensor_drv = optarg;
                break;
            case 'e':
                retVal |= FLAG_SENSOR_AVERAGE;
                break;
            case 'm':
                retVal |= setMaximumTemperature(optarg);
                break;
            case 'o':
                sensor_action = optarg;
                if (strstr(sensor_action, ":") == NULL) {
                    /* Command to be run specified */
                    if (access(sensor_action, F_OK | X_OK) != 0) {
                        fprintf(stderr, "Command %s doesn't exist or is not executable\n",
                                sensor_action);
                        exit(EXIT_FAILURE);
                    }
                }
                break;
#endif
            case 'g':
                retVal |= FLAG_DEBUG;
                break;
            default:
                usage(argv[0]);
        }
    }

#ifdef HAVE_SENSORS
    if ((sensor_action != NULL) && (!getFlagSet(retVal, FLAG_SENSOR_HAVEMAX))) {
        fprintf(stderr, "Cannot use command without maximum temperature settings\n");
        exit(EXIT_FAILURE);
    }
#endif

    return retVal;
}

int main(int argc, char *argv[]) {
    virConnectPtr cp;
    int numInactive = -1, numActive = -1;

	xz_estimate_size("/home/mig/Work/Interest/myPackages/virt-backup/src/virt-backup.h", 1 << 20);
	//xz_estimate_size("/home/mig/Work/Interest/myPackages/virt-backup/src/virt-backup", 1 << 20);
	//xz_estimate_size("/home/mig/images/kvm/winxp.img", 60 * (1 << 20));
	return 0;

    action = NULL;
    path = NULL;
    uri = NULL;
    pathTo = NULL;
    domains = NULL;

    printf("Virt-backup utility v%s\n", APPVERSION);
    printf("Written by Michal Novotny <minovotn@redhat.com>\n");
    printf("[alternative e-mail address: <mignov@gmail.com>]\n");
#ifdef HAVE_LZMA
    printf("LZMA Support: Compiled, default compression level = %d\n", COMPRESSION_LEVEL);
#else
    printf("LZMA Support: Not compiled\n");
#endif
    printf("Using libvirt API version %s\n", getLibvirtAPIVersion(LIBVIR_VERSION_NUMBER));
    printf("\n");

    if (argc > 1)
        action = argv[1];

#ifdef HAVE_SENSORS
    sensor_drv = NULL;
    sensor_action = NULL;
#endif

    flags = parseArgs(argc, argv, action);

    if ((action == NULL) || (path == NULL)) {
        fprintf(stderr, "Error: You don't have %s defined\n", !action ? "subcommand" : "path");
        usage(argv[0]);
        return -1;
    }

    if (strcmp(action, "backup") == 0) {
        mkdir(path, 0700);
        DPRINTF("Setting tempPath to %s\n", path);

        /* virSetErrorFunc("virt-backup", errHandler); */
        cp = virConnectOpen(uri);
        if (cp == NULL) {
            DPRINTF("virConnectOpen call failed\n");
            return -1;
        }

        if (isLocalConnection(cp))
            flags |= FLAG_LOCAL;

        DPRINTF("Hypervisor URI: %s\n", virConnectGetURI(cp));
        DPRINTF("Using %s connection\n", getFlagSet(flags, FLAG_LOCAL) ? "local" : "remote");

        if (!getFlagSet(flags, FLAG_LOCAL)) {
#ifdef LIBVIR_HAVE_BLOCKINFO
            if (!use_libvir_blockinfo_api)
                fprintf(stderr, "Error: Cannot use remote connection without using libvirt block API\n");
#else
            fprintf(stderr, "Error: Cannot use remote connection with this version of libvirt\n");
#endif
            return 1;
        }

        numInactive = virConnectNumOfDefinedDomains(cp);
        if (getFlagSet(flags, FLAG_INCLUDE_ACTIVE))
            numActive = virConnectNumOfDomains(cp);

#ifndef HAVE_LZMA
        flags |= FLAG_NO_COMPRESS;
#endif

        dumpFlags(flags);

        if (numActive + numInactive > 0)
            getDomainFiles(cp, numActive, numInactive, path, getFlagSet(flags, FLAG_NO_COMPRESS) ? 0 : 1, domains);
        else
            printf("Error: No domains defined\n");

        virConnectClose(cp);

        printf("Backup is done\n");
        return 0;
    }
    else
    if (strcmp(action, "restore") == 0) {
        if (pathTo == NULL) {
            DPRINTF("Error: Destination path for restore unset, please use -p destinationPath\n");
            return 1;
        }
        int num;
        char xml[1024];

        DPRINTF("Guest restore requested\n");
        snprintf(xml, 1024, "%s/original-files.xml", path);
        if (access(xml, F_OK) != 0) {
            fprintf(stderr, "Guest XML Definition file on source path not found\n");
            return 1;
        }
        struct sfiles *files = getRestoreXml(xml, &num);

        /* Create the dir if it doesn't exist since otherwise it returns empty size on statvfs */
        mkdir(pathTo, 0755);

        cp = virConnectOpen(uri);
        if (cp == NULL) {
            DPRINTF("virConnectOpen call failed\n");
            return -1;
        }
        if (isLocalConnection(cp))
            flags |= FLAG_LOCAL;

        DPRINTF("Using %s connection\n", getFlagSet(flags, FLAG_LOCAL) ? "local" : "remote");

        if (!(getFlagSet(flags, FLAG_LOCAL))) {
#ifdef LIBVIR_HAVE_BLOCKINFO
            if (!use_libvir_blockinfo_api)
                fprintf(stderr, "Error: Cannot use remote connection without using libvirt block API\n");
#else
            fprintf(stderr, "Error: Cannot use remote connection with this version of libvirt\n");
#endif
            return 1;
        }

        DPRINTF("Hypervisor URI: %s\n", virConnectGetURI(cp));
        dumpFlags(flags);
        restoreGuests(cp, path, pathTo, files, num);
        virConnectClose(cp);
        printf("Restore is done\n");
    }
    else {
        fprintf(stderr, "Error: Unsupported action type (%s). Please run %s to "
                        "see the syntax requested.\n", action, argv[0]);
        return -EINVAL;
    }

    return 0;
}

