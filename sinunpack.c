/*
 * Copyright (C) 2017 Munjeni
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.

 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 * LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 */

#include <sparse/sparse.h>

#if (!defined(_WIN32)) && (!defined(WIN32)) && (!defined(__APPLE__))
	#ifndef __USE_FILE_OFFSET64
		#define __USE_FILE_OFFSET64 1
	#endif
	#ifndef __USE_LARGEFILE64
		#define __USE_LARGEFILE64 1
	#endif
	#ifndef _LARGEFILE64_SOURCE
		#define _LARGEFILE64_SOURCE 1
	#endif
	#ifndef _FILE_OFFSET_BITS
		#define _FILE_OFFSET_BITS 64
	#endif
	#ifndef _FILE_OFFSET_BIT
		#define _FILE_OFFSET_BIT 64
	#endif
#endif

#ifdef _WIN32
	#define __USE_MINGW_ANSI_STDIO 1

#include <windows.h>
#include <setupapi.h>
#include <initguid.h>

#include "GordonGate.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#ifdef HAS_STDINT_H
	#include <stdint.h>
#endif
#ifdef unix
	#include <unistd.h>
	#include <sys/types.h>
#else
	#include <direct.h>
	#include <io.h>
#endif

#if defined(USE_FILE32API)
	#define fopen64 fopen
	#define ftello64 ftell
	#define fseeko64 fseek
#else
	#ifdef __FreeBSD__
		#define fopen64 fopen
		#define ftello64 ftello
		#define fseeko64 fseeko
	#endif
	/*#ifdef __ANDROID__
		#define fopen64 fopen
		#define ftello64 ftello
		#define fseeko64 fseeko
	#endif*/
	#ifdef _MSC_VER
		#define fopen64 fopen
		#if (_MSC_VER >= 1400) && (!(defined(NO_MSCVER_FILE64_FUNC)))
			#define ftello64 _ftelli64
			#define fseeko64 _fseeki64
		#else  /* old msc */
			#define ftello64 ftell
			#define fseeko64 fseek
		#endif
	#endif
#endif

#include <ctype.h>
#include <sys/stat.h>
#include <limits.h>
#include <time.h>
#include <dirent.h>
#include <assert.h>

#ifndef _WIN32
#include <linux/usbdevice_fs.h>
#include <linux/usb/ch9.h>
#include <asm/byteorder.h>

#include <string.h>
#include <errno.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

#include <dirent.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <ctype.h>
#endif

//#include "expat.h"
#include <zlib.h>

#ifdef _WIN32
#define sleep Sleep
#define ONESEC 1000
#else
#define ONESEC 1
#endif

#define ENABLE_DEBUG 1

#if ENABLE_DEBUG
#define LOG printf
#else
#define LOG(...)
#endif

#ifndef O_BINARY
#define O_BINARY 0
#endif

static char tmp[4096];
static char tmp_reply[512];
static unsigned long get_reply_len;
static char product[12];
static char version[64];
static char version_bootloader[64];
static char version_baseband[64];
static char serialno[64];
static char secure[32];
static unsigned int sector_size = 0;
static unsigned int max_download_size = 0;
static char loader_version[64];
static char phone_id[64];
static char device_id[64];
static char rooting_status[32];
static char ufs_info[64];
static char emmc_info[64];
static char default_security[16];
static char platform_id[64];
static unsigned int keystore_counter = 0;
static char security_state[128];
static char s1_root[64];
static char sake_root[16];
static char get_root_key_hash[0x41];

static char slot_count[2];
static char current_slot[2];

static unsigned int something_flashed = 0;

unsigned int swap_uint32(unsigned int val) {
	val = ((val << 8) & 0xFF00FF00 ) | ((val >> 8) & 0xFF00FF);
	return ((val << 16) | (val >> 16)) & 0xffffffff;
}

unsigned long long swap_uint64(unsigned long long val) {
	val = ((val << 8) & 0xFF00FF00FF00FF00ULL) | ((val >> 8) & 0x00FF00FF00FF00FFULL);
	val = ((val << 16) & 0xFFFF0000FFFF0000ULL) | ((val >> 16) & 0x0000FFFF0000FFFFULL);
	return ((val << 32) | (val >> 32)) & 0xffffffffffffffffULL;
}

void fread_unus_res(void *ptr, size_t size, size_t nmemb, FILE *stream) {
	size_t in;
	in = fread(ptr, size, nmemb, stream);
	if (in) {
		/* satisfy warn unused result */
	}
}

unsigned int file_size(char *filename) {
	unsigned int size;

	FILE *fp = fopen(filename, "rb");

	if (fp == NULL) {
		return 0;
	}

	fseek(fp, 0, SEEK_END);
	size = ftell(fp);
	fseek(fp, 0, SEEK_SET);
	fclose(fp);
	return size;
}

static int file_exist(char *file) {
	int ret;
	FILE *f = NULL;

	if ((f = fopen64(file, "rb")) == NULL) {
		ret = 0;
	} else {
		fclose(f);
		ret = 1;
	}
	return ret;
}

static void remove_file_exist(char *file) {
	if (file_exist(file)) {
		remove(file);
	}
}

static char *basenamee(char *in) {
	char *ssc;
	int p = 0;
	ssc = strstr(in, "/");
	if (ssc == NULL) {
		ssc = strstr(in, "\\");
		if(ssc == NULL) {
		  	return in;
		}
	}
	do {
		p = strlen(ssc) + 1;
		in = &in[strlen(in)-p+2];
		ssc = strstr(in, "/");
		if (ssc == NULL)
			ssc = strstr(in, "\\");
	} while(ssc);

	return in;
}

static int command(char *what) {
	int ret;
	static char buffer[300];
	snprintf(buffer, sizeof(buffer), "%s", what);
	ret = system(buffer);
#if 0
	printf("%s\n", buffer);
	printf("returned=%d OK.\n", ret);
#endif
	return ret;
}

#define MAX_UNIT_LINE_LEN 0x20000

static ssize_t g_getline(char **lineptr, size_t *n, FILE *stream) {
	char *cur_pos, *new_lineptr;
	int c;
	size_t new_lineptr_len;

	if (lineptr == NULL || n == NULL || stream == NULL) {
		errno = EINVAL;
		printf("Error: EINVAL!\n");
		return -1;
	}

	if (*lineptr == NULL) {
		*n = MAX_UNIT_LINE_LEN;
		if ((*lineptr = (char *)malloc(*n)) == NULL) {
			errno = ENOMEM;
			printf("Error: MAX_UNIT_LINE_LEN reached!\n");
			return -1;
		}
	}

	cur_pos = *lineptr;
	for (;;) {
		c = getc(stream);

		if (ferror(stream) || (c == EOF && cur_pos == *lineptr))
			return -1;

		if (c == EOF)
			break;

		if ((*lineptr + *n - cur_pos) < 2) {
			if (SSIZE_MAX / 2 < *n) {
#ifdef EOVERFLOW
				errno = EOVERFLOW;
#else
				errno = ERANGE; /* no EOVERFLOW defined */
#endif
			printf("Error: EOVERFLOW!\n");
			return -1;
		}
		new_lineptr_len = *n * 2;

		if ((new_lineptr = (char *)realloc(*lineptr, new_lineptr_len)) == NULL) {
			errno = ENOMEM;
			printf("Error: ENOMEM for realloc!\n");
			return -1;
		}
		*lineptr = new_lineptr;
		*n = new_lineptr_len;
	}

	*cur_pos++ = c;

	if (c == '\r' || c == '\n')
		break;
	}

	*cur_pos = '\0';
	return (ssize_t)(cur_pos - *lineptr);
}

static void trim(char *ptr) {
	int i = 0;
	int j = 0;

	while(ptr[j] != '\0') {
		if(ptr[j] == 0x20 || ptr[j] == 0x09 || ptr[j] == '\n' || ptr[j] == '\r') {
			++j;
			ptr[i] = ptr[j];
		} else {
			ptr[i] = ptr[j];
			++i;
			++j;
		}
	}
	ptr[i] = '\0';
}

static char *TEXT(char *what) {
	return what;
}

void DisplayError(char *title)
{
	printf("%s\n%s\n", title, strerror(errno));
}


static void to_ascii(char *dest, const char *text) {
	unsigned long int ch;
	for(; sscanf((const char *)text, "%02lx", &ch)==1; text+=2)
		*dest++ = ch;
	*dest = 0;
}

static void to_uppercase(char *ptr) {
	for ( ; *ptr; ++ptr) *ptr = toupper(*ptr);
}

static void display_buffer_hex_ascii(char *message, char *buffer, unsigned int size) {
	unsigned int i, j, k;

	LOG("%s[0x%X]:\n", message, size);

	for (i=0; i<size; i+=16) {
		LOG("\n  %08X  ", i);
		for(j=0,k=0; k<16; j++,k++) {
			if (i+j < size) {
				LOG("%02X", buffer[i+j] & 0xff);
			} else {
				LOG("  ");
			}
			LOG(" ");
		}
		LOG(" ");
		for(j=0,k=0; k<16; j++,k++) {
			if (i+j < size) {
				if ((buffer[i+j] < 32) || (buffer[i+j] > 126)) {
					LOG(".");
				} else {
					LOG("%c", buffer[i+j]);
				}
			}
		}
	}
	LOG("\n\n" );
}

/* The max bulk size for linux is 16384 which is defined
 * in drivers/usb/core/devio.c.
 */
#define MAX_USBFS_BULK_SIZE 4096
/*(16 * 1024)*/


static inline int badname(const char *name)
{
	while (*name) {
		if (!isdigit(*name++))
			return 1;
	}
	return 0;
}


static int check_valid_unit(char *in) {
	int i, ret=0;

	if (strlen(in) < 8)
		return ret;

	for (i=0; i<8; ++i) {
		if ((in[i] >= '0' && in[i] <= '9') || (in[i] >= 'A' && in[i] <= 'Z') || (in[i] >= 'a' && in[i] <= 'z'))
			ret += 1;
	}

	if (ret == 8)
		return 1;
	else
		return 0;
}

#define CHUNK 16384

/* These are parameters to deflateInit2. See
   http://zlib.net/manual.html for the exact meanings. */

#define windowBits 15
#define GZIP_ENCODING 16


/* Decompress from file source to file dest until stream ends or EOF.
   inf() returns Z_OK on success, Z_MEM_ERROR if memory could not be
   allocated for processing, Z_DATA_ERROR if the deflate data is
   invalid or incomplete, Z_VERSION_ERROR if the version of zlib.h and
   the version of the library linked do not match, or Z_ERRNO if there
   is an error reading or writing the files. */
int inf(FILE *source, FILE *dest)
{
	int ret, progress=0;
	unsigned long long have;
	z_stream strm;
	unsigned char in[CHUNK];
	unsigned char out[CHUNK];

	/* allocate inflate state */
	strm.zalloc = Z_NULL;
	strm.zfree = Z_NULL;
	strm.opaque = Z_NULL;
	strm.avail_in = 0;
	strm.next_in = Z_NULL;
	ret = inflateInit2(&strm, 47);      /* automatic zlib or gzip decoding */
	if (ret != Z_OK)
	    return ret;

	printf("      ");

	/* decompress until deflate stream ends or end of file */
	do {
		strm.avail_in = fread(in, 1, CHUNK, source);
		if (ferror(source)) {
			(void)inflateEnd(&strm);
			return Z_ERRNO;
		}
		if (strm.avail_in == 0)
			break;
		strm.next_in = in;

	    /* run inflate() on input until output buffer not full */
	    do {
			strm.avail_out = CHUNK;
			strm.next_out = out;
			ret = inflate(&strm, Z_NO_FLUSH);
			assert(ret != Z_STREAM_ERROR);  /* state not clobbered */
			switch (ret) {
				case Z_NEED_DICT:
				ret = Z_DATA_ERROR;     /* and fall through */
				case Z_DATA_ERROR:
				case Z_MEM_ERROR:
				(void)inflateEnd(&strm);
                    DisplayError(TEXT("assert(ret != Z_STREAM_ERROR)"));
				return ret;
			}
			have = CHUNK - strm.avail_out;
			if ((have % 4294967296ULL) == 0)
			{
				progress += 1;
				printf(".");
				if (progress == 60) {
					progress = 0;
					printf("\n      ");
				}
			}
			if (fwrite(out, 1, have, dest) != have || ferror(dest)) {
				(void)inflateEnd(&strm);
				DisplayError(TEXT("Z_ERRNO"));
				return Z_ERRNO;
			}
	    } while (strm.avail_out == 0);

	    /* done when inflate() says it's done */
	} while (ret != Z_STREAM_END);

	/* clean up and return */
	(void)inflateEnd(&strm);
	printf("\n");
	return ret == Z_STREAM_END ? Z_OK : Z_DATA_ERROR;
}

/* report a zlib or i/o error */
void zerr(int ret)
{
	fputs(" - gzpipe: ", stderr);
	switch (ret)
	{
		case Z_ERRNO:
			if (ferror(stdin))
				fputs("error reading stdin!\n", stderr);
			if (ferror(stdout))
				fputs("error writing stdout!\n", stderr);
			break;
		case Z_STREAM_ERROR:
			fputs("invalid compression level!\n", stderr);
			break;
		case Z_DATA_ERROR:
			fputs("invalid or incomplete deflate data!\n", stderr);
			break;
		case Z_MEM_ERROR:
			fputs("out of memory!\n", stderr);
			break;
		case Z_VERSION_ERROR:
			fputs("zlib version mismatch!\n", stderr);
			break;
		default:
			fputs("ok.\n", stderr);
			break;
	}
}


static int gunziper(char *in, char *out)
{
		int ret;
		FILE *zipped = NULL;
		FILE *back = NULL;

		printf (" - setting up infflate...\n");
		if ((zipped = fopen64(in, "rb")) == NULL) {
			printf(" - Could not open %s for infflating!\n", in);
			return 1;
		}
		if ((back = fopen64(out, "wb")) == NULL) {
			printf(" - Could not open %s for write!\n", out);
			if (zipped) fclose(zipped);
			return 1;
		}
		printf (" - infflating, please wait...\n");
		ret = inf(zipped, back);
		printf(" - infflate returned: %i\n", ret);
		zerr(ret);

		if (zipped) fclose(zipped);
		if (back) fclose(back);

		if (ret != 0) {
			remove_file_exist(out);
			return 1;
		}

		printf(" - gunziped ok.\n");
		return 0;
}

/* Parse an octal number, ignoring leading and trailing nonsense. */
static int parseoct(const char *p, size_t n)
{
	int i = 0;

	while (*p < '0' || *p > '7') {
		++p;
		--n;
	}
	while (*p >= '0' && *p <= '7' && n > 0) {
		i *= 8;
		i += *p - '0';
		++p;
		--n;
	}
	return (i);
}

/* Returns true if this is 512 zero bytes. */
static int is_end_of_archive(const char *p)
{
	int n;
	for (n = 511; n >= 0; --n)
	{
		if (p[n] != '\0')
		{
			return 0;
		}
	}
	return 1;
}

/* Create a file, including parent directory as necessary. */
static FILE *create_file(char *pathname)
{
	FILE *f = fopen64(pathname, "wb");

	if (f == NULL)
		return NULL;
	else
		return (f);
}

/* Verify the tar checksum. */
static int verify_checksum(const char *p)
{
	int n, u = 0;
	for (n = 0; n < 512; ++n) {
		if (n < 148 || n > 155)
			/* Standard tar checksum adds unsigned bytes. */
			u += ((unsigned char *)p)[n];
		else
			u += 0x20;

	}
	return (u == parseoct(p + 148, 8));
}

static int process_sins(FILE *a, char *filename, char *outfolder, char *endcommand)
{
	char buff[512];
	FILE *f = NULL;
	size_t bytes_read;
	int filesize;
	int i=0;
	char tmpp[256];
	char tmpg[256];
	char command[64];
	char flashfile[256];
	int have_slot=0;

    int in = -1;
    int out = -1;
    struct sparse_file *s = NULL;
    char imgf[sizeof(tmpp)] = { 0 };
    int converted = 0;

	printf(" - Extracting from %s\n", basenamee(filename));

	for (;;)
	{
		int chunk = 0;
		bytes_read = fread(buff, 1, 512, a);

		if (bytes_read != 512) {
			printf(" - Short read on %s: expected 512, got %d\n", filename, (int)bytes_read);
			return 0;
		}

		if (is_end_of_archive(buff))
		{
			printf(" - End of %s\n", basenamee(filename));
			if (out >= 0)
				close(out);
			if (!converted && strlen(imgf) > 0)
				remove(imgf);
			return 1;
		}

		if (!verify_checksum(buff)) {
			printf(" - Checksum failure\n");
			return 0;
		}

		filesize = parseoct(buff + 124, 12);

		switch (buff[156])
		{
			case '1':
				printf(" - Ignoring hardlink %s\n", buff);
				break;
			case '2':
				printf(" - Ignoring symlink %s\n", buff);
				break;
			case '3':
				printf(" - Ignoring character device %s\n", buff);
					break;
			case '4':
				printf(" - Ignoring block device %s\n", buff);
				break;
			case '5':
				printf(" - Ignoring dir %s\n", buff);
				filesize = 0;
				break;
			case '6':
				printf(" - Ignoring FIFO %s\n", buff);
				break;
			default:
				memset(tmpg, 0, sizeof(tmpg));
				memcpy(tmpg, filename, strlen(filename)-4);
				snprintf(tmpp, sizeof(tmpp), "%s/%s", outfolder, buff);
				printf(" - %s %s\n", (i == 0) ? "Extracting signature" : "Extracting sparse chunk", tmpp);
				i += 1;
				f = create_file(tmpp);	//, parseoct(buff + 100, 8));
				if (f == NULL) {
					printf(" - Error creating %s\n", tmpp);
					return 0;
				}
				snprintf(flashfile, strlen(basenamee(tmpp))-3, "%s", basenamee(tmpp));
				break;
		}

		while (filesize > 0)
		{
			bytes_read = fread(buff, 1, 512, a);
			if (bytes_read != 512) {
				printf(" - Short read on %s: Expected 512, got %d\n", filename, (int)bytes_read);
				return 0;
			}

			if (filesize < 512)
				bytes_read = filesize;

			if (f != NULL)
			{
				if (fwrite(buff, 1, bytes_read, f) != bytes_read)
				{
					printf(" - Failed write\n");
					fclose(f);
					f = NULL;
				}
			}

			filesize -= bytes_read;
			chunk += 1;
		}

		if (f != NULL) {
			fclose(f);
			f = NULL;
		}

		if (i == 1)
		{
			FILE *fp = NULL;
			char *buffer = NULL;
			unsigned int fp_size;

			fp_size = file_size(tmpp);

			printf(" - Uploading signature %s\n", tmpp);

			if (!fp_size) {
				printf("      Error, size of the %s is 0!\n", tmpp);
				return 0;
			}

			snprintf(command, sizeof(command), "signature:%08x", fp_size);
			printf("      %s\n", command);
			// PROCESS signature from tmpp
		}
		else
		{
			FILE *fp = NULL;
			char *buffer = NULL;
			unsigned int fp_size;
			size_t fp_read;
			int g = 0;

			fp_size = file_size(tmpp);

			printf(" - Uploading sparse chunk %s\n", tmpp);

			if (!fp_size) {
				printf("      Error, size of the %s is 0!\n", tmpp);
				return 0;
			}

			snprintf(command, sizeof(command), "download:%08x", fp_size);
			printf("      %s\n", command);

			// PROCESS sparse data file
			if (i == 2) {
			    strcpy(imgf, tmpp);
			    strcpy(imgf + strlen(tmpp) - 3, "img");
			    out = open(imgf, O_WRONLY | O_CREAT | O_TRUNC | O_BINARY, 0664);
			    if (out < 0)
			        fprintf(stderr, "Cannot open output file %s\n", imgf);
			}
			converted = 0;
			if (out >= 0) {
			    in = open(tmpp, O_RDONLY | O_BINARY);
			    if (in < 0)
			        fprintf(stderr, "Cannot open input file %s\n", tmpp);
			    else {
			        s = sparse_file_import(in, true, false);
			        if (!s) {
			            fprintf(stderr, "Failed to read sparse file %s\n", tmpp);
			        } else {
				        if (lseek(out, 0, SEEK_SET) == -1) {
				            perror("lseek failed");
				        } else if (sparse_file_write(s, out, false, false, false) < 0) {
				            fprintf(stderr, "Cannot write output file\n");
				        } else
						converted = 1;
				        sparse_file_destroy(s);
				}
			        close(in);
			    }
			}
			if (converted)
				remove(tmpp);
		}
	}
	return 0;
}



#include <sys/statvfs.h>

static unsigned long get_free_space(char *fnPath)
{
        struct statvfs fiData;

	if ((statvfs(fnPath, &fiData)) < 0)
	{
		printf("  Error: unable to determine available free space for current drive!\n");
		return 0;
	}
	else
	{
		printf ("\nDetermining available free space:\n\n");
		printf ("  Available space to caller    = %llu MB\n",
			 (unsigned long long)((fiData.f_bsize * fiData.f_bavail) / 1024 / 1024));
		printf ("  Total space on current drive = %llu MB\n",
			 (unsigned long long)((fiData.f_bsize * fiData.f_blocks) / 1024 / 1024));
		printf ("  Free space on drive          = %llu MB\n",
			 (unsigned long long)((fiData.f_bsize * fiData.f_bfree) / 1024 / 1024));
	}

	return (unsigned long)fiData.f_bfree;
}

/*========================================================================================*/

int main(int argc, char *argv[])
{
	FILE *fi = NULL;
	int fld_cbck;
	char fld[256];
	char file_format[3];
	char sinfil[256];
	char *progname = basenamee(argv[0]);
	unsigned short VID = 0x0FCE;
	unsigned short PID = 0xB00B;
	int i, j, ret=0;
	char ch;

	DIR *dir = NULL;
	struct dirent *ep = NULL;
	char *extension = NULL;
	int sin_found = 0;

	struct stat filestat;
	char searchfor[1024];
	int bootdelivery_found = 0;

	unsigned long available_mb;

#ifdef _WIN32
	char *device = NULL;
	char *working_path = _getcwd(0, 0);
#else
	char working_path[PATH_MAX];
	if (getcwd(working_path, sizeof(working_path)) == NULL) {
		perror("getcwd() error");
		goto pauza;
	}
#endif

	printf("--------------------------------------------------------\n");
	printf("    %s based on newflasher v13 by Munjeni @ 2017/2018\n", progname);
	printf("--------------------------------------------------------\n");

	available_mb = get_free_space(working_path);

	if (available_mb < 10240)
	{
		printf("  Error! You do not have needed 10240 MB available free space on your\n");
		printf("  disk drive! You have only %lu MB free.\n", available_mb);
		goto pauza;
	}

	memset(slot_count, 0x30, sizeof(slot_count));
	memset(current_slot, 0x30, sizeof(current_slot));


/*=======================================  process .sin files  =======================================*/

	printf("\n");
	sin_found = 0;
	printf("Processing .sin files...\n");
	snprintf(fld, sizeof(fld), "unpacked/");
	if (0 != access(fld, F_OK))
	{
		if (ENOENT == errno) {
			snprintf(fld, sizeof(fld), "mkdir unpacked");
			fld_cbck = command(fld);
			if (fld_cbck == 0) {
				printf("Created ouput folder flash_session\n");
			} else {
				printf("FAILURE to create output folder unpacked!\n");
				ret = 1;
				goto getoutofflashing;
			}
		}

		if (ENOTDIR == errno) {
			printf("FAILURE to create output folder unpacked because there is file called unpacked!!!\n"
				"Remove or rename file unpacked first!\n");
			ret = 1;
			goto getoutofflashing;
		}

	}
	else
	{
		printf("Using existing folder unpacked\n");
	}

	if ((dir = opendir(working_path)) != NULL)
	{
		while ((ep = readdir(dir)) != NULL)
		{
			/*if (ep->d_type == DT_REG)*/
			{
				if (strcmp(ep->d_name, ".") != 0 && strcmp(ep->d_name, "..") != 0)
				{
					if ((extension = strrchr(ep->d_name, '.')) != NULL)
					{
						if (strcmp(extension, ".sin") == 0 && strstr(ep->d_name, "artition") == NULL)   /* look for .sin & skip Partition or partition sin */
						{
							sin_found = 1;
							printf("\n");
							printf("Processing %s\n", ep->d_name);
#ifdef _WIN32
							snprintf(sinfil, sizeof(sinfil), "%s\\%s", working_path, ep->d_name);
#else
							snprintf(sinfil, sizeof(sinfil), "./%s", ep->d_name);
#endif
							if (!strlen(sinfil)) {
								printf("Oops!!! Sinfile name empty!\n");
								ret = 1;
								goto getoutofflashing;
							}

							fi = fopen64(sinfil, "rb");
							if (fi == NULL) {
								printf(" - unable to open %s!\n", sinfil);
								ret = 1;
								goto getoutofflashing;
							}
							fseeko64(fi, 0, SEEK_SET);
							fread_unus_res(file_format, 1, 2, fi);
							if (fi) fclose(fi);

							if (memcmp(file_format, "\x1F\x8B", 2) == 0)
							{
							   	FILE *a = NULL;
#ifdef _WIN32
								snprintf(fld, sizeof(fld), "%s\\unpacked\\converted.file", working_path);
#else
								snprintf(fld, sizeof(fld), "./unpacked/converted.file");
#endif
								if (gunziper(sinfil, fld))
								{
									ret = 1;
									goto getoutofflashing;
								}

								a = fopen64(fld, "rb");
								if (a == NULL)
								{
									printf(" - Unable to open %s\n", fld);
								}
								else
								{
									if (!process_sins(a, sinfil, "unpacked", "flash"))
									{
										fclose(a);
										remove(fld);
										closedir(dir);
										goto getoutofflashing;
									}
									fclose(a);
								}

								remove(fld);
							}
							else
							{
								FILE *a = NULL;

								a = fopen64(sinfil, "rb");
								if (a == NULL)
								{
									printf(" - Unable to open %s\n", sinfil);
								}
								else
								{
									if (!process_sins(a, sinfil, "unpacked", "flash"))
									{
										fclose(a);
										remove(fld);
										closedir(dir);
										goto getoutofflashing;
									}
									fclose(a);
								}
							}
						}
					}
				}
			}
		}
		closedir(dir);
	}

	if (!sin_found)
		printf("No .sin files in current dir.\n");
	else
		something_flashed = 1;

  getoutofflashing:
  pauza:
	return ret;
}

