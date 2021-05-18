/*
 * buffered file I/O
 * Copyright (c) 2001 Fabrice Bellard
 *
 * This file is part of FFmpeg.
 *
 * FFmpeg is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * FFmpeg is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with FFmpeg; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include "libavutil/avstring.h"
#include "libavutil/internal.h"
#include "libavutil/opt.h"

#include "avformat.h"
#include <fcntl.h>
#if HAVE_IO_H
#include <io.h>
#endif
#if HAVE_UNISTD_H
//#include <windows.h>
#include <unistd.h>
#endif
#include <sys/stat.h>
#include <stdlib.h>
#include "os_support.h"
//#include "url.h"
#include "SMS4.h"
#include "libavformat/url.h"
#include <time.h>
/* Some systems may not have S_ISFIFO */
#ifndef S_ISFIFO
#  ifdef S_IFIFO
#    define S_ISFIFO(m) (((m) & S_IFMT) == S_IFIFO)
#  else
#    define S_ISFIFO(m) 0
#  endif
#endif

/* standard file protocol */

typedef struct FileContext {
    const AVClass *class;
    int fd;
    int trunc;
    int blocksize;
	int is_enc;
	int64_t file_length;
	int64_t enc_length;
	int64_t offset;
	int64_t file_offset;
	int64_t file_start;

}FileContext;



static const AVOption file_options[] = {
    { "truncate", "Truncate existing files on write", offsetof(FileContext, trunc), AV_OPT_TYPE_INT, { .i64 = 1 }, 0, 1, AV_OPT_FLAG_ENCODING_PARAM },
    { "blocksize", "set I/O operation maximum block size", offsetof(FileContext, blocksize), AV_OPT_TYPE_INT, { .i64 = INT_MAX }, 1, INT_MAX, AV_OPT_FLAG_ENCODING_PARAM },
    { NULL }
};

static const AVOption pipe_options[] = {
    { "blocksize", "set I/O operation maximum block size", offsetof(FileContext, blocksize), AV_OPT_TYPE_INT, { .i64 = INT_MAX }, 1, INT_MAX, AV_OPT_FLAG_ENCODING_PARAM },
    { NULL }
};
static const AVClass file_class = {
    .class_name = "file",
    .item_name  = av_default_item_name,
    .option     = file_options,
    .version    = LIBAVUTIL_VERSION_INT,
};

static const AVClass pipe_class = {
    .class_name = "pipe",
    .item_name  = av_default_item_name,
    .option     = pipe_options,
    .version    = LIBAVUTIL_VERSION_INT,
};


int filesize;

FILEMY* file_info;
unsigned char DecryptKey[16];
//BOOL decrypt;

//BOOL decrypt;
//unsigned char DecryptKey[16];
//FILEMY* file_info;
//HANDLE mutex;
//FILE* fileread;
//FILE* filetest;

//write_mark = TRUE;


/*
void OutputDebugPrintf(const char * strOutputString,...)
{
    char strBuffer[4096]={0};
    va_list vlArgs;
    va_start(vlArgs,strOutputString);
    _vsnprintf(strBuffer,sizeof(strBuffer)-1,strOutputString,vlArgs);
    //vsprintf(strBuffer,strOutputString,vlArgs);
    va_end(vlArgs);
    OutputDebugString(strBuffer);
}
*/
unsigned long ulrand(void) ;
char *bin2hex(char *bin,unsigned int bin_len);
int analyze_file(const char *filename);
unsigned long ulrand(void) {
    return (
     (((unsigned long)rand()<<24)&0xFF000000ul)
    |(((unsigned long)rand()<<12)&0x00FFF000ul)
    |(((unsigned long)rand()    )&0x00000FFFul));
}
int i;
unsigned long ul;

char *bin2hex(char *bin,unsigned int bin_len)
{
	int pos = 0;
	int offset = 0;
	char *hex;

	hex = (char*)malloc(bin_len * 2 + 1);
	memset(hex,0,bin_len * 2 + 1);

	while(pos < bin_len)
	{
		offset += sprintf(hex + offset,"%02x",(unsigned char)bin[pos]);
		pos++;
	}

	return hex;
}



static int file_read(URLContext *h, unsigned char *buf, int size)
{
    FileContext *c = h->priv_data;
    int r;
	int temp = 0;
	int64_t offset_t;
	int enc_size;

	unsigned char* buf_t = (unsigned char*)malloc(size + 32);
	unsigned char* buf_enc1 = (unsigned char*)malloc(size + 32);
	unsigned char* buf_enc2 = (unsigned char*)malloc(size + 32);
	
	if(c->is_enc == 1){
		SMS4SetKey((uint32*)DecryptKey,1);
		if(c->offset == 0){//开始读视频
			lseek(c->fd, c->file_start, 0);
			if((size&15) == 0){
				r = read(c->fd, buf_enc1, size);
				SMS4Decrypt2((uint32*)buf_enc1, (uint32*)buf_enc2, size);
				for(i = 0; i < size; i++){
					*(buf + i) = (*(buf_enc1 + i) << 3) + *(buf_enc2 + i);
				}
			}
			else{
				temp = size + 16 - (size&15);
				r = read(c->fd, buf_enc1, temp);
				SMS4Decrypt2((uint32*)buf_enc1, (uint32*)buf_enc2, temp);
				for(i = 0; i < size; i++){
					*(buf + i) = (*(buf_enc1 + i) << 3) + *(buf_enc2 + i);
				}
			}
		}else if((c->offset != 0) && c->file_offset < c->enc_length){
		//	sprintf(test, "file_offset:%I64d  result:%d--%I64d\n",(c->file_offset + (int64_t)size),(c->file_offset + (int64_t)size) > c->enc_length,(c->file_offset + (int64_t)size)- c->enc_length);
			if((c->file_offset + (int64_t)size) > c->enc_length){//读的内容不是全部加密的
				if((c->offset&15) == 0){//offset对齐
					enc_size = c->enc_length - c->file_offset;
					if((enc_size&15)== 0){
						r = read(c->fd, buf_enc1, enc_size);
						SMS4Decrypt2((uint32*)buf_enc1, (uint32*)buf_enc2, enc_size);
						for(i = 0; i < enc_size; i++){
							*(buf + i) = (*(buf_enc1 + i) << 3) + *(buf_enc2 + i);
						}
						r = read(c->fd, buf + enc_size, (size - enc_size));
					//	memcpy(buf, buf_t, size);
					}
				}else{//offset不对齐 前移
					offset_t = (c->offset&15);
					c->file_offset = c->file_offset - offset_t;
					lseek(c->fd, c->file_offset, 0);
					enc_size = c->enc_length - c->file_offset;
					r = read(c->fd, buf_enc1, enc_size);
					SMS4Decrypt2((uint32*)buf_enc1, (uint32*)buf_enc2, enc_size);
					for(i = 0; i < enc_size; i++){
						*(buf_t + i) = (*(buf_enc1 + i) << 3) + *(buf_enc2 + i);
					}
				//	SMS4Decrypt((uint32*)buf_t, enc_size);
					r = read(c->fd, buf_t + enc_size, size + offset_t - enc_size);
					memcpy(buf, buf_t + offset_t, size);
					c->file_offset += offset_t;
				}
			}else{//读的内容是全部加密
				if((c->offset&15) == 0){
					if((size&15) == 0){
						r = read(c->fd, buf_enc1, size);
						SMS4Decrypt2((uint32*)buf_enc1, (uint32*)buf_enc2, size);		
						for(i = 0; i < size; i++){
							*(buf + i) = (*(buf_enc1 + i) << 3) + *(buf_enc2 + i);
						}
					}else{
						temp = size + (16 - (size&15));
						r = read(c->fd, buf_enc1, temp);
						SMS4Decrypt2((uint32*)buf_enc1, (uint32*)buf_enc2, temp);
						for(i = 0; i < size; i++){
							*(buf + i) = (*(buf_enc1 + i) << 3) + *(buf_enc2 + i);
						}
					}
				}else{//offset不对齐 前移
					offset_t =(c->offset&15);
					c->file_offset -= offset_t;
					lseek(c->fd, c->file_offset, 0);
					temp = size + offset_t;
					if((temp&15) == 0){
						r = read(c->fd, buf_enc1, temp);
						SMS4Decrypt2((uint32*)buf_enc1, (uint32*)buf_enc2, temp);
						for(i = 0; i < temp; i++){
							*(buf_t + i) = (*(buf_enc1 + i) << 3) + *(buf_enc2 + i);
						}
						memcpy(buf, buf_t + offset_t, size);
					}else{
						temp += (16 - (temp&15));
						r = read( c->fd, buf_enc1, temp);
						SMS4Decrypt2((uint32*)buf_enc1, (uint32*)buf_enc2, temp);
						for(i = 0; i < temp; i++){
							*(buf_t + i) = (*(buf_enc1 + i) << 3) + *(buf_enc2 + i);
						}
						memcpy(buf, buf_t + offset_t, size);
					}
					c->file_offset += offset_t;
				}
			}
		}else{
			r = read(c->fd, buf, size);
		}
	}else{
		r = read(c->fd, buf, size);
	}
	//OutputDebugPrintf("offset:%s",offset);
	//OutputDebugPrintf("size:%s",sized);
	c->offset += size;
	c->file_offset += size;
	file_info->FileOffset += size;
	lseek(c->fd, c->file_offset, 0);
	free(buf_t);
	free(buf_enc1);
	free(buf_enc2);
	return size;
    //return (-1 == r)?AVERROR(errno):r;
}

static int file_write(URLContext *h, const unsigned char *buf, int size)
{
    FileContext *c = h->priv_data;
    int r;
    size = FFMIN(size, c->blocksize);
    r = write(c->fd, buf, size);
    return (-1 == r)?AVERROR(errno):r;
}

static int file_get_handle(URLContext *h)
{
    FileContext *c = h->priv_data;
    return c->fd;
}

static int file_check(URLContext *h, int mask)
{
#if HAVE_ACCESS && defined(R_OK)
    int ret = 0;
    if (access(h->filename, F_OK) < 0)
        return AVERROR(errno);
    if (mask&AVIO_FLAG_READ)
        if (access(h->filename, R_OK) >= 0)
            ret |= AVIO_FLAG_READ;
    if (mask&AVIO_FLAG_WRITE)
        if (access(h->filename, W_OK) >= 0)
            ret |= AVIO_FLAG_WRITE;
#else
    struct stat st;
    int ret = stat(h->filename, &st);
    if (ret < 0)
        return AVERROR(errno);

    ret |= st.st_mode&S_IRUSR ? mask&AVIO_FLAG_READ  : 0;
    ret |= st.st_mode&S_IWUSR ? mask&AVIO_FLAG_WRITE : 0;
#endif
    return ret;
}

int analyze_file(const char *filename){
	HdyjFileExt* fileEx;
	int64_t file_size;
	int64_t file_off;
	FILE* pfile;
	char* fill_buf = "1q2w3e4r5t6y7u8i";
	file_info = (FILEMY*)malloc(sizeof(FILEMY));
	fileEx = (HdyjFileExt*)malloc(sizeof(HdyjFileExt));
	memset(fileEx,0,sizeof(HdyjFileExt));
	memset(file_info,0,sizeof(FILEMY));
	memset(DecryptKey,0,16);
	pfile = fopen(filename, "rb+");
	if (pfile){
		fseek(pfile, 0, 2);
		file_size =ftell(pfile);
		file_off = file_size - sizeof(HdyjFileExt);
		fseek(pfile,file_off,0);
		fread(fileEx, sizeof(HdyjFileExt), 1, pfile);
		fseek(pfile, 0, 0);
		if(fileEx->symbol){
			if(!strcmp(fileEx->symbol,"tfbd")){
				file_info->EncrypSize = fileEx->encfile_size;
				file_info->FileOffset = 0;
				file_info->filesize = fileEx->orgfile_size;
				file_info->isEncrypted = TRUE;
                                for (int i = 0; i < 16; i++){
                                        if (i < 10){
                                                DecryptKey[i] = (fileEx->key[i]) ^ *(fill_buf + i);
                                        }
                                        else{
                                                DecryptKey[i] = fileEx->key[i];
                                        }
                                }
                        }else{
                            file_info->isEncrypted = 0;
                            file_info->FileOffset = 0;
                            file_info->EncrypSize = 0;
                            file_info->filesize = file_size;
                        }

                }
	}

	if (pfile)
		fclose(pfile);
	free(fileEx);
    return 0;
}

//int analyze_file1(FileContext *c){
//    HdyjFileExt* fileEx;
//    int64_t file_size;
//    int64_t file_off;
//    char* fill_buf = "1q2w3e4r5t6y7u8i";
//    file_info = (FILEMY*)malloc(sizeof(FILEMY));
//    fileEx = (HdyjFileExt*)malloc(sizeof(HdyjFileExt));
//    memset(fileEx, 0, sizeof(HdyjFileExt));
//    memset(file_info, 0, sizeof(FILEMY));
//    memset(DecryptKey, 0, 16);
//    if (c->fd){
//        lseek(c->fd, 0, 2);
//        file_size = _telli64(c->fd);
//        file_off = file_size - sizeof(HdyjFileExt);
//        lseek(c->fd, file_off, 0);
//        read(c->fd, fileEx, sizeof(HdyjFileExt));
//        lseek(c->fd, 0, 0);
//        if (fileEx->symbol){
//            if (!strcmp(fileEx->symbol, "tfbd")){
//                file_info->EncrypSize = fileEx->encfile_size;
//                file_info->FileOffset = 0;
//                file_info->filesize = fileEx->orgfile_size;
//                file_info->isEncrypted = TRUE;
//            }
//            for (int i = 0; i < 16; i++){
//                if (i < 10){
//                    DecryptKey[i] = (fileEx->key[i]) ^ *(fill_buf + i);
//                }
//                else{
//                    DecryptKey[i] = fileEx->key[i];
//                }
//            };
//        }
//        else{
//            file_info->EncrypSize = 0;
//            file_info->FileOffset = 0;
//            file_info->isEncrypted = 0;
//            file_info->filesize = file_size;
//        }
//    }
//
//    free(fileEx);
//}
#if CONFIG_FILE_PROTOCOL

static int file_open(URLContext *h, const char *filename, int flags)
{
    FileContext *c = h->priv_data;
	//analyze_file(filename);
    int access;
    int fd;
    struct stat st;
	analyze_file(filename);
    av_strstart(filename, "file:", &filename);
    if (flags & AVIO_FLAG_WRITE && flags & AVIO_FLAG_READ) {
        access = O_CREAT | O_RDWR;
        if (c->trunc)
            access |= O_TRUNC;
    } else if (flags & AVIO_FLAG_WRITE) {
        access = O_CREAT | O_WRONLY;
        if (c->trunc)
            access |= O_TRUNC;
    } else {
        access = O_RDONLY;
    }
#ifdef O_BINARY
    access |= O_BINARY;
#endif
    fd = avpriv_open(filename, access, 0666);
    if (fd == -1)
        return AVERROR(errno);	
	
	c->fd = fd;
    h->is_streamed = !fstat(fd, &st) && S_ISFIFO(st.st_mode);

	//analyze_file1(c);
	c->is_enc = file_info->isEncrypted;
	c->file_length = file_info->filesize;
	c->enc_length = file_info->EncrypSize;
	if (file_info->FileOffset){
		c->enc_length += file_info->FileOffset;
	}
	c->offset = 0;
	c->file_offset = file_info->FileOffset;
	c->file_start = file_info->FileOffset;
	/*char *k = bin2hex((char*)DecryptKey, 16);
	char out[200];
	sprintf(out, "print:%d;key:%s", print, k);
	FILE* decprint = fopen("D:\\printdeckey.log", "wb+");
	fwrite(out, 1, strlen(out), decprint);
	fclose(decprint);*/
    return 0;
}

/* XXX: use llseek */
static int64_t file_seek(URLContext *h, int64_t pos, int whence)
{
    FileContext *c = h->priv_data;
    int64_t ret;
	int64_t cur_pos;

    if (whence == AVSEEK_SIZE) {
        struct stat st;
        ret = fstat(c->fd, &st);
        return ret < 0 ? AVERROR(errno) : (S_ISFIFO(st.st_mode) ? 0 : file_info->filesize);
    }
	if(c->file_start){
		pos += c->file_start;
	}
    ret = lseek(c->fd, pos, whence);
	cur_pos = ret;
	c->file_offset = cur_pos;
	c->offset = c->file_offset - c->file_start;
    return ret < 0 ? AVERROR(errno) : ret;
}

static int file_close(URLContext *h)
{
    FileContext *c = h->priv_data;
	free(file_info);
    return close(c->fd);
}

URLProtocol ff_file_protocol = {
    .name                = "file",
    .url_open            = file_open,
    .url_read            = file_read,
    .url_write           = file_write,
    .url_seek            = file_seek,
    .url_close           = file_close,
    .url_get_file_handle = file_get_handle,
    .url_check           = file_check,
    .priv_data_size      = sizeof(FileContext),
    .priv_data_class     = &file_class,
};

#endif /* CONFIG_FILE_PROTOCOL */

#if CONFIG_PIPE_PROTOCOL

static int pipe_open(URLContext *h, const char *filename, int flags)
{
    FileContext *c = h->priv_data;
    int fd;
    char *final;
    av_strstart(filename, "pipe:", &filename);

    fd = strtol(filename, &final, 10);
    if((filename == final) || *final ) {/* No digits found, or something like 10ab */
        if (flags & AVIO_FLAG_WRITE) {
            fd = 1;
        } else {
            fd = 0;
        }
    }
#if HAVE_SETMODE
    setmode(fd, O_BINARY);
#endif
    c->fd = fd;
    h->is_streamed = 1;
    return 0;
}

URLProtocol ff_pipe_protocol = {
    .name                = "pipe",
    .url_open            = pipe_open,
    .url_read            = file_read,
    .url_write           = file_write,
    .url_get_file_handle = file_get_handle,
    .url_check           = file_check,
    .priv_data_size      = sizeof(FileContext),
    .priv_data_class     = &pipe_class,
};

#endif /* CONFIG_PIPE_PROTOCOL */
