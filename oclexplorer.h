/*
 * OCLExplorer bitcoin addresses brute-force tool
 * Copyright (C) 2017 Stanislav V. Tretyakov <svtrostov@yandex.ru>
 * 
 */

#if !defined (__OCL_EXPLORER_H__)
#define __OCL_EXPLORER_H__
#define CL_USE_DEPRECATED_OPENCL_1_2_APIS

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/time.h>
#include <time.h>
#include <stdbool.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <ctype.h>
#include <sys/file.h>
#include <errno.h>
#include <assert.h>
#include <math.h>
#include <CL/cl.h>
#include <inttypes.h>

#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/ripemd.h>


/***********************************************************************
 * Определения и константы
 ***********************************************************************/

/*Работа с битами*/
#define BIT_SET(a,b) ((a) |= (1<<(b)))
#define BIT_CLEAR(a,b) ((a) &= ~(1<<(b)))
#define BIT_FLIP(a,b) ((a) ^= (1<<(b)))
#define BIT_CHECK(a,b) ((a) & (1<<(b)))


/*Конвертация в hex представление*/
static const char hex_asc[] = "0123456789abcdef";
#define hex_asc_0(x)   hex_asc[((x) & 0x0f)]
#define hex_asc_O(x)   hex_asc[((x) & 0xf0) >> 4]

#define MAX_KERNEL 3
#define MAX_ARG 6

#define is_pow2(v) (!((v) & ((v)-1)))
#define round_up_pow2(x, a) (((x) + ((a)-1)) & ~((a)-1))


#define BTREE_HEADER_SIZE (4 + 256*256*256*4)
#define BTREE_LINE (256*4)
#define BTREE_RECORD (24)


#define ACCESS_BUNDLE 1024
#define ACCESS_STRIDE (ACCESS_BUNDLE/8)

#define ARG_FOUND_SIZE 48

/***********************************************************************
 * Структуры
 ***********************************************************************/

/**/
typedef struct ocl_t{
	cl_platform_id		platform_id;	//Платформа
	cl_device_id		device_id;		//Устройство
	cl_context			context;		//Контекст
	cl_command_queue	command;		//Команда
	cl_program			program;		//Программа
	unsigned int		ncols;			//Количество столбцов в матрице
	unsigned int		nrows;			//Количество строк в матрице
	unsigned int		is_unlim_round;	//Признак, указывающий что должно быть неограниченное количество раундов, т.е. поиск с определенного ключа и до победы
	unsigned int		round;			//Общее количество элементов матрицы
	unsigned int		invsize;		//Размер очереди для инверсии mod inverse
	
	unsigned int		quirks;			//Опции компилятора
	cl_kernel			kernel[MAX_KERNEL]; //Внешние функции CL программы на устройстве
	cl_mem				arguments[MAX_ARG];		//Аргументы для функций
	size_t				argument_size[MAX_ARG];	//Размер аргументов

	const char 		*	pkey_base;		//Начальный приватный ключ
	
} ocl_s;


typedef struct binfile_s{
	char * name;
	char * bin_file;
}binfile_s;



typedef struct hashrate_s{
	struct timeval time_start;
	struct timeval time_now;
	double runtime;
	double hashrate;
	const char * unit;
}hashrate_s;


typedef struct{
	uint8_t private_bin[32];
	uint8_t private_hex[65];
	uint8_t private_wif[65];
	uint8_t public_x[32];
	uint8_t public_y[32];
	uint8_t public_bin[65];
	uint8_t public_hex[132];
	uint8_t public_sha256_bin[32];
	uint8_t public_sha256_hex[65];
	uint8_t public_ripemd160_bin[20];
	uint8_t public_ripemd160_hex[41];
	uint8_t address_hex[64];
}keyinfo_s;




/***********************************************************************
 * Глобальные переменные
 ***********************************************************************/








/***********************************************************************
 * Функции - oclexplorer.c
 ***********************************************************************/

int		main(int argc, char **argv);
void 	loop(ocl_s * ocl);







/***********************************************************************
 * Функции - oclengine.c
 ***********************************************************************/

const char * 			ocl_strerror(cl_int ret);
void					ocl_error(int code, const char *desc);
void					ocl_print_info(ocl_s *ocl);

ocl_s *					ocl_init(int platform_id, int device_id, const char * program, uint32_t ncols, uint32_t nrows, uint32_t invsize);
void					ocl_clear(ocl_s *ocl);


cl_platform_id			ocl_platform_get(int num);
int						ocl_platform_list(cl_platform_id **list_out);
void					ocl_platforms_info(cl_platform_id *ids, int np, int base);
const char *			ocl_platform_getstr(cl_platform_id pid, cl_platform_info param);

cl_device_id			ocl_device_manual(int platformidx, int deviceidx);
cl_device_id			ocl_device_get(cl_platform_id pid, int num);
int						ocl_devices_list(cl_platform_id pid, cl_device_id **list_out);
void					ocl_devices_info(cl_platform_id pid, cl_device_id *ids, int nd, int base);
cl_platform_id			ocl_device_getplatform(cl_device_id did);
cl_device_type			ocl_device_gettype(cl_device_id did);
const char *			ocl_device_getstr(cl_device_id did, cl_device_info param);
size_t					ocl_device_getsizet(cl_device_id did, cl_device_info param);
cl_ulong				ocl_device_getulong(cl_device_id did, cl_device_info param);
cl_uint					ocl_device_getuint(cl_device_id did, cl_device_info param);

unsigned int			ocl_get_quirks(cl_device_id did, char * optbuf);
void					ocl_get_quirks_str(unsigned int quirks, char * optbuf);
int						ocl_load_program(ocl_s * ocl, const char *filename, const char *opts);
uint32_t				ocl_hash_program(ocl_s * ocl, const char *opts, const char *program, size_t size);
void					ocl_buildlog(ocl_s * ocl, cl_program prog);
int						ocl_amd_patch_inner(unsigned char *binary, size_t size);
int						ocl_amd_patch(unsigned char *binary, size_t size);

int						ocl_kernel_create(ocl_s *ocl, int knum, const char *func);
int						ocl_kernel_arg_alloc(ocl_s *ocl, int arg, size_t size, int host);
void *					ocl_map_arg_buffer(ocl_s *ocl, int arg, int rw);
void					ocl_unmap_arg_buffer(ocl_s *ocl, int arg, void *buf);
int						ocl_kernel_int_arg(ocl_s *ocl, int kernel, int arg, int value);
int						ocl_kernel_init(ocl_s *ocl);
int						ocl_kernel_start(ocl_s *ocl);

uint32_t				btree_search(const uint32_t * hash, const uint32_t * tree);
void 					btree_add(const uint32_t * hash, uint32_t * tree);
int						btree_load(const char * filename);

void					ocl_get_point(EC_POINT *ppnt, const unsigned char *buf);
void					ocl_put_point(unsigned char *buf, const EC_POINT *ppnt);
void					ocl_put_point_tpa(unsigned char *buf, int cell, const EC_POINT *ppnt);
void					ocl_get_point_tpa(EC_POINT *ppnt, const unsigned char *buf, int cell);



/***********************************************************************
 * Функции - utils.c
 ***********************************************************************/
uint32_t 	hash_crc32(uint32_t crc32_start, const void *buf, size_t n );
uint8_t *	bin2hex(uint8_t * buf, const uint8_t * from, size_t n);
int			hex2bin(uint8_t * buf, const uint8_t * from, size_t n);
double time_diff(struct timeval x , struct timeval y);

void	b58_encode_check(void *buf, size_t len, char *result);
int		b58_decode_check(const char *input, void *buf, size_t len);
void	encode_privkey(const BIGNUM *bn, int addrtype, uint8_t *bin_result, uint8_t *wit_result);
keyinfo_s * 	get_key_info(const BIGNUM * private_key);
int		set_pkey(const BIGNUM *bnpriv, EC_KEY *pkey);
void	hashrate_update(hashrate_s * hr, uint64_t value);




#endif /*__OCL_EXPLORER_H__*/
