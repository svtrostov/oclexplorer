/*
 * OCLExplorer bitcoin addresses brute-force tool
 * Copyright (C) 2017 Stanislav V. Tretyakov <svtrostov@yandex.ru>
 * 
 */

#include "oclexplorer.h"


static uint32_t * BTREE_HEAP;
static uint32_t  BTREE_HEAP_SIZE;


/***********************************************************************
 * OpenCL debugging and support
 ***********************************************************************/

const char *
ocl_strerror(cl_int ret){
#define OCL_STATUS(st) case st: return #st;
	switch (ret) {
		OCL_STATUS(CL_SUCCESS);
		OCL_STATUS(CL_DEVICE_NOT_FOUND);
		OCL_STATUS(CL_DEVICE_NOT_AVAILABLE);
		OCL_STATUS(CL_COMPILER_NOT_AVAILABLE);
		OCL_STATUS(CL_MEM_OBJECT_ALLOCATION_FAILURE);
		OCL_STATUS(CL_OUT_OF_RESOURCES);
		OCL_STATUS(CL_OUT_OF_HOST_MEMORY);
		OCL_STATUS(CL_PROFILING_INFO_NOT_AVAILABLE);
		OCL_STATUS(CL_MEM_COPY_OVERLAP);
		OCL_STATUS(CL_IMAGE_FORMAT_MISMATCH);
		OCL_STATUS(CL_IMAGE_FORMAT_NOT_SUPPORTED);
		OCL_STATUS(CL_BUILD_PROGRAM_FAILURE);
		OCL_STATUS(CL_MAP_FAILURE);
#if defined(CL_MISALIGNED_SUB_BUFFER_OFFSET)
		OCL_STATUS(CL_MISALIGNED_SUB_BUFFER_OFFSET);
#endif /* defined(CL_MISALIGNED_SUB_BUFFER_OFFSET) */
#if defined(CL_EXEC_STATUS_ERROR_FOR_EVENTS_IN_WAIT_LIST)
		OCL_STATUS(CL_EXEC_STATUS_ERROR_FOR_EVENTS_IN_WAIT_LIST);
#endif /* defined(CL_EXEC_STATUS_ERROR_FOR_EVENTS_IN_WAIT_LIST) */
		OCL_STATUS(CL_INVALID_VALUE);
		OCL_STATUS(CL_INVALID_DEVICE_TYPE);
		OCL_STATUS(CL_INVALID_PLATFORM);
		OCL_STATUS(CL_INVALID_DEVICE);
		OCL_STATUS(CL_INVALID_CONTEXT);
		OCL_STATUS(CL_INVALID_QUEUE_PROPERTIES);
		OCL_STATUS(CL_INVALID_COMMAND_QUEUE);
		OCL_STATUS(CL_INVALID_HOST_PTR);
		OCL_STATUS(CL_INVALID_MEM_OBJECT);
		OCL_STATUS(CL_INVALID_IMAGE_FORMAT_DESCRIPTOR);
		OCL_STATUS(CL_INVALID_IMAGE_SIZE);
		OCL_STATUS(CL_INVALID_SAMPLER);
		OCL_STATUS(CL_INVALID_BINARY);
		OCL_STATUS(CL_INVALID_BUILD_OPTIONS);
		OCL_STATUS(CL_INVALID_PROGRAM);
		OCL_STATUS(CL_INVALID_PROGRAM_EXECUTABLE);
		OCL_STATUS(CL_INVALID_KERNEL_NAME);
		OCL_STATUS(CL_INVALID_KERNEL_DEFINITION);
		OCL_STATUS(CL_INVALID_KERNEL);
		OCL_STATUS(CL_INVALID_ARG_INDEX);
		OCL_STATUS(CL_INVALID_ARG_VALUE);
		OCL_STATUS(CL_INVALID_ARG_SIZE);
		OCL_STATUS(CL_INVALID_KERNEL_ARGS);
		OCL_STATUS(CL_INVALID_WORK_DIMENSION);
		OCL_STATUS(CL_INVALID_WORK_GROUP_SIZE);
		OCL_STATUS(CL_INVALID_WORK_ITEM_SIZE);
		OCL_STATUS(CL_INVALID_GLOBAL_OFFSET);
		OCL_STATUS(CL_INVALID_EVENT_WAIT_LIST);
		OCL_STATUS(CL_INVALID_EVENT);
		OCL_STATUS(CL_INVALID_OPERATION);
		OCL_STATUS(CL_INVALID_GL_OBJECT);
		OCL_STATUS(CL_INVALID_BUFFER_SIZE);
		OCL_STATUS(CL_INVALID_MIP_LEVEL);
		OCL_STATUS(CL_INVALID_GLOBAL_WORK_SIZE);
#if defined(CL_INVALID_PROPERTY)
		OCL_STATUS(CL_INVALID_PROPERTY);
#endif /* defined(CL_INVALID_PROPERTY) */
#undef OCL_STATUS
	default: {
		static char tmp[64];
		snprintf(tmp, sizeof(tmp), "Unknown code %d", ret);
		return tmp;
	}
	}
}

void
ocl_error(int code, const char *desc){
	const char *err = ocl_strerror(code);
	if (desc) {
		fprintf(stderr, "%s: %s\n", desc, err);
	} else {
		fprintf(stderr, "%s\n", err);
	}
}


/*Вывод информации о текущем устройстве и платформе*/
void
ocl_print_info(ocl_s *ocl){
	cl_device_id did = ocl->device_id;

	fprintf(stderr, "\n==[SELECTED DEVICE INFO]============================\n");
	fprintf(stderr, "Device: %s\n", ocl_device_getstr(did, CL_DEVICE_NAME));
	fprintf(stderr, "Vendor: %s (%04x)\n", ocl_device_getstr(did, CL_DEVICE_VENDOR), ocl_device_getuint(did, CL_DEVICE_VENDOR_ID));
	fprintf(stderr, "Driver: %s\n", ocl_device_getstr(did, CL_DRIVER_VERSION));
	fprintf(stderr, "Profile: %s\n", ocl_device_getstr(did, CL_DEVICE_PROFILE));
	fprintf(stderr, "Version: %s\n", ocl_device_getstr(did, CL_DEVICE_VERSION));
	fprintf(stderr, "Max compute units: %zd\n", ocl_device_getsizet(did, CL_DEVICE_MAX_COMPUTE_UNITS));
	fprintf(stderr, "Max workgroup size: %zd\n", ocl_device_getsizet(did, CL_DEVICE_MAX_WORK_GROUP_SIZE));
	fprintf(stderr, "Global memory: %ld\n", ocl_device_getulong(did, CL_DEVICE_GLOBAL_MEM_SIZE));
	fprintf(stderr, "Max allocation: %ld\n\n", ocl_device_getulong(did, CL_DEVICE_MAX_MEM_ALLOC_SIZE));
}



/***********************************************************************
 * OCL
 ***********************************************************************/

/*Инициализация устройства и компиляция программы*/
ocl_s *
ocl_init(int platform_id, int device_id, const char * program, uint32_t ncols, uint32_t nrows, uint32_t invsize){

	ocl_s * ocl = (ocl_s *)calloc(1, sizeof(ocl_s));

	/* получить доступные платформы */
	if((ocl->platform_id = ocl_platform_get(platform_id)) == NULL) return NULL;

	/* получить доступные устройства */
	if((ocl->device_id = ocl_device_get(ocl->platform_id, device_id)) == NULL) return NULL;


	cl_int ret;

	/* создать контекст */
	ocl->context = clCreateContext(NULL, 1, &(ocl->device_id), NULL, NULL, &ret);
	if (!ocl->context){
		ocl_error(ret, "clCreateContext");
		return NULL;
	}

	/* создаем команду */
	ocl->command = clCreateCommandQueue(ocl->context, ocl->device_id, 0, &ret);
	if (!ocl->context){
		ocl_error(ret, "clCreateCommandQueue");
		return NULL;
	}


	/* получить опции компилятора */
	char optbuf[256];
	ocl->quirks = ocl_get_quirks(ocl->device_id, optbuf);

	/*Загрузка и компиляция CL программы*/
	if(!ocl_load_program(ocl, program, optbuf)) return NULL;


	/*Вычисление настроек матрицы*/

	/*Количество одновременно выполняемых потоков на GPU*/
	size_t nthreads = ocl_device_getsizet(ocl->device_id, CL_DEVICE_MAX_WORK_GROUP_SIZE);
	size_t full_threads = ocl_device_getsizet(ocl->device_id, CL_DEVICE_MAX_COMPUTE_UNITS);
	full_threads *= nthreads;

	cl_ulong memsize	= ocl_device_getulong(ocl->device_id, CL_DEVICE_GLOBAL_MEM_SIZE);
	cl_ulong allocsize	= ocl_device_getulong(ocl->device_id, CL_DEVICE_MAX_MEM_ALLOC_SIZE);
	memsize /= 2;

	if(!ncols || !nrows){

		ncols = full_threads;
		nrows = 2;
		while ((ncols > nrows) && !(ncols & 1)){
			ncols /= 2;
			nrows *= 2;
		}

		int worksize = 2048; //defult is 2048
		int wsmult = 1;
		while ((!worksize || ((wsmult * 2) <= worksize)) &&
			   ((ncols * nrows * 2 * 128) < memsize) &&
			   ((ncols * nrows * 2 * 64) < allocsize)) {
			if (ncols > nrows)
				nrows *= 2;
			else
				ncols *= 2;
			wsmult *= 2;
		}

	}

	uint32_t round = nrows * ncols;

	if(!invsize){
		invsize = 2;
		while(!(round % (invsize << 1)) && ((round / invsize) > full_threads)) invsize <<= 1;
	}

	if ((round % invsize) || !is_pow2(invsize) || (invsize < 2)) {
		fprintf(stderr, "Grid size: %dx%d\n", ncols, nrows);
		fprintf(stderr, "Modular inverse thread size: %d\n", invsize);
		if (round % invsize)
			fprintf(stderr, "Modular inverse work size must evenly divide points\n");
		else
			fprintf(stderr, "Modular inverse work per task (%d) must be a power of 2\n", invsize);
		return NULL;
	}

	ocl->ncols = ncols;
	ocl->nrows = nrows;
	ocl->round = round;
	ocl->invsize = invsize;

	printf("Grid size: %dx%d, total %d\n", ncols, nrows, round);
	printf("Modular inverse: %d threads, %d ops each\n", round/invsize, invsize);

	return ocl;

}/*END: ocl_init()*/



static void
ocl_free_kernel(ocl_s *ocl){
	int i, arg;
	for (arg = 0; arg < MAX_ARG; arg++) {
		if (ocl->arguments[arg]) {
			clReleaseMemObject(ocl->arguments[arg]);
			ocl->arguments[arg] = NULL;
			ocl->argument_size[arg] = 0;
		}
	}
	for (i = 0; i < MAX_KERNEL; i++) {
		if(ocl->kernel[i]){
			clReleaseKernel(ocl->kernel[i]);
			ocl->kernel[i] = NULL;
		}
	}
}


/*Удаление устройства*/
void
ocl_clear(ocl_s * ocl){

	ocl_free_kernel(ocl);

	if (ocl->program) {
		clReleaseProgram(ocl->program);
	}
	if (ocl->command) {
		clReleaseCommandQueue(ocl->command);
	}
	if (ocl->context) {
		clReleaseContext(ocl->context);
	}

	memset(ocl, 0, sizeof(ocl_s));

}





/***********************************************************************
 * PLATFORM
 ***********************************************************************/
 
/*Получение платформы*/
cl_platform_id
ocl_platform_get(int num){

	int np;
	cl_platform_id id, *ids;

	np = ocl_platform_list(&ids);
	if (np < 0) return NULL;
	if (!np){
		fprintf(stderr, "No OpenCL platforms available\n");
		return NULL;
	}
	if (num < 0) {
		if (np == 1) 
			num = 0;
		else
			num = np;
	}
	if (num < np) {
		id = ids[num];
		free(ids);
		return id;
	}
	free(ids);
	return NULL;
}


/*Получение списка доступных платформ*/
int
ocl_platform_list(cl_platform_id **list_out){
	cl_uint np;
	cl_int res;
	cl_platform_id *ids;
	res = clGetPlatformIDs(0, NULL, &np);
	if (res != CL_SUCCESS) {
		ocl_error(res, "clGetPlatformIDs(0)");
		*list_out = NULL;
		return -1;
	}
	if (np) {
		ids = (cl_platform_id *) malloc(np * sizeof(*ids));
		if (ids == NULL) {
			fprintf(stderr,
				"Could not allocate platform ID list\n");
			*list_out = NULL;
			return -1;
		}
		res = clGetPlatformIDs(np, ids, NULL);
		if (res != CL_SUCCESS) {
			ocl_error(res, "clGetPlatformIDs(n)");
			free(ids);
			*list_out = NULL;
			return -1;
		}
		*list_out = ids;
	}
	return np;
}

/*Вывод информации о доступных платформах*/
void
ocl_platforms_info(cl_platform_id *ids, int np, int base){
	int i;
	char nbuf[128];
	char vbuf[128];
	size_t len;
	cl_int res;

	for (i = 0; i < np; i++) {
		res = clGetPlatformInfo(ids[i], CL_PLATFORM_NAME, sizeof(nbuf), nbuf, &len);
		if (res != CL_SUCCESS) {
			ocl_error(res, "clGetPlatformInfo(NAME)");
			continue;
		}
		if (len >= sizeof(nbuf))
			len = sizeof(nbuf) - 1;
		nbuf[len] = '\0';
		res = clGetPlatformInfo(ids[i], CL_PLATFORM_VENDOR, sizeof(vbuf), vbuf, &len);
		if (res != CL_SUCCESS) {
			ocl_error(res, "clGetPlatformInfo(VENDOR)");
			continue;
		}
		if (len >= sizeof(vbuf))
			len = sizeof(vbuf) - 1;
		vbuf[len] = '\0';
		fprintf(stderr, "%d: [%s] %s\n", i + base, vbuf, nbuf);
	}
}


const char *
ocl_platform_getstr(cl_platform_id pid, cl_platform_info param){
	static char platform_str[1024];
	cl_int ret;
	size_t size_ret;
	ret = clGetPlatformInfo(pid, param,
				sizeof(platform_str), platform_str,
				&size_ret);
	if (ret != CL_SUCCESS) {
		snprintf(platform_str, sizeof(platform_str),
			 "clGetPlatformInfo(%d): %s",
			 param, ocl_strerror(ret));
	}
	return platform_str;
}



/***********************************************************************
 * DEVICE
 ***********************************************************************/

/*Получение заданного устройства в указанной платформе*/
cl_device_id
ocl_device_manual(int platformidx, int deviceidx){
	cl_platform_id pid;
	cl_device_id did = NULL;

	pid = ocl_platform_get(platformidx);
	if (pid) {
		did = ocl_device_get(pid, deviceidx);
		if (did)
			return did;
	}
	return NULL;
}

/*Получение устройства*/
cl_device_id
ocl_device_get(cl_platform_id pid, int num){
	int nd;
	cl_device_id id, *ids;

	nd = ocl_devices_list(pid, &ids);
	if (nd < 0)
		return NULL;
	if (!nd) {
		fprintf(stderr, "No OpenCL devices found\n");
		return NULL;
	}
	if (num < 0) {
		if (nd == 1)
			num = 0;
		else
			num = nd;
	}
	if (num < nd) {
		id = ids[num];
		free(ids);
		return id;
	}
	free(ids);
	return NULL;
}


/*Список устройств платформы*/
int
ocl_devices_list(cl_platform_id pid, cl_device_id **list_out){
	cl_uint nd;
	cl_int res;
	cl_device_id *ids;
	res = clGetDeviceIDs(pid, CL_DEVICE_TYPE_GPU, 0, NULL, &nd);
	if (res != CL_SUCCESS) {
		ocl_error(res, "clGetDeviceIDs(0)");
		*list_out = NULL;
		return -1;
	}
	if (nd) {
		ids = (cl_device_id *) malloc(nd * sizeof(*ids));
		if (ids == NULL) {
			fprintf(stderr, "Could not allocate device ID list\n");
			*list_out = NULL;
			return -1;
		}
		res = clGetDeviceIDs(pid, CL_DEVICE_TYPE_GPU, nd, ids, NULL);
		if (res != CL_SUCCESS) {
			ocl_error(res, "clGetDeviceIDs(n)");
			free(ids);
			*list_out = NULL;
			return -1;
		}
		*list_out = ids;
	}
	return nd;
}


/*Информация об устройствах платформы*/
void
ocl_devices_info(cl_platform_id pid, cl_device_id *ids, int nd, int base){
	int i;
	char nbuf[128];
	char vbuf[128];
	size_t len;
	cl_int res;

	for (i = 0; i < nd; i++) {
		res = clGetDeviceInfo(ids[i], CL_DEVICE_NAME, sizeof(nbuf), nbuf, &len);
		if (res != CL_SUCCESS) continue;
		if (len >= sizeof(nbuf))
			len = sizeof(nbuf) - 1;
		nbuf[len] = '\0';
		res = clGetDeviceInfo(ids[i], CL_DEVICE_VENDOR, sizeof(vbuf), vbuf, &len);
		if (res != CL_SUCCESS) continue;
		if (len >= sizeof(vbuf))
			len = sizeof(vbuf) - 1;
		vbuf[len] = '\0';
		fprintf(stderr, "  %d: [%s] %s\n", i + base, vbuf, nbuf);
	}
}

/*Возвращает платформу заданного устройства*/
cl_platform_id
ocl_device_getplatform(cl_device_id did){
	cl_int ret;
	cl_platform_id val;
	size_t size_ret;
	ret = clGetDeviceInfo(did, CL_DEVICE_PLATFORM,
			      sizeof(val), &val, &size_ret);
	if (ret != CL_SUCCESS) {
		fprintf(stderr, "clGetDeviceInfo(CL_DEVICE_PLATFORM): %s",
			ocl_strerror(ret));
	}
	return val;
}

/*Возвращает тип устройства*/
cl_device_type
ocl_device_gettype(cl_device_id did){
	cl_int ret;
	cl_device_type val;
	size_t size_ret;
	ret = clGetDeviceInfo(did, CL_DEVICE_TYPE,
			      sizeof(val), &val, &size_ret);
	if (ret != CL_SUCCESS) {
		fprintf(stderr, "clGetDeviceInfo(CL_DEVICE_TYPE): %s",
			ocl_strerror(ret));
	}
	return val;
}

/*Возвращает текстовый параметр устройства*/
const char *
ocl_device_getstr(cl_device_id did, cl_device_info param){
	static char device_str[1024];
	cl_int ret;
	size_t size_ret;
	ret = clGetDeviceInfo(did, param,
			      sizeof(device_str), device_str,
			      &size_ret);
	if (ret != CL_SUCCESS) {
		snprintf(device_str, sizeof(device_str),
			 "clGetDeviceInfo(%d): %s",
			 param, ocl_strerror(ret));
	}
	return device_str;
}

/*Возвращает size_t параметр устройства*/
size_t
ocl_device_getsizet(cl_device_id did, cl_device_info param){
	cl_int ret;
	size_t val;
	size_t size_ret;
	ret = clGetDeviceInfo(did, param, sizeof(val), &val, &size_ret);
	if (ret != CL_SUCCESS) {
		fprintf(stderr,
			"clGetDeviceInfo(%d): %s", param, ocl_strerror(ret));
	}
	return val;
}

/*Возвращает cl_ulong параметр устройства*/
cl_ulong
ocl_device_getulong(cl_device_id did, cl_device_info param){
	cl_int ret;
	cl_ulong val;
	size_t size_ret;
	ret = clGetDeviceInfo(did, param, sizeof(val), &val, &size_ret);
	if (ret != CL_SUCCESS) {
		fprintf(stderr,
			"clGetDeviceInfo(%d): %s", param, ocl_strerror(ret));
	}
	return val;
}

/*Возвращает cl_uint параметр устройства*/
cl_uint
ocl_device_getuint(cl_device_id did, cl_device_info param){
	cl_int ret;
        cl_uint val;
	size_t size_ret;
	ret = clGetDeviceInfo(did, param, sizeof(val), &val, &size_ret);
	if (ret != CL_SUCCESS) {
		fprintf(stderr,
			"clGetDeviceInfo(%d): %s", param, ocl_strerror(ret));
	}
	return val;
}


enum {
	VG_OCL_DEEP_PREPROC_UNROLL  = (1 << 0),
	VG_OCL_PRAGMA_UNROLL        = (1 << 1),
	VG_OCL_EXPENSIVE_BRANCHES   = (1 << 2),
	VG_OCL_DEEP_VLIW            = (1 << 3),
	VG_OCL_AMD_BFI_INT          = (1 << 4),
	VG_OCL_NV_VERBOSE           = (1 << 5),
	VG_OCL_BROKEN               = (1 << 6),
	VG_OCL_NO_BINARIES          = (1 << 7),

	VG_OCL_OPTIMIZATIONS        = (VG_OCL_DEEP_PREPROC_UNROLL |
				       VG_OCL_PRAGMA_UNROLL |
				       VG_OCL_EXPENSIVE_BRANCHES |
				       VG_OCL_DEEP_VLIW |
				       VG_OCL_AMD_BFI_INT),

};


/*Вычисление исходя из устройства опций для компиляции*/
unsigned int
ocl_get_quirks(cl_device_id did, char * optbuf){
	uint32_t vend;
	const char *dvn;
	unsigned int quirks = 0;

	quirks |= VG_OCL_DEEP_PREPROC_UNROLL;

	vend = ocl_device_getuint(did, CL_DEVICE_VENDOR_ID);
	switch (vend) {
	case 0x10de: /* NVIDIA */
		/*
		 * NVIDIA's compiler seems to take a really really long
		 * time when using preprocessor unrolling, but works
		 * well with pragma unroll.
		 */
		quirks &= ~VG_OCL_DEEP_PREPROC_UNROLL;
		quirks |= VG_OCL_PRAGMA_UNROLL;
		quirks |= VG_OCL_NV_VERBOSE;
		break;
	case 0x1002: /* AMD/ATI */
		/*
		 * AMD's compiler works best with preprocesor unrolling.
		 * Pragma unroll is unreliable with AMD's compiler and
		 * seems to crash based on whether the gods were smiling
		 * when Catalyst was last installed/upgraded.
		 */
		if (ocl_device_gettype(did) & CL_DEVICE_TYPE_GPU) {
			quirks |= VG_OCL_EXPENSIVE_BRANCHES;
			quirks |= VG_OCL_DEEP_VLIW;
			dvn = ocl_device_getstr(did, CL_DEVICE_EXTENSIONS);
			if (dvn && strstr(dvn, "cl_amd_media_ops"))
				quirks |= VG_OCL_AMD_BFI_INT;

			dvn = ocl_device_getstr(did, CL_DEVICE_NAME);
			if (!strcmp(dvn, "ATI RV710")) {
				quirks &= ~VG_OCL_OPTIMIZATIONS;
				quirks |= VG_OCL_NO_BINARIES;
			}
		}
		break;
	default:
		break;
	}

	if(optbuf) ocl_get_quirks_str(quirks, optbuf);

	return quirks;
}


/*Получение строки опций для компиляции из вычесленного значения ocl_get_quirks()*/
void
ocl_get_quirks_str(unsigned int quirks, char * optbuf){

	int end = 0;
	if (quirks & VG_OCL_DEEP_PREPROC_UNROLL)
		end += sprintf(optbuf + end, "-DDEEP_PREPROC_UNROLL ");
	if (quirks & VG_OCL_PRAGMA_UNROLL)
		end += sprintf(optbuf + end, "-DPRAGMA_UNROLL ");
	if (quirks & VG_OCL_EXPENSIVE_BRANCHES)
		end += sprintf(optbuf + end, "-DVERY_EXPENSIVE_BRANCHES ");
	if (quirks & VG_OCL_DEEP_VLIW)
		end += sprintf(optbuf + end, "-DDEEP_VLIW ");
	if (quirks & VG_OCL_AMD_BFI_INT)
		end += sprintf(optbuf + end, "-DAMD_BFI_INT ");
	if (quirks & VG_OCL_NV_VERBOSE)
		end += sprintf(optbuf + end, "-cl-nv-verbose ");
	optbuf[end] = '\0';
}



/***********************************************************************
 * PROGRAM
 ***********************************************************************/


int
ocl_load_program(ocl_s * ocl, const char *filename, const char *opts){
	FILE *kfp;
	char *buf, *tbuf;
	int len, fromsource = 0, patched = 0;
	size_t sz, szr;
	cl_program prog;
	cl_int ret, sts;
	uint32_t prog_hash = 0;
	char bin_name[64];
	uint8_t * ptr;

	sz = 128 * 1024;
	buf = (char *) malloc(sz);
	if (!buf) {
		fprintf(stderr, "Could not allocate program buffer\n");
		return 0;
	}

	fprintf(stderr, "Load program file: %s\n",filename);
	kfp = fopen(filename, "r");
	if (!kfp) {
		fprintf(stderr, "Error loading kernel file '%s': %s\n",
		       filename, strerror(errno));
		free(buf);
		return 0;
	}

	len = fread(buf, 1, sz, kfp);
	fclose(kfp);
	kfp = NULL;

	if (!len) {
		fprintf(stderr, "Short read on CL kernel\n");
		free(buf);
		return 0;
	}

	prog_hash = ocl_hash_program(ocl, opts, buf, len);
	ptr = (uint8_t *)&prog_hash;
	sprintf(bin_name, "%02x%02x%02x%02x.oclbin", ptr[0], ptr[1], ptr[2], ptr[3]);

	if (ocl->quirks & VG_OCL_NO_BINARIES) {
		//
	} else {
		kfp = fopen(bin_name, "rb");
	}

	//Нет бинарника, компилируем из исходника
	if (!kfp) {
		fromsource = 1;
		sz = len;
		prog = clCreateProgramWithSource(ocl->context,
						 1, (const char **) &buf, &sz,
						 &ret);
	} else {
		szr = 0;
		while (!feof(kfp)) {
			len = fread(buf + szr, 1, sz - szr, kfp);
			if (!len) {
				fprintf(stderr,
					"Short read on CL kernel binary\n");
				fclose(kfp);
				free(buf);
				return 0;
			}
			szr += len;
			if (szr == sz) {
				tbuf = (char *) realloc(buf, sz*2);
				if (!tbuf) {
					fprintf(stderr,
						"Could not expand CL kernel "
						"binary buffer\n");
					fclose(kfp);
					free(buf);
					return 0;
				}
				buf = tbuf;
				sz *= 2;
			}
		}
		fclose(kfp);
	rebuild:
		prog = clCreateProgramWithBinary(ocl->context,
						 1, &ocl->device_id,
						 &szr,
						 (const unsigned char **) &buf,
						 &sts,
						 &ret);
	}
	free(buf);
	if (!prog) {
		ocl_error(ret, "clCreateProgramWithSource");
		return 0;
	}

	if (fromsource && !patched) {
		fprintf(stderr,"Compiling CL, can take minutes...");
		fflush(stderr);
	}

	ret = clBuildProgram(prog, 1, &ocl->device_id, opts, NULL, NULL);
	if (ret != CL_SUCCESS) {
		if (fromsource && !patched) fprintf(stderr, "failure.\n");
		ocl_error(ret, "clBuildProgram");
		ocl_buildlog(ocl, prog);
		clReleaseProgram(prog);
		return 0;
	}

	if (fromsource && !(ocl->quirks & VG_OCL_NO_BINARIES)) {
		ret = clGetProgramInfo(prog,
				       CL_PROGRAM_BINARY_SIZES,
				       sizeof(szr), &szr,
				       &sz);
		if (ret != CL_SUCCESS) {
			ocl_error(ret,
				     "WARNING: clGetProgramInfo(BINARY_SIZES)");
			goto out;
		}
		if (sz == 0) {
			fprintf(stderr,
				"WARNING: zero-length CL kernel binary\n");
			goto out;
		}

		buf = (char *) malloc(szr);
		if (!buf) {
			fprintf(stderr,
				"WARNING: Could not allocate %zd bytes "
				"for CL binary\n",
			       szr);
			goto out;
		}

		ret = clGetProgramInfo(prog,
				       CL_PROGRAM_BINARIES,
				       sizeof(buf), &buf,
				       &sz);
		if (ret != CL_SUCCESS) {
			ocl_error(ret,
				     "WARNING: clGetProgramInfo(BINARIES)");
			free(buf);
			goto out;
		}

		if ((ocl->quirks & VG_OCL_AMD_BFI_INT) && !patched) {
			patched = ocl_amd_patch((unsigned char *) buf, szr);
			if (patched > 0) {
				clReleaseProgram(prog);
				goto rebuild;
			}
			fprintf(stderr,
				"WARNING: AMD BFI_INT patching failed\n");
			if (patched < 0) {
				/* Program was incompletely modified */
				free(buf);
				goto out;
			}
		}

		kfp = fopen(bin_name, "wb");
		if (!kfp) {
			fprintf(stderr, "WARNING: "
				"could not save CL kernel binary: %s\n",
				strerror(errno));
		} else {
			sz = fwrite(buf, 1, szr, kfp);
			fclose(kfp);
			if (sz != szr) {
				fprintf(stderr,
					"WARNING: short write on CL kernel "
					"binary file: expected "
					"%zd, got %zd\n",
					szr, sz);
				unlink(bin_name);
			}
		}
		free(buf);
	}

out:
	ocl->program = prog;

	return 1;
}



/*Получение CRC32 хеша программы*/
uint32_t
ocl_hash_program(ocl_s * ocl, const char *opts, const char *program, size_t size){

	const char *str;
	uint32_t h = 0;

	cl_platform_id pid = ocl_device_getplatform(ocl->device_id);

	str = ocl_platform_getstr(pid, CL_PLATFORM_NAME);
	h = hash_crc32(h, str, strlen(str));

	str = ocl_platform_getstr(pid, CL_PLATFORM_VERSION);
	h = hash_crc32(h, str, strlen(str));

	str = ocl_device_getstr(ocl->device_id, CL_DEVICE_NAME);
	h = hash_crc32(h, str, strlen(str));

	if (opts) h = hash_crc32(h, opts, strlen(opts));
	if (program && size) h = hash_crc32(h, program, size);

	return h;
}


/*Построение лога процесса компиляции программы*/
void
ocl_buildlog(ocl_s * ocl, cl_program prog){
	size_t logbufsize, logsize;
	char *log;
	int off = 0;
	cl_int ret;

	ret = clGetProgramBuildInfo(prog,
				    ocl->device_id,
				    CL_PROGRAM_BUILD_LOG,
				    0, NULL,
				    &logbufsize);
	if (ret != CL_SUCCESS) {
		ocl_error(ret, "clGetProgramBuildInfo");
		return;
	}

	log = (char *) malloc(logbufsize);
	if (!log) {
		fprintf(stderr, "Could not allocate build log buffer\n");
		return;
	}

	ret = clGetProgramBuildInfo(prog,
				    ocl->device_id,
				    CL_PROGRAM_BUILD_LOG,
				    logbufsize,
				    log,
				    &logsize);
	if (ret != CL_SUCCESS) {
		ocl_error(ret, "clGetProgramBuildInfo");

	} else {
		/* Remove leading newlines and trailing newlines/whitespace */
		log[logbufsize-1] = '\0';
		for (off = logsize - 1; off >= 0; off--) {
			if ((log[off] != '\r') &&
			    (log[off] != '\n') &&
			    (log[off] != ' ') &&
			    (log[off] != '\t') &&
			    (log[off] != '\0'))
				break;
			log[off] = '\0';
		}
		for (off = 0; off < logbufsize; off++) {
			if ((log[off] != '\r') &&
			    (log[off] != '\n'))
				break;
		}

		fprintf(stderr, "Build log:\n%s\n", &log[off]);
	}
	free(log);
}



typedef struct {
	unsigned char	e_ident[16];
	uint16_t	e_type;
	uint16_t	e_machine;
	uint32_t	e_version;
	uint32_t	e_entry;
	uint32_t	e_phoff;
	uint32_t	e_shoff;
	uint32_t	e_flags;
	uint16_t	e_ehsize;
	uint16_t	e_phentsize;
	uint16_t	e_phnum;
	uint16_t	e_shentsize;
	uint16_t	e_shnum;
	uint16_t	e_shstrndx;
} vg_elf32_header_t;

typedef struct {
	uint32_t	sh_name;
	uint32_t	sh_type;
	uint32_t	sh_flags;
	uint32_t	sh_addr;
	uint32_t	sh_offset;
	uint32_t	sh_size;
	uint32_t	sh_link;
	uint32_t	sh_info;
	uint32_t	sh_addralign;
	uint32_t	sh_entsize;
} vg_elf32_shdr_t;

int
ocl_amd_patch_inner(unsigned char *binary, size_t size){
	vg_elf32_header_t *ehp;
	vg_elf32_shdr_t *shp, *nshp;
	uint32_t *instr;
	size_t off;
	int i, n, txt2idx, patched;

	ehp = (vg_elf32_header_t *) binary;
	if ((size < sizeof(*ehp)) ||
	    memcmp(ehp->e_ident, "\x7f" "ELF\1\1\1\x64", 8) ||
	    !ehp->e_shoff)
		return 0;

	off = ehp->e_shoff + (ehp->e_shstrndx * ehp->e_shentsize);
	nshp = (vg_elf32_shdr_t *) (binary + off);
	if ((off + sizeof(*nshp)) > size)
		return 0;

	shp = (vg_elf32_shdr_t *) (binary + ehp->e_shoff);
	n = 0;
	txt2idx = 0;
	for (i = 0; i < ehp->e_shnum; i++) {
		off = nshp->sh_offset + shp[i].sh_name;
		if (((off + 6) >= size) ||
		    memcmp(binary + off, ".text", 6))
			continue;
		n++;
		if (n == 2)
			txt2idx = i;
	}
	if (n != 2)
		return 0;

	off = shp[txt2idx].sh_offset;
	instr = (uint32_t *) (binary + off);
	n = shp[txt2idx].sh_size / 4;
	patched = 0;
	for (i = 0; i < n; i += 2) {
		if (((instr[i] & 0x02001000) == 0) &&
		    ((instr[i+1] & 0x9003f000) == 0x0001a000)) {
			instr[i+1] ^= (0x0001a000 ^ 0x0000c000);
			patched++;
		}
	}

	return patched;
}

/*Патчим AMD*/
int
ocl_amd_patch(unsigned char *binary, size_t size){
	vg_elf32_header_t *ehp;
	unsigned char *ptr;
	size_t offset = 1;
	int ninner = 0, nrun, npatched = 0;

	ehp = (vg_elf32_header_t *) binary;
	if ((size < sizeof(*ehp)) ||
	    memcmp(ehp->e_ident, "\x7f" "ELF\1\1\1\0", 8) ||
	    !ehp->e_shoff)
		return 0;

	offset = 1;
	while (offset < (size - 8)) {
		ptr = (unsigned char *) memchr(binary + offset,
					       0x7f,
					       size - offset);
		if (!ptr)
			return npatched;
		offset = ptr - binary;
		ehp = (vg_elf32_header_t *) ptr;
		if (((size - offset) < sizeof(*ehp)) ||
		    memcmp(ehp->e_ident, "\x7f" "ELF\1\1\1\x64", 8) ||
		    !ehp->e_shoff) {
			offset += 1;
			continue;
		}

		ninner++;
		nrun = ocl_amd_patch_inner(ptr, size - offset);
		npatched += nrun;
		npatched++;
		offset += 1;
	}
	return npatched;
}




/***********************************************************************
 * PROGRAM KERNEL
 ***********************************************************************/

/*Регистрация функции*/
int
ocl_kernel_create(ocl_s *ocl, int knum, const char *func){
	cl_kernel krn;
	cl_int ret;

	krn = clCreateKernel(ocl->program, func, &ret);
	if (!krn) {
		fprintf(stderr, "clCreateKernel(%s)",func);
		ocl_error(ret, NULL);
		clReleaseKernel(ocl->kernel[knum]);
		ocl->kernel[knum] = NULL;
		return 0;
	}

	ocl->kernel[knum] = krn;
	return 1;
}


static int ocl_arg_map[][8] = {
	/* hashes_out / found */
	{ 2, 0, -1 },
	/* z_heap */
	{ 0, 1, 1, 0, 2, 2, -1 },
	/* point_tmp */
	{ 0, 0, 2, 1, -1 },
	/* row_in */
	{ 0, 2, -1 },
	/* col_in */
	{ 0, 3, -1 },
	/* target_table */
	{ 2, 3, -1 },
};

/*Регистрация аргумента*/
int
ocl_kernel_arg_alloc(ocl_s *ocl, int arg, size_t size, int host){
	cl_mem clbuf;
	cl_int ret;
	int j, knum, karg;

	if (ocl->arguments[arg]){
		clReleaseMemObject(ocl->arguments[arg]);
		ocl->arguments[arg] 	= NULL;
		ocl->argument_size[arg]	= 0;
	}

	clbuf = clCreateBuffer(ocl->context, CL_MEM_READ_WRITE | (host ? CL_MEM_ALLOC_HOST_PTR : 0), size, NULL, &ret);
	if (!clbuf){
		fprintf(stderr, "clCreateBuffer(%d): ", arg);
		ocl_error(ret, NULL);
		return 0;
	}

	clRetainMemObject(clbuf);
	ocl->arguments[arg] = clbuf;
	ocl->argument_size[arg] = size;

	for (j = 0; ocl_arg_map[arg][j] >= 0; j += 2) {
		knum = ocl_arg_map[arg][j];
		karg = ocl_arg_map[arg][j+1];
		ret = clSetKernelArg(ocl->kernel[knum], karg, sizeof(clbuf), &clbuf);
		if (ret) {
			fprintf(stderr, "clSetKernelArg(%d,%d): ", knum, karg);
			ocl_error(ret, NULL);
			return 0;
		}
	}

	clReleaseMemObject(clbuf);
	return 1;
}


void *
ocl_map_arg_buffer(ocl_s *ocl, int arg, int rw){
	void *buf;
	cl_int ret;
	buf = clEnqueueMapBuffer(ocl->command,
				ocl->arguments[arg],
				CL_TRUE,
				(rw == 2) ? (CL_MAP_READ|CL_MAP_WRITE)
				          : (rw ? CL_MAP_WRITE : CL_MAP_READ),
				0, ocl->argument_size[arg],
				0, NULL,
				NULL,
				&ret);
	if (!buf){
		fprintf(stderr, "clEnqueueMapBuffer(%d): ", arg);
		ocl_error(ret, NULL);
		return NULL;
	}
	return buf;
}


void
ocl_unmap_arg_buffer(ocl_s *ocl, int arg, void *buf){
	cl_int ret;
	cl_event ev;
	ret = clEnqueueUnmapMemObject(ocl->command,
				      ocl->arguments[arg],
				      buf,
				      0, NULL,
				      &ev);
	if (ret != CL_SUCCESS) {
		fprintf(stderr, "clEnqueueUnmapMemObject(%d): ", arg);
		ocl_error(ret, NULL);
		return;
	}

	ret = clWaitForEvents(1, &ev);
	clReleaseEvent(ev);
	if (ret != CL_SUCCESS) {
		fprintf(stderr, "clWaitForEvent(clUnmapMemObject,%d): ", arg);
		ocl_error(ret, NULL);
	}
}



int
ocl_kernel_int_arg(ocl_s *ocl, int kernel, int arg, int value){
	cl_int ret;
	ret = clSetKernelArg(ocl->kernel[kernel],
			     arg,
			     sizeof(value),
			     &value);
	if (ret) {
		fprintf(stderr, "clSetKernelArg(%d): ", arg);
		ocl_error(ret, NULL);
		return 0;
	}
	return 1;
}


/*Инициализация аргументов*/
int
ocl_kernel_init(ocl_s *ocl){
	
	/*
	 * Функция OpenCL - Задание начальных точек для вычисления матрицы
	 * KERNEL ID : 0
	 * ec_add_grid(
	 * 		__global bn_word * points_out, 
	 * 		__global bn_word * z_heap, 
	 * 		__global bn_word *row_in, 
	 * 		__global bignum *col_in
	 * )
	 * 
	 * 
	 * Функция OpenCL - вычисление инверсий
	 * KERNEL ID : 1
	 * heap_invert(
	 * 		__global bn_word *z_heap, 
	 * 		int batch
	 * )
	 * 
	 * 
	 * Функция OpenCL - вычисление хешей точек и поиск совпадений с хешами, заданными в структуре бинарных хешей
	 * KERNEL ID : 2
	 * hash_and_check(
	 * 		__global uint * found,			//Аргумент для записи результата поиска совпадений хешей точек в списке бинарных хешей
	 * 		__global bn_word * points_in,	//Массив XY координат якоби
	 * 		__global bn_word * z_heap,		//Массив Z
	 * 		__global uint * tree			//Аргумент для хранения структуры бинарных хешей
	 *	)
	 * 
	 * 
	 * ARG values map:
	 * 0 = hash_and_check(found)
	 * 1 = ec_add_grid(z_heap), heap_invert(z_heap), hash_and_check(z_heap)
	 * 2 = ec_add_grid(points_out), hash_and_check(points_in)
	 * 3 = ec_add_grid(row_in)
	 * 4 = ec_add_grid(col_in)
	 * 5 = hash_and_check(tree)
	 */


	//Подсключение к функциям OpenCL скрипта
	if (!ocl_kernel_create(ocl, 0, "ec_add_grid") ||
	    !ocl_kernel_create(ocl, 1, "heap_invert") ||
	    !ocl_kernel_create(ocl, 2, "hash_and_check")) {
		clReleaseProgram(ocl->program);
		ocl->program = NULL;
		return 0;
	}


	//Аргумент для записи результата поиска совпадений хешей точек в списке бинарных хешей: hash_and_check(found)
	if(!ocl_kernel_arg_alloc(ocl, 0, ARG_FOUND_SIZE, 1)) return 0;

	//Аргумент для хранения структуры бинарных хешей: hash_and_check(tree)
	if(!ocl_kernel_arg_alloc(ocl, 5, BTREE_HEAP_SIZE, 0)) return 0;
	unsigned char * tree = (unsigned char *)ocl_map_arg_buffer(ocl, 5, 1);
	memcpy(tree, BTREE_HEAP, BTREE_HEAP_SIZE);
	ocl_unmap_arg_buffer(ocl, 5, tree);

	//Аргумент для хранения начальных точек для вычисления входной матрицы: ec_add_grid(col_in)
	if(!ocl_kernel_arg_alloc(ocl, 4, 32 * 2 * ocl->nrows, 1)){
		printf("No memory ARG:4\n");
		return 0;
	}
	
	//z_heap & row_in
	if (!ocl_kernel_arg_alloc(ocl, 1, round_up_pow2(32 * 2 * ocl->round, 4096), 0) ||		//ec_add_grid(z_heap), heap_invert(z_heap), hash_and_check(z_heap)
	    !ocl_kernel_arg_alloc(ocl, 2, round_up_pow2(32 * 2 * ocl->round, 4096), 0) ||		//ec_add_grid(points_out), hash_and_check(points_in)
	    !ocl_kernel_arg_alloc(ocl, 3, round_up_pow2(32 * 2 * ocl->ncols, 4096), 1)){		//ec_add_grid(row_in)
			printf("No memory ARG:1,2,3\n");
			return 0;
		}

	//Аргумент для хранения размера очереди инверсии: heap_invert(batch)
	if(!ocl_kernel_int_arg(ocl, 1, 1, ocl->invsize)) return 0;

	return 1;
}




int
ocl_kernel_start(ocl_s *ocl){

	cl_int ret;
	cl_event ev;
	size_t globalws[2] = { ocl->ncols, ocl->nrows };
	size_t invws = (ocl->round) / ocl->invsize;

	//Запуск первой функции: ec_add_grid
	ret = clEnqueueNDRangeKernel(ocl->command, 
				ocl->kernel[0],
				2,
				NULL, globalws, NULL,
				0, NULL,
				&ev);
	if (ret != CL_SUCCESS) {
		ocl_error(ret, "clEnqueueNDRange(0)");
		return 0;
	}

	ret = clWaitForEvents(1, &ev);
	clReleaseEvent(ev);
	if (ret != CL_SUCCESS) {
		ocl_error(ret, "clWaitForEvents(NDRange,0)");
		return 0;
	}

	////Запуск второй функции: heap_invert
	ret = clEnqueueNDRangeKernel(ocl->command, 
				ocl->kernel[1],
				1,
				NULL, &invws, NULL,
				0, NULL,
				&ev);
	if (ret != CL_SUCCESS) {
		ocl_error(ret, "clEnqueueNDRange(1)");
		return 0;
	}

	ret = clWaitForEvents(1, &ev);
	clReleaseEvent(ev);
	if (ret != CL_SUCCESS) {
		ocl_error(ret, "clWaitForEvents(NDRange,1)");
		return 0;
	}


	//Запуск третьей функции: hash_and_check
	ret = clEnqueueNDRangeKernel(ocl->command, 
				ocl->kernel[2],
				2,
				NULL, globalws, NULL,
				0, NULL,
				&ev);
	if (ret != CL_SUCCESS) {
		ocl_error(ret, "clEnqueueNDRange(2)");
		return 0;
	}

	ret = clWaitForEvents(1, &ev);
	clReleaseEvent(ev);
	if (ret != CL_SUCCESS) {
		ocl_error(ret, "clWaitForEvents(NDRange,2)");
		return 0;
	}

	return 1;
}




/***********************************************************************
 * BINARY TREE
 ***********************************************************************/

uint32_t
btree_search(const uint32_t * hash, const uint32_t * tree){
	
	if(!tree) tree = BTREE_HEAP;

	uint8_t * h = (uint8_t *)hash;
	uint8_t a = h[0];
	uint8_t b = h[1];
	uint8_t c = h[2];
	uint32_t hpos = 1 + (a + b*256 + c*256*256);
	uint32_t pos = tree[hpos];
	uint32_t pos_next = pos;

	//20 bytes (hash160 length) + 4 bytes (position of next record)

	while(pos_next>0){
		pos = pos_next;
		pos_next = tree[pos + 5];
		if(hash[0] == tree[pos] && hash[1] == tree[pos+1] && hash[2] == tree[pos+2] && hash[3] == tree[pos+3] && hash[4] == tree[pos+4]){
			return pos;
		}
	}

	return 0;
}



void 
btree_add(const uint32_t * hash, uint32_t * tree){

	if(!tree) tree = BTREE_HEAP;

	if(btree_search(hash, tree)>0) return;

	uint8_t * h = (uint8_t *)hash;
	uint8_t a = h[0];
	uint8_t b = h[1];
	uint8_t c = h[2];
	uint32_t hpos = 1+ (a + b*256 + c*256*256);

	//20 bytes (hash160 length) + 1 byte (coin_id) + 4 bytes (position of next record)
	uint32_t last = tree[0];
	tree[0] = last + 6;

	tree[last]   = hash[0];
	tree[last+1] = hash[1];
	tree[last+2] = hash[2];
	tree[last+3] = hash[3];
	tree[last+4] = hash[4];
	tree[last+5] = tree[hpos];
	tree[hpos] = last;
};




int
btree_load(const char * filename){
	struct timeval before , after;
	uint32_t nnn = 0;
	uint8_t buf[32];
	FILE * wfd;
	struct stat st;
	size_t fsize = 0;
	uint32_t hsize = 1 + 256*256*256;		// необходимо в дальнейшем также умножить на 4 (т.к. uint 4 байта)
	uint32_t bsize = 0;
	uint32_t tsize = 0;

	if(!filename || stat(filename, &st)==-1){
		printf("BIN file [%s] not found\n", filename);
		return 0;
	}
	
	fsize = st.st_size;

	bsize = ((uint32_t)ceil(fsize/20)+2) * 6; //20 bytes (hash160 length) +  4 bytes (position of next record)
	tsize = bsize + hsize;

	uint32_t * heap = calloc(tsize, 4);
	heap[0] = hsize;

	BTREE_HEAP = heap;
	BTREE_HEAP_SIZE = tsize*4;

	gettimeofday(&before , NULL);
	nnn = 0;
	wfd = fopen(filename, "rb");
	if(!wfd){printf("%s can not open\n",filename); return 0;}
	printf("[%s] loading...\t", filename); fflush(stdout);

	while (!feof(wfd)) {
		if(fread(buf, 1, 20, wfd) == 20){
			btree_add((uint32_t *)buf, heap);
			if(btree_search((uint32_t *)buf, heap) == 0 ) printf("Bad algorithm\n");
			nnn++;
		}
	}
	fclose(wfd);

	gettimeofday(&after , NULL);
	printf ( " loaded %u records : %01.6f sec\n", nnn, (double)(time_diff(before , after)/1000000));

	return 1;
}




/***********************************************************************
 * POINT <--> RAW
 ***********************************************************************/

static void
ocl_get_bignum_raw(BIGNUM *bn, const unsigned char *buf){
	bn_expand(bn, 256);
	memcpy(bn->d, buf, 32);
	bn->top = (32 / sizeof(BN_ULONG));
}

static void
ocl_put_bignum_raw(unsigned char *buf, const BIGNUM *bn){
	int bnlen = (bn->top * sizeof(BN_ULONG));
	if (bnlen >= 32) {
		memcpy(buf, bn->d, 32);
	} else {
		memcpy(buf, bn->d, bnlen);
		memset(buf + bnlen, 0, 32 - bnlen);
	}
}

struct ec_point_st {
	const EC_METHOD *meth;
	BIGNUM X;
	BIGNUM Y;
	BIGNUM Z;
	int Z_is_one;
};

void
ocl_get_point(EC_POINT *ppnt, const unsigned char *buf){
	static const unsigned char mont_one[] = { 0x01,0x00,0x00,0x03,0xd1 };
	ocl_get_bignum_raw(&ppnt->X, buf);
	ocl_get_bignum_raw(&ppnt->Y, buf + 32);
	if (!ppnt->Z_is_one) {
		ppnt->Z_is_one = 1;
		BN_bin2bn(mont_one, sizeof(mont_one), &ppnt->Z);
	}
}

void
ocl_put_point(unsigned char *buf, const EC_POINT *ppnt){
	assert(ppnt->Z_is_one);
	ocl_put_bignum_raw(buf, &ppnt->X);
	ocl_put_bignum_raw(buf + 32, &ppnt->Y);
}



void
ocl_put_point_tpa(unsigned char *buf, int cell, const EC_POINT *ppnt){
	unsigned char pntbuf[64];
	int start, i;

	ocl_put_point(pntbuf, ppnt);

	start = ((((2 * cell) / ACCESS_STRIDE) * ACCESS_BUNDLE) +
		 (cell % (ACCESS_STRIDE/2)));
	for (i = 0; i < 8; i++)
		memcpy(buf + 4*(start + i*ACCESS_STRIDE),
		       pntbuf+(i*4),
		       4);
	for (i = 0; i < 8; i++)
		memcpy(buf + 4*(start + (ACCESS_STRIDE/2) + (i*ACCESS_STRIDE)),
		       pntbuf+32+(i*4),
		       4);
}

void
ocl_get_point_tpa(EC_POINT *ppnt, const unsigned char *buf, int cell){
	unsigned char pntbuf[64];
	int start, i;

	start = ((((2 * cell) / ACCESS_STRIDE) * ACCESS_BUNDLE) +
		 (cell % (ACCESS_STRIDE/2)));
	for (i = 0; i < 8; i++)
		memcpy(pntbuf+(i*4),
		       buf + 4*(start + i*ACCESS_STRIDE),
		       4);
	for (i = 0; i < 8; i++)
		memcpy(pntbuf+32+(i*4),
		       buf + 4*(start + (ACCESS_STRIDE/2) + (i*ACCESS_STRIDE)),
		       4);

	ocl_get_point(ppnt, pntbuf);
}









