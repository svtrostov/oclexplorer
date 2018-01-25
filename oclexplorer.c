/*
 * OCLExplorer bitcoin addresses brute-force tool
 * Copyright (C) 2017 Stanislav V. Tretyakov <svtrostov@yandex.ru>
 * 
 */
 

#include "oclexplorer.h"



/***********************************************************************
 * MAIN FUNCTION
 ***********************************************************************/
int
main(int argc, char **argv){

	const char * clfilename = NULL;
	int platform_id = 0;
	int device_id = 0;
	int opt;
	const char * pkey_base = NULL;
	const char * bin_file = NULL;
	unsigned int is_unlim_round = 0;
	uint32_t nrows = 0, ncols = 0, invsize = 0;
	char *pend;


	//Чтение опций запуска программы
	while ((opt = getopt(argc, argv,"f:p:d:k:ug:i:b:")) != -1){
		switch (opt) {
			//Имя файла OpenCl скрипта
			case 'f':
				clfilename = optarg;
			break;
			//ID платформы
			case 'p':
				platform_id = atoi(optarg);
			break;
			//ID устройства
			case 'd':
				device_id = atoi(optarg);
			break;
			//Стартовый секретный ключ
			case 'k':
				pkey_base = optarg;
			break;
			//Признак, указывающий что должно быть неограниченное количество раундов, т.е. поиск с определенного ключа и до победы
			case 'u':
				is_unlim_round = 1;
			break;
			//Размер матрицы
			case 'g':
			nrows = 0;
			ncols = strtol(optarg, &pend, 0);
			if (pend && *pend == 'x') {
				nrows = strtol(pend+1, NULL, 0);
			}
			if (!nrows || !ncols) {
				fprintf(stderr,
					"Invalid grid size: '%s'\n", optarg);
				return 1;
			}
			break;
			//Размер очереди модулярной инверсии чисел
			case 'i':
				invsize = atoi(optarg);
				if (!invsize) {
					fprintf(stderr,
						"Invalid modular inverse size '%s'\n",
						optarg);
					return 1;
				}
				if (invsize & (invsize - 1)) {
					fprintf(stderr,
						"Modular inverse size must be "
						"a power of 2\n");
					return 1;
				}
			break;
			//Имя файла с хешами bitcoin кошельков ripemd160 в бинарном формате
			case 'b':
				bin_file = optarg;
			break;
		}//switch
	}//while opt

	//1 - загрузка бинарных данных, ДОЛЖНА БЫТЬ ПЕРВОЙ ОПЕРАЦИЕЙ, т.к. испольуется далее при инициализации GPU
	if(!btree_load(bin_file)) return 1;

	ocl_s * ocl = ocl_init(platform_id, device_id, (clfilename ? clfilename : "./gpu.cl"), ncols, nrows, invsize);
	if(!ocl) return 1;
	if(!ocl_kernel_init(ocl)) return 1;

	ocl->pkey_base = pkey_base;
	ocl->is_unlim_round = is_unlim_round;

	ocl_print_info(ocl);


	loop(ocl);


	ocl_clear(ocl);
	free(ocl);

	return 0;
}/*END: main()*/





void loop(ocl_s * ocl){

	int i, n;

	BIGNUM * bn_tmp = BN_new();
	BN_CTX * bn_ctx = BN_CTX_new();

	EC_KEY * pkey = EC_KEY_new_by_curve_name(NID_secp256k1);
	EC_KEY_precompute_mult(pkey, bn_ctx);

	BIGNUM * N = BN_new();
	BN_hex2bn(&N, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");

	const BIGNUM * bn_key = NULL;

	const EC_GROUP	*	pgroup	= EC_KEY_get0_group(pkey);
	const EC_POINT	*	pgen	= EC_GROUP_get0_generator(pgroup);

	EC_POINT **pprows = NULL, **ppcols, *pbatchinc = NULL, *poffset = NULL;

	//Выделение памяти под базовые точки матрицы
	ppcols = (EC_POINT **) malloc(ocl->ncols * sizeof(EC_POINT*));
	pprows = (EC_POINT **) malloc(ocl->nrows * sizeof(EC_POINT*));
	for (i = 0; i < ocl->ncols; i++) ppcols[i] = EC_POINT_new(pgroup);
	for (i = 0; i < ocl->nrows; i++) pprows[i] = EC_POINT_new(pgroup);

	pbatchinc = EC_POINT_new(pgroup);
	poffset = EC_POINT_new(pgroup);

	BN_set_word(bn_tmp, ocl->ncols);
	EC_POINT_mul(pgroup, pbatchinc, bn_tmp, NULL, NULL, bn_ctx);
	EC_POINT_make_affine(pgroup, pbatchinc, bn_ctx);

	//Точка сдвига начальных инкрементов на общее количество элементов в матрице
	BN_set_word(bn_tmp, ocl->round);
	EC_POINT_mul(pgroup, poffset, bn_tmp, NULL, NULL, bn_ctx);
	EC_POINT_make_affine(pgroup, poffset, bn_ctx);


	uint64_t total = 0;
	uint32_t iterations = 0;	//Количество итераций смены секретных ключей
	uint32_t rounds = 0;		//Количество раундов работы с GPU
	uint8_t pkey_bin[32];
	uint8_t pkey_s[65];
	time_t now;
	char buffer[4096];
	char time_buf[128];
	unsigned char hash_buf[128];
	char tmp[1024];
	unsigned char * points_in;
	unsigned char * strides_in;
	uint32_t * uint32_ptr;
	uint8_t * uint8_ptr;
	uint32_t found_delta;
	uint32_t found_pos;
	uint8_t * found_hash;
	keyinfo_s * info;
	FILE * ffd;

	hashrate_s round_hr;
	hashrate_s total_hr;

	uint32_t round_max = (ocl->is_unlim_round == 0 ? (uint32_t)(0xFFFFFFFF / ocl->round) + 1 : 0);

	gettimeofday(&(total_hr.time_start), NULL);

	for(;;){
	/******************************************************************/

		iterations++;

		//Установка буффера результата в положение по-умолчанию
		uint32_ptr = (uint32_t *) ocl_map_arg_buffer(ocl, 0, 1);
		if (!uint32_ptr){fprintf(stderr, "ERROR: Could not map result buffer\n");return;}
		uint32_ptr[0] = 0xffffffff;
		ocl_unmap_arg_buffer(ocl, 0, uint32_ptr);


		//Генерация случайного закрытого ключа
		EC_KEY_generate_key(pkey);


		//Если задан стартовый приватный ключ - устанавливаем его
		if(iterations == 1 && ocl->pkey_base != NULL){
			BN_hex2bn(&bn_tmp, ocl->pkey_base);
			set_pkey(bn_tmp, pkey);
		}

		//Вывод ключа на экран
		bn_key = EC_KEY_get0_private_key(pkey);
		n = BN_num_bytes(bn_key);
		if(n < 32) memset(pkey_bin, 0, 32 - n);
		BN_bn2bin(bn_key, &pkey_bin[32 - n]);
		bin2hex(pkey_s, pkey_bin, 32);

		now = time(NULL);
		strftime (buffer, 1023, "%Y-%m-%d %H:%M:%S", localtime(&now));
		printf("\nIteration %u at [%s] from: %s\n",iterations, buffer, pkey_s);


		//Подготовка начальных значений для матрицы
		EC_POINT_copy(ppcols[0], EC_KEY_get0_public_key(pkey));

		//Подготовка начальных значений для матрицы
		for (i = 1; i < ocl->ncols; i++){
			EC_POINT_add(pgroup, ppcols[i], ppcols[i-1], pgen, bn_ctx);
		}
		EC_POINTs_make_affine(pgroup, ocl->ncols, ppcols, bn_ctx);

		//Заполняем полученными базовыми точками переменные OpenCL функции
		points_in = (unsigned char *)ocl_map_arg_buffer(ocl, 3, 1);
		if (!points_in) {
			fprintf(stderr, "ERROR: Could not map column buffer\n"); return;
		}
		for (i = 0; i < ocl->ncols; i++){
			ocl_put_point_tpa(points_in, i, ppcols[i]);
		}
		ocl_unmap_arg_buffer(ocl, 3, points_in);

		//Вычисление инкрементальных базовых точек
		EC_POINT_copy(pprows[0], pgen);
		for (i = 1; i < ocl->nrows; i++) {
			EC_POINT_add(pgroup, pprows[i], pprows[i-1], pbatchinc, bn_ctx);
		}
		EC_POINTs_make_affine(pgroup, ocl->nrows, pprows, bn_ctx);

		rounds = 1;

		while(rounds < round_max || round_max == 0){
			///////////////////////////////////////////////////////////

			gettimeofday(&(round_hr.time_start), NULL);

			bn_key = EC_KEY_get0_private_key(pkey);
			n = BN_num_bytes(bn_key);
			if(n < 32) memset(pkey_bin, 0, 32 - n);
			BN_bn2bin(bn_key, &pkey_bin[32 - n]);
			bin2hex(pkey_s, pkey_bin, 32);
			//printf("\nround %u from: %s\n",rounds, pkey_s);
			
			if (rounds > 1) {
				//Сдвиг инкремента на poffset точек вперед
				for (i = 0; i < ocl->nrows; i++) {
					EC_POINT_add(pgroup, pprows[i], pprows[i], poffset, bn_ctx);
				}
				EC_POINTs_make_affine(pgroup, ocl->nrows, pprows, bn_ctx);
			}
			
			//Копирование инкрементальных базовых точек на устройство
			strides_in = (unsigned char *)
				ocl_map_arg_buffer(ocl, 4, 1);
			if (!strides_in) {
				fprintf(stderr,"ERROR: Could not map row buffer\n"); return;
			}
			memset(strides_in, 0, 64 * ocl->nrows);
			for (i = 0; i < ocl->nrows; i++){
				ocl_put_point(strides_in + (64*i), pprows[i]);
			}
			ocl_unmap_arg_buffer(ocl, 4, strides_in);
			
			
			if(ocl_kernel_start(ocl)){

				//Полуение значения признака нахождения совпадения
				uint8_ptr = (uint8_t *) ocl_map_arg_buffer(ocl, 0, 2);
				if(!uint8_ptr){fprintf(stderr, "ERROR: Could not map result buffer");return;}
				found_delta = *(uint32_t *)&uint8_ptr[0];

				//Совпадение найдено
				if (found_delta != 0xffffffff){

					found_pos	= *(uint32_t *)&uint8_ptr[4];
					found_hash	= &uint8_ptr[12];

					//Проверка хеша пройдена успешно, хеш найден
					if(found_pos > 0 && btree_search(&(*(uint32_t *)found_hash), NULL) > 0){

						BN_copy(bn_tmp, bn_key);
						BN_add_word(bn_tmp, found_delta+1);

						info = get_key_info(bn_tmp);

						//Найденный хеш и вычисленный хеш из закрытого ключа совпадают, 100% нахождение
						if(strncmp((char*)found_hash, (char*)info->public_ripemd160_bin, 20) == 0){

							bin2hex(hash_buf, found_hash, 20);

							now = time(NULL);
							strftime(time_buf, 127, "%Y-%m-%d %H:%M:%S", localtime(&now));

							n = sprintf(buffer,
								"\n++++++++++++++++++++++++++++++++++++++++++++++++++\n"\
								"TIME: %s\n"\
								"PRIV: %s\n"\
								"PUBL: %s\n"\
								"HASH: %s\n"\
								"ADDR: %s\n"\
								"SALT: %s\n"\
								"OFST: %i\n"\
								"GPUH: %s\n"\
								"++++++++++++++++++++++++++++++++++++++++++++++++++\n",
								time_buf,
								info->private_hex,
								info->public_hex,
								info->public_ripemd160_hex,
								info->address_hex,
								pkey_s,
								found_delta,
								hash_buf
							);

							printf("\n%s\n",buffer);

							sprintf(tmp, "./%s.%u.txt", info->public_ripemd160_hex, (uint32_t)now);
							ffd = fopen(tmp,"w");
							if(ffd){
								fwrite(buffer, n, 1, ffd);
								fclose(ffd);
							}
							ffd = fopen("./found.txt","a");
							if(ffd){
								fwrite(buffer, n, 1, ffd);
								fclose(ffd);
							}

						}//strncmp gpu_hash & priv hash

						free(info);

					}//Проверка хеша пройдена успешно, хеш найден

					memset(uint8_ptr, 0, ARG_FOUND_SIZE);
					memset(uint8_ptr, 0xFF, 4);
				}//Совпадение найдено


				ocl_unmap_arg_buffer(ocl, 0, uint8_ptr);

				//инкрементирование закрытого ключа
				BN_copy(bn_tmp, bn_key);
				BN_add_word(bn_tmp, ocl->round);
				set_pkey(bn_tmp, pkey);

			}else return;


			total += ocl->round;

			hashrate_update(&round_hr, ocl->round);
			hashrate_update(&total_hr, total);

			printf("\r[%s], round %u: %01.2fs (%01.2f %s) [total %"PRIu64" (%01.2f %s)]   ", pkey_s, rounds, round_hr.runtime, round_hr.hashrate, round_hr.unit, total, total_hr.hashrate, total_hr.unit);
			fflush(stdout);

			rounds++;
			////////////////////////////////////////////////////////////
		}



		
		
		
	/******************************************************************/
	}



	return;
}



