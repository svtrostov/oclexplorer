/*
 * OCLExplorer bitcoin addresses brute-force tool
 * Copyright (C) 2017 Stanislav V. Tretyakov <svtrostov@yandex.ru>
 * 
 */


#include "oclexplorer.h"


const char *b58_alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

const signed char b58_reverse_map[256] = {
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1,  0,  1,  2,  3,  4,  5,  6,  7,  8, -1, -1, -1, -1, -1, -1,
	-1,  9, 10, 11, 12, 13, 14, 15, 16, -1, 17, 18, 19, 20, 21, -1,
	22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, -1, -1, -1, -1, -1,
	-1, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, -1, 44, 45, 46,
	47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1
};


static const unsigned long crcTable[256] = {
   0x00000000,0x77073096,0xEE0E612C,0x990951BA,0x076DC419,0x706AF48F,0xE963A535,
   0x9E6495A3,0x0EDB8832,0x79DCB8A4,0xE0D5E91E,0x97D2D988,0x09B64C2B,0x7EB17CBD,
   0xE7B82D07,0x90BF1D91,0x1DB71064,0x6AB020F2,0xF3B97148,0x84BE41DE,0x1ADAD47D,
   0x6DDDE4EB,0xF4D4B551,0x83D385C7,0x136C9856,0x646BA8C0,0xFD62F97A,0x8A65C9EC,
   0x14015C4F,0x63066CD9,0xFA0F3D63,0x8D080DF5,0x3B6E20C8,0x4C69105E,0xD56041E4,
   0xA2677172,0x3C03E4D1,0x4B04D447,0xD20D85FD,0xA50AB56B,0x35B5A8FA,0x42B2986C,
   0xDBBBC9D6,0xACBCF940,0x32D86CE3,0x45DF5C75,0xDCD60DCF,0xABD13D59,0x26D930AC,
   0x51DE003A,0xC8D75180,0xBFD06116,0x21B4F4B5,0x56B3C423,0xCFBA9599,0xB8BDA50F,
   0x2802B89E,0x5F058808,0xC60CD9B2,0xB10BE924,0x2F6F7C87,0x58684C11,0xC1611DAB,
   0xB6662D3D,0x76DC4190,0x01DB7106,0x98D220BC,0xEFD5102A,0x71B18589,0x06B6B51F,
   0x9FBFE4A5,0xE8B8D433,0x7807C9A2,0x0F00F934,0x9609A88E,0xE10E9818,0x7F6A0DBB,
   0x086D3D2D,0x91646C97,0xE6635C01,0x6B6B51F4,0x1C6C6162,0x856530D8,0xF262004E,
   0x6C0695ED,0x1B01A57B,0x8208F4C1,0xF50FC457,0x65B0D9C6,0x12B7E950,0x8BBEB8EA,
   0xFCB9887C,0x62DD1DDF,0x15DA2D49,0x8CD37CF3,0xFBD44C65,0x4DB26158,0x3AB551CE,
   0xA3BC0074,0xD4BB30E2,0x4ADFA541,0x3DD895D7,0xA4D1C46D,0xD3D6F4FB,0x4369E96A,
   0x346ED9FC,0xAD678846,0xDA60B8D0,0x44042D73,0x33031DE5,0xAA0A4C5F,0xDD0D7CC9,
   0x5005713C,0x270241AA,0xBE0B1010,0xC90C2086,0x5768B525,0x206F85B3,0xB966D409,
   0xCE61E49F,0x5EDEF90E,0x29D9C998,0xB0D09822,0xC7D7A8B4,0x59B33D17,0x2EB40D81,
   0xB7BD5C3B,0xC0BA6CAD,0xEDB88320,0x9ABFB3B6,0x03B6E20C,0x74B1D29A,0xEAD54739,
   0x9DD277AF,0x04DB2615,0x73DC1683,0xE3630B12,0x94643B84,0x0D6D6A3E,0x7A6A5AA8,
   0xE40ECF0B,0x9309FF9D,0x0A00AE27,0x7D079EB1,0xF00F9344,0x8708A3D2,0x1E01F268,
   0x6906C2FE,0xF762575D,0x806567CB,0x196C3671,0x6E6B06E7,0xFED41B76,0x89D32BE0,
   0x10DA7A5A,0x67DD4ACC,0xF9B9DF6F,0x8EBEEFF9,0x17B7BE43,0x60B08ED5,0xD6D6A3E8,
   0xA1D1937E,0x38D8C2C4,0x4FDFF252,0xD1BB67F1,0xA6BC5767,0x3FB506DD,0x48B2364B,
   0xD80D2BDA,0xAF0A1B4C,0x36034AF6,0x41047A60,0xDF60EFC3,0xA867DF55,0x316E8EEF,
   0x4669BE79,0xCB61B38C,0xBC66831A,0x256FD2A0,0x5268E236,0xCC0C7795,0xBB0B4703,
   0x220216B9,0x5505262F,0xC5BA3BBE,0xB2BD0B28,0x2BB45A92,0x5CB36A04,0xC2D7FFA7,
   0xB5D0CF31,0x2CD99E8B,0x5BDEAE1D,0x9B64C2B0,0xEC63F226,0x756AA39C,0x026D930A,
   0x9C0906A9,0xEB0E363F,0x72076785,0x05005713,0x95BF4A82,0xE2B87A14,0x7BB12BAE,
   0x0CB61B38,0x92D28E9B,0xE5D5BE0D,0x7CDCEFB7,0x0BDBDF21,0x86D3D2D4,0xF1D4E242,
   0x68DDB3F8,0x1FDA836E,0x81BE16CD,0xF6B9265B,0x6FB077E1,0x18B74777,0x88085AE6,
   0xFF0F6A70,0x66063BCA,0x11010B5C,0x8F659EFF,0xF862AE69,0x616BFFD3,0x166CCF45,
   0xA00AE278,0xD70DD2EE,0x4E048354,0x3903B3C2,0xA7672661,0xD06016F7,0x4969474D,
   0x3E6E77DB,0xAED16A4A,0xD9D65ADC,0x40DF0B66,0x37D83BF0,0xA9BCAE53,0xDEBB9EC5,
   0x47B2CF7F,0x30B5FFE9,0xBDBDF21C,0xCABAC28A,0x53B39330,0x24B4A3A6,0xBAD03605,
   0xCDD70693,0x54DE5729,0x23D967BF,0xB3667A2E,0xC4614AB8,0x5D681B02,0x2A6F2B94,
   0xB40BBE37,0xC30C8EA1,0x5A05DF1B,0x2D02EF8D };

/*Вычисление CRC32
 * crc32_in - 0 если начальное хеширование или значение последнего хеща для продолжения
 * */
uint32_t 
hash_crc32(uint32_t crc32_in, const void *buf, size_t n ){
    uint32_t crc32 = crc32_in ^ 0xFFFFFFFF;
    uint8_t  *ptr  = (uint8_t *) buf;
    size_t i;
    for (i=0; i < n; i++) {
        crc32 = (crc32 >> 8) ^ crcTable[ (crc32 ^ ptr[i]) & 0xFF ];
    }
    return( crc32 ^ 0xFFFFFFFF );
}


uint8_t *
bin2hex(uint8_t * buf, const uint8_t * from, size_t n){
	if(!buf) buf = malloc(n*2+1);
	size_t a,b=0;
	for(a=0;a<n;a++){
		buf[b++] = hex_asc_O(from[a]);
		buf[b++] = hex_asc_0(from[a]);
	}
	buf[b]=0;
	return buf;
}


int
hex2bin(uint8_t * buf, const uint8_t * from, size_t n){
	if(!n) n = strlen((char *)from);
	if(n % 2 == 1) return -1;	//Нечетное
	size_t len = n / 2;
	size_t i = 0;
	uint8_t ch;

	for(i=0; i<len; i++){
		ch = from[i*2];
		if(ch > 0x60) ch -= 39;  // convert chars a-f
		ch -= 48;  // convert chars 0-9
		ch *= 16;

		ch += from[i*2 + 1];
		if(ch > 0x60) ch -= 39;  // convert chars a-f
		ch -= 48;  // convert chars 0-9

		buf[i] = ch;
	}

	return len;
}



double time_diff(struct timeval x , struct timeval y){
	double x_ms , y_ms , diff;
	x_ms = (double)x.tv_sec*1000000 + (double)x.tv_usec;
	y_ms = (double)y.tv_sec*1000000 + (double)y.tv_usec;
	diff = (double)y_ms - (double)x_ms;
	return diff;
}



void
b58_encode_check(void *buf, size_t len, char *result){
	unsigned char hash1[32];
	unsigned char hash2[32];

	int d, p;

	BN_CTX *bnctx;
	BIGNUM *bn, *bndiv, *bntmp;
	BIGNUM bna, bnb, bnbase, bnrem;
	unsigned char *binres;
	int brlen, zpfx;

	bnctx = BN_CTX_new();
	BN_init(&bna);
	BN_init(&bnb);
	BN_init(&bnbase);
	BN_init(&bnrem);
	BN_set_word(&bnbase, 58);

	bn = &bna;
	bndiv = &bnb;

	brlen = (2 * len) + 4;
	binres = (unsigned char*) malloc(brlen);
	memcpy(binres, buf, len);

	SHA256(binres, len, hash1);
	SHA256(hash1, sizeof(hash1), hash2);
	memcpy(&binres[len], hash2, 4);

	BN_bin2bn(binres, len + 4, bn);

	for (zpfx = 0; zpfx < (len + 4) && binres[zpfx] == 0; zpfx++);

	p = brlen;
	while (!BN_is_zero(bn)) {
		BN_div(bndiv, &bnrem, bn, &bnbase, bnctx);
		bntmp = bn;
		bn = bndiv;
		bndiv = bntmp;
		d = BN_get_word(&bnrem);
		binres[--p] = b58_alphabet[d];
	}

	while (zpfx--) {
		binres[--p] = b58_alphabet[0];
	}

	memcpy(result, &binres[p], brlen - p);
	result[brlen - p] = '\0';

	free(binres);
	BN_clear_free(&bna);
	BN_clear_free(&bnb);
	BN_clear_free(&bnbase);
	BN_clear_free(&bnrem);
	BN_CTX_free(bnctx);
}

#define skip_char(c) \
	(((c) == '\r') || ((c) == '\n') || ((c) == ' ') || ((c) == '\t'))

int
b58_decode_check(const char *input, void *buf, size_t len){
	int i, l, c;
	unsigned char *xbuf = NULL;
	BIGNUM bn, bnw, bnbase;
	BN_CTX *bnctx;
	unsigned char hash1[32], hash2[32];
	int zpfx;
	int res = 0;

	BN_init(&bn);
	BN_init(&bnw);
	BN_init(&bnbase);
	BN_set_word(&bnbase, 58);
	bnctx = BN_CTX_new();

	/* Build a bignum from the encoded value */
	l = strlen(input);
	for (i = 0; i < l; i++) {
		if (skip_char(input[i]))
			continue;
		c = b58_reverse_map[(int)input[i]];
		if (c < 0)
			goto out;
		BN_clear(&bnw);
		BN_set_word(&bnw, c);
		BN_mul(&bn, &bn, &bnbase, bnctx);
		BN_add(&bn, &bn, &bnw);
	}

	/* Copy the bignum to a byte buffer */
	for (i = 0, zpfx = 0; input[i]; i++) {
		if (skip_char(input[i]))
			continue;
		if (input[i] != b58_alphabet[0])
			break;
		zpfx++;
	}
	c = BN_num_bytes(&bn);
	l = zpfx + c;
	if (l < 5)
		goto out;
	xbuf = (unsigned char *) malloc(l);
	if (!xbuf)
		goto out;
	if (zpfx)
		memset(xbuf, 0, zpfx);
	if (c)
		BN_bn2bin(&bn, xbuf + zpfx);

	/* Check the hash code */
	l -= 4;
	SHA256(xbuf, l, hash1);
	SHA256(hash1, sizeof(hash1), hash2);
	if (memcmp(hash2, xbuf + l, 4))
		goto out;

	/* Buffer verified */
	if (len) {
		if (len > l)
			len = l;
		memcpy(buf, xbuf, len);
	}
	res = l;

out:
	if (xbuf)
		free(xbuf);
	BN_clear_free(&bn);
	BN_clear_free(&bnw);
	BN_clear_free(&bnbase);
	BN_CTX_free(bnctx);
	return res;
}


void
encode_privkey(const BIGNUM *bn, int addrtype, uint8_t *bin_result, uint8_t *wit_result){

	unsigned char eckey_buf[128];
	int nbytes;

	eckey_buf[0] = addrtype;
	nbytes = BN_num_bytes(bn);
	if (nbytes > 32) nbytes = 32;
	if (nbytes < 32)
		memset(eckey_buf + 1, 0, 32 - nbytes);
	BN_bn2bin(bn, &eckey_buf[33 - nbytes]);
	bin2hex(bin_result, eckey_buf+1, 32);
	b58_encode_check(eckey_buf, 33, (char*)wit_result);
}



keyinfo_s * 
get_key_info(const BIGNUM * private_key){

	keyinfo_s * info = calloc(1, sizeof(keyinfo_s));

	EC_GROUP * group 	= EC_GROUP_new_by_curve_name ( NID_secp256k1 );
	BN_CTX   * ctx 		= BN_CTX_new();
	BIGNUM   * x 		= BN_new();
	BIGNUM   * y 		= BN_new();
	EC_POINT * point 	= EC_POINT_new(group);

	EC_POINT_mul(group, point, private_key, NULL, NULL, NULL);
	EC_POINT_get_affine_coordinates_GFp(group, point, x, y, NULL);

	BN_bn2bin(private_key, info->private_bin + 32 - BN_num_bytes(private_key));
	BN_bn2bin(x, info->public_x + 32 - BN_num_bytes(x));
	BN_bn2bin(y, info->public_y + 32 - BN_num_bytes(y));

	info->public_bin[0] = 4;
	memcpy (&info->public_bin[1], info->public_x, 32);
	memcpy (&info->public_bin[33], info->public_y, 32);

	SHA256 ( info->public_bin, 65, info->public_sha256_bin );
	RIPEMD160 ( info->public_sha256_bin, 32, info->public_ripemd160_bin );

	uint8_t rout[21];
	rout[0] = 0;
	memcpy(rout+1, info->public_ripemd160_bin, 20);


	b58_encode_check(rout, 21, (char*)info->address_hex);


	int n, j;

	n = 0;
	for(j=0;j<32;j++){
		info->private_hex[n++] = hex_asc_O(info->private_bin[j]);
		info->private_hex[n++] = hex_asc_0(info->private_bin[j]);
	}
	info->private_hex[n] = 0;

	n = 0;
	for(j=0;j<65;j++){
		info->public_hex[n++] = hex_asc_O(info->public_bin[j]);
		info->public_hex[n++] = hex_asc_0(info->public_bin[j]);
	}
	info->public_hex[n] = 0;

	n = 0;
	for(j=0;j<20;j++){
		info->public_ripemd160_hex[n++] = hex_asc_O(info->public_ripemd160_bin[j]);
		info->public_ripemd160_hex[n++] = hex_asc_0(info->public_ripemd160_bin[j]);
	}
	info->public_ripemd160_hex[n] = 0;

	n = 0;
	for(j=0;j<32;j++){
		info->public_sha256_hex[n++] = hex_asc_O(info->public_sha256_bin[j]);
		info->public_sha256_hex[n++] = hex_asc_0(info->public_sha256_bin[j]);
	}
	info->public_sha256_hex[n] = 0;


	BN_free(x);
	BN_free(y);
	BN_CTX_free(ctx);
	EC_POINT_free(point);
	return info;
}



int
set_pkey(const BIGNUM *bnpriv, EC_KEY *pkey){

	const EC_GROUP *pgroup;
	EC_POINT *ppnt;
	int res;

	pgroup = EC_KEY_get0_group(pkey);
	ppnt = EC_POINT_new(pgroup);

	res = (ppnt &&
	       EC_KEY_set_private_key(pkey, bnpriv) &&
	       EC_POINT_mul(pgroup, ppnt, bnpriv, NULL, NULL, NULL) &&
	       EC_KEY_set_public_key(pkey, ppnt));

	if (ppnt)
		EC_POINT_free(ppnt);

	if (!res)
		return 0;

	assert(EC_KEY_check_key(pkey));
	return 1;
}



void
hashrate_update(hashrate_s * hr, uint64_t value){
	gettimeofday(&(hr->time_now), NULL);
	hr->runtime = time_diff(hr->time_start, hr->time_now) / 1000000;
	hr->hashrate = value / hr->runtime;
	hr->unit = "key/s";
	if (hr->hashrate > 1000) {
		hr->unit = "Kkey/s";
		hr->hashrate /= 1000.0;
		if (hr->hashrate > 1000) {
			hr->unit = "Mkey/s";
			hr->hashrate /= 1000.0;
		}
	}
}

