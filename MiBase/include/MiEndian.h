#ifndef MiEndian_H_
#define MiEndian_H_
#include "MiUtil.h"
#ifdef __cplusplus
extern "C"{
#endif
char* mi_put_amf_string(char *c, const char *str);
char* mi_put_amf_double(char *c, double d);
char* mi_put_byte(char *output, uint8_t nVal);
char* mi_put_be16(char *output, uint16_t nVal);
char* mi_put_be24(char *output, uint32_t nVal);
char* mi_put_be32(char *output, uint32_t nVal);
char* mi_put_be64(char *output, uint64_t nVal);

uint32_t mi_get_be32(uint8_t *output);
uint16_t  mi_get_be16(uint8_t *output);
#ifdef __cplusplus
}
#endif
#endif 
