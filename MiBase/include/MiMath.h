
#ifndef INCLUDE_MI_MATH_H_
#define INCLUDE_MI_MATH_H_
#include "MiUtil.h"
static inline int16_t mi_rtp_seq_distance(const uint16_t prev_value, const uint16_t value)
{
    return (int16_t)(value - prev_value);
}

int16_t  mi_floattoint16(float f);
float    mi_int16tofloat(int16_t i16);
uint64_t mi_random();
int32_t  mi_insert_uint16_sort(uint16_t a[],uint16_t value,uint32_t* alen);




#endif 
