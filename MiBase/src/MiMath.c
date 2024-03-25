﻿#include "MiMath.h"
#include "MiTime.h"
#if WIN32
#define random rand
#define srandom srand
#endif

int16_t mi_floattoint16(float f){
    return (int16_t)(f * 32767 + 0.5);
}

float mi_int16tofloat(int16_t i16){
    return (float)i16/32767;
}

uint64_t mi_random() {
	static mi_bool _random_contexttialized = mi_false;
	if (!_random_contexttialized) {
		_random_contexttialized = mi_true;
#ifdef WIN32
		srandom((uint64_t)(mi_get_system_time()));
#else
		srandom((uint64_t)(mi_get_system_time() | (getpid() << 13)));
#endif // !WIN32

		
	}
	return random();
}
void mi_insertSort(int a[], int n) {
	for (int i = 1; i < n; i++) {
		if (a[i] < a[i - 1]) { //若第i个元素大于i-1元素，直接插入。小于的话，移动有序表后插入
			int j = i - 1;
			int x = a[i]; //复制为哨兵，即存储待排序元素
			a[i] = a[i - 1]; //先后移一个元素
			while (x < a[j]) { //查找在有序表的插入位置
				a[j + 1] = a[j];
				j--; //元素后移
			}
			a[j + 1] = x; //插入到正确位置
		}

	}
}

int mi_get_uint16_index(uint16_t* a, uint16_t value,int32_t alen){
	int low,high,mid;
	low = 0;
	high =alen;
	while(low<=high){
		mid = (high+low)/2;
		if(value==a[mid]) return -1;
		if(mi_rtp_seq_distance(value,a[mid])>0)
			high = mid-1;
		else if(mi_rtp_seq_distance(a[mid],value)>0)
			low = mid+1;
		else
			return mid;
	}
	return low;
}


int32_t mi_insert_uint16_sort(uint16_t* a, uint16_t value, uint32_t *palen) {
	int32_t alen = *palen;
	int32_t index=-1;
	if(alen==0){
		a[0]=value;
		*palen=1;
		return mi_ok;
	}
	if (mi_rtp_seq_distance(a[alen-1], value)>0){
		a[alen]=value;
		*palen=alen+1;
		return mi_ok;
	}
	index= mi_get_uint16_index(a,value,alen);
	if(index==-1) return 1;

	mi_memmove((char*) a + (index + 1) * sizeof(uint16_t),
			(char*) a + index * sizeof(uint16_t),
			sizeof(uint16_t) * (alen - index));
	a[index] = value;
	*palen = alen + 1;
	return mi_ok;
}
