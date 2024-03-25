#ifndef INCLUDE_MI_VECTOR_H_
#define INCLUDE_MI_VECTOR_H_


#include "MiBuffer.h"

typedef struct{
	int32_t capacity;
	int32_t vsize;
	char** payload;
}MiStringVector;

typedef struct{
	 uint32_t vsize;
	 uint32_t capacity;
	 uint16_t* payload;
}MiUint16Sort;



void mi_insert_uint16Sort(MiUint16Sort* psort,uint16_t val);
void mi_create_uint16Sort(MiUint16Sort* psort);
void mi_create_uint16Sort2(MiUint16Sort* psort,int32_t pcapacity);
void mi_destroy_uint16Sort(MiUint16Sort* psort);
void mi_clear_uint16Sort(MiUint16Sort* psort);
void mi_clear_uint16Sort2(MiUint16Sort* psort,int32_t index);

void mi_insert_stringVector(MiStringVector* vec,char* str);
void mi_insert_stringVector2(MiStringVector* vec,char* str,int plen);
void mi_create_stringVector(MiStringVector* vec);
void mi_destroy_stringVector(MiStringVector* vec);
void mi_clear_stringVector(MiStringVector* vec);

//声明一个结构体
#define mi_vector_declare(x) \
typedef struct{ \
	int32_t capacity; \
	int32_t vsize; \
	x* payload; \
}x##Vector; \
void mi_create_##x##Vector(x##Vector* vec);\
void mi_destroy_##x##Vector(x##Vector* vec);\
void mi_clear_##x##Vector(x##Vector* vec);\
void mi_insert_##x##Vector(x##Vector* vec,x* value);\
void mi_remove_##x##Vector(x##Vector* vec,int32_t index);\


#define mi_vector_impl(x) \
void mi_insert_##x##Vector(x##Vector* vec,x* value){ \
	if(vec==NULL) return;\
	if(vec->vsize>=vec->capacity){\
		x* tmp=(x*)mi_calloc(sizeof(x)*(vec->capacity+5),1);\
		mi_memcpy(tmp,vec->payload,sizeof(x)*vec->vsize);\
		mi_free(vec->payload);\
		vec->payload=tmp;\
		vec->capacity+=5;\
	}\
	if(value)\
		mi_memcpy(&vec->payload[vec->vsize++],value,sizeof(x));\
	else\
		mi_memset(&vec->payload[vec->vsize++],0,sizeof(x));\
}\
void mi_create_##x##Vector(x##Vector* vec){\
	vec->capacity=5;\
	vec->payload=(x*)mi_calloc(vec->capacity*sizeof(x),1);\
	vec->vsize=0;\
}\
void mi_destroy_##x##Vector(x##Vector* vec){\
	vec->vsize=0;\
	vec->capacity=0;\
	mi_free(vec->payload);\
}\
void mi_clear_##x##Vector(x##Vector* vec){\
	mi_memset(vec->payload,0,vec->capacity*sizeof(x));\
	vec->vsize=0;\
}\
void mi_remove_##x##Vector(x##Vector* vec,int32_t index){\
	if(vec==NULL||vec->vsize==0||index>=vec->vsize) return;\
	if(vec->vsize==1) {mi_clear_##x##Vector(vec);return;}\
	if(vec->vsize!=index+1){mi_memmove((char*)vec->payload+index*sizeof(x),(char*)vec->payload+(index+1)*sizeof(x),sizeof(x)*(vec->vsize-index-1));}\
	vec->vsize--;\
}\


#define mi_vector_declare2(x) \
typedef struct{ \
	int32_t capacity; \
	int32_t vsize; \
	x** payload; \
}x##Vector; \
typedef struct{ \
	x##Vector vec;\
	void (*clear)(x##Vector* vec);\
	void (*insert)(x##Vector* vec,x* value);\
	void (*remove)(x##Vector* vec,int32_t index);\
}x##Vector2; \
void mi_create_##x##Vector2(x##Vector2* vec);\
void mi_destroy_##x##Vector2(x##Vector2* vec);\



#define mi_vector_impl2(x) \
void mi_insert_##x##Vector2(x##Vector* vec,x* value){ \
	if(vec==NULL) return;\
	if(vec->vsize>=vec->capacity){\
		x** tmp=(x**)mi_calloc(sizeof(x*)*(vec->capacity+5),1);\
		mi_memcpy(tmp,vec->payload,sizeof(x*)*vec->vsize);\
		mi_free(vec->payload);\
		vec->payload=tmp;\
		vec->capacity+=5;\
	}\
	if(value)\
		vec->payload[vec->vsize++]=value;\
}\
void mi_destroy_##x##Vector2(x##Vector2* vec){\
	vec->vec.vsize=0;\
	vec->vec.capacity=0;\
	mi_free(vec->vec.payload);\
}\
void mi_clear_##x##Vector2(x##Vector* vec){\
	mi_memset(vec->payload,0,vec->capacity*sizeof(x*));\
	vec->vsize=0;\
}\
void mi_remove_##x##Vector2(x##Vector* vec,int32_t index){\
	if(vec==NULL||vec->vsize==0||index>=vec->vsize) return;\
	if(vec->vsize==1) {mi_clear_##x##Vector2(vec);return;}\
	if(vec->vsize!=index+1){mi_memmove((char*)vec->payload+index*sizeof(x*),(char*)vec->payload+(index+1)*sizeof(x*),sizeof(x*)*(vec->vsize-index-1));}\
	vec->vsize--;\
}\
void mi_create_##x##Vector2(x##Vector2* vec){\
	vec->vec.vsize=0;\
	vec->vec.capacity=5;\
	vec->vec.payload=(x**)mi_calloc(vec->vec.capacity*sizeof(x*),1);\
	vec->insert=mi_insert_##x##Vector2;\
	vec->remove=mi_remove_##x##Vector2;\
	vec->clear=mi_clear_##x##Vector2;\
}\

#endif
