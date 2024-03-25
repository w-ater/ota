#include "MiVector.h"
#include "MiMath.h"


void mi_insert_stringVector(MiStringVector* vec,char* str){
	if(vec==NULL||str==NULL) 
		return;
	mi_insert_stringVector2(vec,str,mi_strlen(str)+1);
}
void mi_insert_stringVector2(MiStringVector* vec,char* str,int plen){
	if(vec==NULL||str==NULL) 
		return;
	if(vec->vsize>=vec->capacity){
		char** tmp=(char**)mi_malloc((vec->capacity+5)*sizeof(char*));
		mi_memcpy(tmp,vec->payload,vec->vsize*sizeof(char*));
		mi_free(vec->payload);
		vec->payload=tmp;
		vec->capacity+=5;
	}
	vec->payload[vec->vsize]=(char*)mi_calloc(plen,1);
	mi_memcpy(vec->payload[vec->vsize],str,plen);
	vec->vsize++;
}
void mi_create_stringVector(MiStringVector* vec){
	if(vec==NULL) return;
	vec->capacity=5;
	vec->payload=(char**)mi_calloc(vec->capacity*sizeof(char*),1);
	vec->vsize=0;
}

void mi_destroy_stringVector(MiStringVector* vec){
	if(vec==NULL) return;
	for(int i=0;i<vec->vsize;i++){
		mi_free(vec->payload[i]);
	}
	vec->vsize=0;
	vec->capacity=0;
	mi_free(vec->payload);
}
void mi_clear_stringVector(MiStringVector* vec){
	if(vec==NULL) return;
	mi_memset(vec->payload,0,sizeof(char*)*vec->capacity);
	vec->vsize=0;
}


void mi_insert_uint16Sort(MiUint16Sort* psort,uint16_t val){
	if (psort->vsize >= psort->capacity - 1) {
		uint16_t *tmp = (uint16_t*) mi_calloc((psort->capacity + 50) * sizeof(uint16_t), 1);
		mi_memcpy(tmp, psort->payload, psort->vsize * sizeof(uint16_t));
		mi_free(psort->payload);
		psort->payload = tmp;
		psort->capacity += 50;
	}
	mi_insert_uint16_sort(psort->payload, val, &psort->vsize);
}
void mi_create_uint16Sort(MiUint16Sort* psort){
	mi_create_uint16Sort2(psort,50);
}
void mi_create_uint16Sort2(MiUint16Sort* psort,int32_t pcapacity){
	if(psort==NULL) 
		return;
	psort->capacity = pcapacity;
	if (psort->payload == NULL)		
		psort->payload = (uint16_t*) mi_calloc(sizeof(uint16_t) * psort->capacity,1);
}
void mi_destroy_uint16Sort(MiUint16Sort* psort)
{
	if(psort==NULL) 
		return;
	mi_free(psort->payload);
	psort->capacity=0;
	psort->vsize=0;
}
void mi_clear_uint16Sort(MiUint16Sort* psort){
	psort->vsize=0;
}

void mi_clear_uint16Sort2(MiUint16Sort* psort,int32_t index)
{
	if(psort->vsize==0)
		return;
	int32_t vsize=psort->vsize-index-1;
	mi_memmove((char*)psort->payload,(char*)psort->payload+index*sizeof(uint16_t),vsize*sizeof(uint16_t));
	psort->vsize=vsize;
}
