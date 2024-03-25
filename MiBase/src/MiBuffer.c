
#include "MiBuffer.h"

void mi_init_buffer(MiBuffer* buf, char* b, int32_t nn) {
    buf->head = buf->data = b;
    buf->size = nn;
}
void mi_destroy_buffer(MiBuffer* buf) {

}
int32_t mi_buffer_pos(MiBuffer* buf)
{
    return (int)(buf->head - buf->data);
}

int32_t mi_buffer_left(MiBuffer* buf)
{
    return buf->size - (int)(buf->head - buf->data);
}

int32_t mi_buffer_empty(MiBuffer* buf)
{
    return !buf->data || (buf->head >= buf->data + buf->size);
}

int32_t mi_buffer_require(MiBuffer* buf, int32_t required_size)
{
    if (required_size < 0) {
        return 0;
    }

    return required_size <= buf->size - (buf->head - buf->data);
}

void mi_buffer_skip(MiBuffer* buf, int32_t size)
{
    if (buf == NULL) return;

    buf->head += size;
}

char mi_read_1bytes(MiBuffer* buf)
{

    return *buf->head++;
}

int16_t mi_read_2bytes(MiBuffer* buf)
{


    int16_t value;
    char* pp = (char*)&value;
    pp[1] = *buf->head++;
    pp[0] = *buf->head++;

    return value;
}

uint16_t mi_readchar_2bytes(char* buf)
{


    uint16_t value = 0;
    char* pp = (char*)&value;
    pp[1] = buf[0];
    pp[0] = buf[1];

    return value;
}

int16_t mi_read_le2bytes(MiBuffer* buf)
{


    int16_t value;
    char* pp = (char*)&value;
    pp[1] = *buf->head++;
    pp[0] = *buf->head++;

    return value;
}

int32_t mi_read_3bytes(MiBuffer* buf)
{


    int32_t value = 0x00;
    char* pp = (char*)&value;
    pp[2] = *buf->head++;
    pp[1] = *buf->head++;
    pp[0] = *buf->head++;

    return value;
}

int32_t mi_read_le3bytes(MiBuffer* buf)
{


    int32_t value = 0x00;
    char* pp = (char*)&value;
    pp[0] = *buf->head++;
    pp[1] = *buf->head++;
    pp[2] = *buf->head++;

    return value;
}

int32_t mi_read_4bytes(MiBuffer* buf)
{


    int32_t value = 0;
    char* pp = (char*)&value;
    pp[3] = *buf->head++;
    pp[2] = *buf->head++;
    pp[1] = *buf->head++;
    pp[0] = *buf->head++;

    return value;
}


uint32_t mi_readchar_4bytes(char* buf)
{


    uint32_t value;
    char* pp = (char*)&value;
    pp[3] = buf[0];
    pp[2] = buf[1];
    pp[1] = buf[2];
    pp[0] = buf[3];

    return value;
}

int32_t mi_read_le4bytes(MiBuffer* buf)
{


    int32_t value;
    char* pp = (char*)&value;
    pp[0] = *buf->head++;
    pp[1] = *buf->head++;
    pp[2] = *buf->head++;
    pp[3] = *buf->head++;

    return value;
}

int64_t mi_read_8bytes(MiBuffer* buf)
{


    int64_t value;
    char* pp = (char*)&value;
    pp[7] = *buf->head++;
    pp[6] = *buf->head++;
    pp[5] = *buf->head++;
    pp[4] = *buf->head++;
    pp[3] = *buf->head++;
    pp[2] = *buf->head++;
    pp[1] = *buf->head++;
    pp[0] = *buf->head++;

    return value;
}

int64_t mi_read_le8bytes(MiBuffer* buf)
{
    int64_t value;
    char* pp = (char*)&value;
    pp[0] = *buf->head++;
    pp[1] = *buf->head++;
    pp[2] = *buf->head++;
    pp[3] = *buf->head++;
    pp[4] = *buf->head++;
    pp[5] = *buf->head++;
    pp[6] = *buf->head++;
    pp[7] = *buf->head++;

    return value;
}



void mi_read_bytes(MiBuffer* buf, char* data, int32_t size)
{
    mi_memcpy(data, buf->head, size);
    buf->head += size;
}

void mi_write_1bytes(MiBuffer* buf, char value)
{
    *buf->head++ = value;
}

void mi_write_2bytes(MiBuffer* buf, int16_t value)
{
    char* pp = (char*)&value;
    *buf->head++ = pp[1];
    *buf->head++ = pp[0];
}

void mi_write_le2bytes(MiBuffer* buf, int16_t value)
{

    char* pp = (char*)&value;
    *buf->head++ = pp[0];
    *buf->head++ = pp[1];
}

void mi_write_4bytes(MiBuffer* buf, int32_t value)
{
    char* pp = (char*)&value;
    *buf->head++ = pp[3];
    *buf->head++ = pp[2];
    *buf->head++ = pp[1];
    *buf->head++ = pp[0];
}

void mi_write_le4bytes(MiBuffer* buf, int32_t value)
{
    char* pp = (char*)&value;
    *buf->head++ = pp[0];
    *buf->head++ = pp[1];
    *buf->head++ = pp[2];
    *buf->head++ = pp[3];
}

void mi_write_3bytes(MiBuffer* buf, int32_t value)
{
    char* pp = (char*)&value;
    *buf->head++ = pp[2];
    *buf->head++ = pp[1];
    *buf->head++ = pp[0];
}

void mi_write_le3bytes(MiBuffer* buf, int32_t value)
{
    char* pp = (char*)&value;
    *buf->head++ = pp[0];
    *buf->head++ = pp[1];
    *buf->head++ = pp[2];
}

void mi_write_8bytes(MiBuffer* buf, int64_t value)
{
    char* pp = (char*)&value;
    *buf->head++ = pp[7];
    *buf->head++ = pp[6];
    *buf->head++ = pp[5];
    *buf->head++ = pp[4];
    *buf->head++ = pp[3];
    *buf->head++ = pp[2];
    *buf->head++ = pp[1];
    *buf->head++ = pp[0];
}

void mi_write_le8bytes(MiBuffer* buf, int64_t value)
{
    char* pp = (char*)&value;
    *buf->head++ = pp[0];
    *buf->head++ = pp[1];
    *buf->head++ = pp[2];
    *buf->head++ = pp[3];
    *buf->head++ = pp[4];
    *buf->head++ = pp[5];
    *buf->head++ = pp[6];
    *buf->head++ = pp[7];
}


void mi_write_bytes(MiBuffer* buf, char* data, int32_t size)
{
    mi_memcpy(buf->head, data, size);
    buf->head += size;
}

void mi_write_cstring(MiBuffer* buf, char* data)
{
    int32_t datasize = mi_strlen(data);
    mi_memcpy(buf->head, data, datasize);
    buf->head += datasize;
}
