#ifndef MiBuffer_H_
#define MiBuffer_H_
#include "MiUtil.h"
typedef struct {
    // current position at bytes.
    char* head;
    // the bytes data for buffer to read or write.
    char* data;
    // the total number of bytes.
    int32_t size;
}MiBuffer;

void mi_init_buffer(MiBuffer* buf, char* b, int32_t nn);
void mi_destroy_buffer(MiBuffer* buf);
int32_t mi_buffer_pos(MiBuffer* buf);
// Left bytes in buffer, total size() minus the current pos().
int32_t mi_buffer_left(MiBuffer* buf);
// Whether buffer is empty.
int32_t mi_buffer_empty(MiBuffer* buf);
// Whether buffer is able to supply required size of bytes.
// @remark User should check buffer by require then do read/write.
// @remark Assert the required_size is not negative.
int32_t mi_buffer_require(MiBuffer* buf, int32_t required_size);
void mi_buffer_skip(MiBuffer* buf, int32_t size);
// Write 1bytes char to buffer.
void mi_write_1bytes(MiBuffer* buf, char value);
// Write 2bytes int32_t to buffer.
void mi_write_2bytes(MiBuffer* buf, int16_t value);
void mi_write_le2bytes(MiBuffer* buf, int16_t value);
// Write 4bytes int32_t to buffer.
void mi_write_4bytes(MiBuffer* buf, int32_t value);
void mi_write_le4bytes(MiBuffer* buf, int32_t value);
// Write 3bytes int32_t to buffer.
void mi_write_3bytes(MiBuffer* buf, int32_t value);
void mi_write_le3bytes(MiBuffer* buf, int32_t value);
// Write 8bytes int32_t to buffer.
void mi_write_8bytes(MiBuffer* buf, int64_t value);
void mi_write_le8bytes(MiBuffer* buf, int64_t value);
// Write string to buffer

// Write bytes to buffer
void mi_write_bytes(MiBuffer* buf, char* data, int32_t size);
void mi_write_cstring(MiBuffer* buf, char* data);

// Read 1bytes char from buffer.
char mi_read_1bytes(MiBuffer* buf);
// Read 2bytes int32_t from buffer.
int16_t mi_read_2bytes(MiBuffer* buf);
int16_t mi_read_le2bytes(MiBuffer* buf);
// Read 3bytes int32_t from buffer.
int32_t mi_read_3bytes(MiBuffer* buf);
int32_t mi_read_le3bytes(MiBuffer* buf);
// Read 4bytes int32_t from buffer.
int32_t mi_read_4bytes(MiBuffer* buf);
int32_t mi_read_le4bytes(MiBuffer* buf);
// Read 8bytes int32_t from buffer.
int64_t mi_read_8bytes(MiBuffer* buf);
int64_t mi_read_le8bytes(MiBuffer* buf);
// Read bytes from buffer, length specifies by param len.
void mi_read_bytes(MiBuffer* buf, char* data, int32_t size);


uint16_t mi_readchar_2bytes(char* buf);
uint32_t mi_readchar_4bytes(char* buf);


#endif