#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h>
#include <netdb.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <pthread.h>
#include <sys/time.h>
#include <time.h>
#include <signal.h>
#include <stdbool.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h> //使用 malloc, calloc等动态分配内存方法
#include <time.h>   //获取系统时间
#include <errno.h>
#include <pthread.h>
#include <fcntl.h> //非阻塞
#include <sys/un.h>
#include <arpa/inet.h>  //inet_addr()
#include <unistd.h>     //close()
#include <sys/types.h>  //文件IO操作
#include <sys/socket.h> //
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netdb.h> //gethostbyname, gethostbyname2, gethostbyname_r, gethostbyname_r2
#include <sys/un.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/ioctl.h> //SIOCSIFADDR

#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include "./wolfssl/openssl/ssl.h"  //wolfssl转openssl的兼容层
#include "./wolfssl/ssl.h" 

#define SERIAL_PORT "/dev/ttyUSB2"
#define BUFFER_SIZE 256

#define TIMEOUT_SEC 3

#define false   0
#define true    1
#define MY_BUF_SIZE 256
/* 
#define OTA_DEBUG //开启debug打印
#ifdef OTA_DEBUG
#define OTA_INFO(...) fprintf(stdout, "[OTA_INFO] %s(%d): ", __FUNCTION__, __LINE__),fprintf(stdout, __VA_ARGS__)
#define OTA_ERR(...) fprintf(stderr, "[OTA_ERR] %s(%d): ", __FUNCTION__, __LINE__),fprintf(stderr, __VA_ARGS__)
#else
#define OTA_INFO(...)
#define OTA_ERR(...) 
#endif
*/
#define NONE_LEVEL 0
#define INFO_LEVEL 1
#define ERR_LEVEL  2
	
	
#define LOG_LEVEL 1//打印级别控制的宏定义
	
#if(LOG_LEVEL == NONE_LEVEL)
#define OTA_INFO(...)
#define OTA_ERR(...) 
#elif(LOG_LEVEL == INFO_LEVEL)
#define OTA_INFO(...) fprintf(stdout, "[OTA_INFO] %s(%d): ", __FUNCTION__, __LINE__),fprintf(stdout, __VA_ARGS__)
#define OTA_ERR(...) fprintf(stderr, "[OTA_INFO] %s(%d): ", __FUNCTION__, __LINE__),fprintf(stderr, __VA_ARGS__)
#elif(LOG_LEVEL == ERR_LEVEL)
#define OTA_INFO(...) 
#define OTA_ERR(...) fprintf(stderr, "[OTA_INFO] %s(%d): ", __FUNCTION__, __LINE__),fprintf(stderr, __VA_ARGS__)
#endif
#define OTA_DEBUG //开启debug打印

static void OTA_HEX(FILE* f, void* dat, uint32_t len)
{
    uint8_t* p = (uint8_t*)dat;
    uint32_t i;
    for (i = 0; i < len; i++)
        fprintf(f, "%02X ", p[i]);
    fprintf(f, "\r\n");
}
typedef struct
{
    pthread_t thread_id;
    char ip[256];
    bool result;
    bool actionEnd;
} GetHostName_Struct;

static void* ws_getHostThread(void* argv)
{
    int32_t ret;
    //int32_t i;
    char buf[1024];
    struct hostent host_body, *host = NULL;
    struct in_addr **addr_list;
    GetHostName_Struct *gs = (GetHostName_Struct *)argv;

    /*  此类方法不可重入!  即使关闭线程
    if((host = gethostbyname(gs->ip)) == NULL)
    //if((host = gethostbyname2(gs->ip, AF_INET)) == NULL)
    {
        gs->actionEnd = true;
        return NULL;
    }*/
    if (gethostbyname_r(gs->ip, &host_body, buf, sizeof(buf), &host, &ret))
    {
        gs->actionEnd = true;
        return NULL;
    }

    if (host == NULL)
    {
        gs->actionEnd = true;
        return NULL;
    }

    addr_list = (struct in_addr **)host->h_addr_list;
    // printf("ip name: %s\r\nip list: ", host->h_name);
    // for(i = 0; addr_list[i] != NULL; i++)
    //     printf("%s, ", inet_ntoa(*addr_list[i]));
    // printf("\r\n");

    //一个域名可用解析出多个ip,这里只用了第一个
    if (addr_list[0] == NULL)
    {
        gs->actionEnd = true;
        return NULL;
    }
    memset(gs->ip, 0, sizeof(gs->ip));
    strcpy(gs->ip, (char*)(inet_ntoa(*addr_list[0])));
    gs->result = true;
    gs->actionEnd = true;
    return NULL;
}

int32_t ws_getIpByHostName(const char* hostName, char* retIp, int32_t timeoutMs)
{
    int32_t timeout = 0;
    GetHostName_Struct gs;
    if (!hostName || strlen(hostName) < 1)
        return -1;
    //开线程从域名获取IP
    memset(&gs, 0, sizeof(GetHostName_Struct));
    strcpy(gs.ip, hostName);
    gs.result = false;
    gs.actionEnd = false;
    if (pthread_create(&gs.thread_id, NULL, ws_getHostThread, &gs) < 0)
        return -1;
    //等待请求结果
    do {
        usleep(1000);
    } while (!gs.actionEnd && ++timeout < timeoutMs);
    //pthread_cancel(gs.thread_id);
    pthread_join(gs.thread_id, NULL);
    if (!gs.result)
        return -timeout;
    //一个域名可用解析出多个ip,这里只用了第一个
    memset(retIp, 0, strlen((const char*)retIp));
    strcpy(retIp, gs.ip);
    return timeout;
}
//https://application.daguiot.com/ota/error?version=1.0.0.1&msg=""
//static void ws_buildHttpHead(char* ip, int32_t port, char* path, char* shakeKey, char* package)
//{
//    const char httpDemo[] =
//        "GET %s HTTP/1.1\r\n"
//        "Connection: Upgrade\r\n"
//        "Host: %s:%d\r\n"
//        "Sec-WebSocket-Key: %s\r\n"
//        "Sec-WebSocket-Version: 13\r\n"
//        "Upgrade: websocket\r\n\r\n";
//    sprintf(package, httpDemo, path, ip, port, shakeKey);
//}

int32_t https_buildHttpHead(char* ip, char* path, char* shakeKey, char* package)
{
		
//    char ip[128] = {0};
//    char path[128] = {0};
//	
//	strcpy(ip, "application.daguiot.com");
//	
//	memset(path, 0, sizeof(path));
//	char pathDemo[] = "/ota/error?version=1.0.0.1&msg=\"\"";
	
	const char httpDemo[] =
	"GET %s HTTP/1.1\r\n"
	"Host: %s\r\n"
	"Accept-Encoding:gzip, deflate, br\r\n"
    "Connection:close\r\n"\
	"Cache-Control:no-cache\r\n"
	"Content-Length:0\r\n"
	"\r\n";
	sprintf(package, httpDemo, path, ip);
	OTA_INFO("package %s\n",package);
}
//==================== 加密方法BASE64 ====================

//base64编/解码用的基础字符集
static const char ws_base64char[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

int32_t ws_base64_encode(const uint8_t* bindata, char* base64, int32_t binlength)
{
    int32_t i, j;
    uint8_t current;
    for (i = 0, j = 0; i < binlength; i += 3)
    {
        current = (bindata[i] >> 2);
        current &= (uint8_t)0x3F;
        base64[j++] = ws_base64char[(int32_t)current];
        current = ((uint8_t)(bindata[i] << 4)) & ((uint8_t)0x30);
        if (i + 1 >= binlength)
        {
            base64[j++] = ws_base64char[(int32_t)current];
            base64[j++] = '=';
            base64[j++] = '=';
            break;
        }
        current |= ((uint8_t)(bindata[i + 1] >> 4)) & ((uint8_t)0x0F);
        base64[j++] = ws_base64char[(int32_t)current];
        current = ((uint8_t)(bindata[i + 1] << 2)) & ((uint8_t)0x3C);
        if (i + 2 >= binlength)
        {
            base64[j++] = ws_base64char[(int32_t)current];
            base64[j++] = '=';
            break;
        }
        current |= ((uint8_t)(bindata[i + 2] >> 6)) & ((uint8_t)0x03);
        base64[j++] = ws_base64char[(int32_t)current];
        current = ((uint8_t)bindata[i + 2]) & ((uint8_t)0x3F);
        base64[j++] = ws_base64char[(int32_t)current];
    }
    base64[j] = '\0';
    return j;
}
/*******************************************************************************
 * 名称: ws_base64_decode
 * 功能: base64格式解码为ascii
 * 参数: 
 *      base64: base64字符串输入
 *      bindata: ascii字符串输出
 * 返回: 解码出来的ascii字符串长度
 * 说明: 无
 ******************************************************************************/
int32_t ws_base64_decode(const char* base64, uint8_t* bindata)
{
    int32_t i, j;
    uint8_t k;
    uint8_t temp[4];
    for (i = 0, j = 0; base64[i] != '\0'; i += 4)
    {
        memset(temp, 0xFF, sizeof(temp));
        for (k = 0; k < 64; k++)
        {
            if (ws_base64char[k] == base64[i])
                temp[0] = k;
        }
        for (k = 0; k < 64; k++)
        {
            if (ws_base64char[k] == base64[i + 1])
                temp[1] = k;
        }
        for (k = 0; k < 64; k++)
        {
            if (ws_base64char[k] == base64[i + 2])
                temp[2] = k;
        }
        for (k = 0; k < 64; k++)
        {
            if (ws_base64char[k] == base64[i + 3])
                temp[3] = k;
        }
        bindata[j++] = ((uint8_t)(((uint8_t)(temp[0] << 2)) & 0xFC)) |
                       ((uint8_t)((uint8_t)(temp[1] >> 4) & 0x03));
        if (base64[i + 2] == '=')
            break;
        bindata[j++] = ((uint8_t)(((uint8_t)(temp[1] << 4)) & 0xF0)) |
                       ((uint8_t)((uint8_t)(temp[2] >> 2) & 0x0F));
        if (base64[i + 3] == '=')
            break;
        bindata[j++] = ((uint8_t)(((uint8_t)(temp[2] << 6)) & 0xF0)) |
                       ((uint8_t)(temp[3] & 0x3F));
    }
    return j;
}
typedef struct SHA1Context
{
    uint32_t Message_Digest[5];
    uint32_t Length_Low;
    uint32_t Length_High;
    uint8_t Message_Block[64];
    int32_t Message_Block_Index;
    int32_t Computed;
    int32_t Corrupted;
} SHA1Context;

#define SHA1CircularShift(bits, word) ((((word) << (bits)) & 0xFFFFFFFF) | ((word) >> (32 - (bits))))

static void SHA1ProcessMessageBlock(SHA1Context *context)
{
    const uint32_t K[] = {0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6};
    int32_t t;
    uint32_t temp;
    uint32_t W[80];
    uint32_t A, B, C, D, E;

    for (t = 0; t < 16; t++)
    {
        W[t] = ((uint32_t)context->Message_Block[t * 4]) << 24;
        W[t] |= ((uint32_t)context->Message_Block[t * 4 + 1]) << 16;
        W[t] |= ((uint32_t)context->Message_Block[t * 4 + 2]) << 8;
        W[t] |= ((uint32_t)context->Message_Block[t * 4 + 3]);
    }

    for (t = 16; t < 80; t++)
        W[t] = SHA1CircularShift(1, W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16]);

    A = context->Message_Digest[0];
    B = context->Message_Digest[1];
    C = context->Message_Digest[2];
    D = context->Message_Digest[3];
    E = context->Message_Digest[4];

    for (t = 0; t < 20; t++)
    {
        temp = SHA1CircularShift(5, A) + ((B & C) | ((~B) & D)) + E + W[t] + K[0];
        temp &= 0xFFFFFFFF;
        E = D;
        D = C;
        C = SHA1CircularShift(30, B);
        B = A;
        A = temp;
    }
    for (t = 20; t < 40; t++)
    {
        temp = SHA1CircularShift(5, A) + (B ^ C ^ D) + E + W[t] + K[1];
        temp &= 0xFFFFFFFF;
        E = D;
        D = C;
        C = SHA1CircularShift(30, B);
        B = A;
        A = temp;
    }
    for (t = 40; t < 60; t++)
    {
        temp = SHA1CircularShift(5, A) + ((B & C) | (B & D) | (C & D)) + E + W[t] + K[2];
        temp &= 0xFFFFFFFF;
        E = D;
        D = C;
        C = SHA1CircularShift(30, B);
        B = A;
        A = temp;
    }
    for (t = 60; t < 80; t++)
    {
        temp = SHA1CircularShift(5, A) + (B ^ C ^ D) + E + W[t] + K[3];
        temp &= 0xFFFFFFFF;
        E = D;
        D = C;
        C = SHA1CircularShift(30, B);
        B = A;
        A = temp;
    }
    context->Message_Digest[0] = (context->Message_Digest[0] + A) & 0xFFFFFFFF;
    context->Message_Digest[1] = (context->Message_Digest[1] + B) & 0xFFFFFFFF;
    context->Message_Digest[2] = (context->Message_Digest[2] + C) & 0xFFFFFFFF;
    context->Message_Digest[3] = (context->Message_Digest[3] + D) & 0xFFFFFFFF;
    context->Message_Digest[4] = (context->Message_Digest[4] + E) & 0xFFFFFFFF;
    context->Message_Block_Index = 0;
}

static void SHA1Reset(SHA1Context* context)
{
    context->Length_Low = 0;
    context->Length_High = 0;
    context->Message_Block_Index = 0;

    context->Message_Digest[0] = 0x67452301;
    context->Message_Digest[1] = 0xEFCDAB89;
    context->Message_Digest[2] = 0x98BADCFE;
    context->Message_Digest[3] = 0x10325476;
    context->Message_Digest[4] = 0xC3D2E1F0;

    context->Computed = 0;
    context->Corrupted = 0;
}

static void SHA1PadMessage(SHA1Context* context)
{
    if (context->Message_Block_Index > 55)
    {
        context->Message_Block[context->Message_Block_Index++] = 0x80;
        while (context->Message_Block_Index < 64)
            context->Message_Block[context->Message_Block_Index++] = 0;
        SHA1ProcessMessageBlock(context);
        while (context->Message_Block_Index < 56)
            context->Message_Block[context->Message_Block_Index++] = 0;
    }
    else
    {
        context->Message_Block[context->Message_Block_Index++] = 0x80;
        while (context->Message_Block_Index < 56)
            context->Message_Block[context->Message_Block_Index++] = 0;
    }
    context->Message_Block[56] = (context->Length_High >> 24) & 0xFF;
    context->Message_Block[57] = (context->Length_High >> 16) & 0xFF;
    context->Message_Block[58] = (context->Length_High >> 8) & 0xFF;
    context->Message_Block[59] = (context->Length_High) & 0xFF;
    context->Message_Block[60] = (context->Length_Low >> 24) & 0xFF;
    context->Message_Block[61] = (context->Length_Low >> 16) & 0xFF;
    context->Message_Block[62] = (context->Length_Low >> 8) & 0xFF;
    context->Message_Block[63] = (context->Length_Low) & 0xFF;

    SHA1ProcessMessageBlock(context);
}

static int32_t SHA1Result(SHA1Context* context)
{
    if (context->Corrupted)
    {
        return 0;
    }
    if (!context->Computed)
    {
        SHA1PadMessage(context);
        context->Computed = 1;
    }
    return 1;
}

static void SHA1Input(SHA1Context* context, const char* message_array, uint32_t length)
{
    if (!length)
        return;

    if (context->Computed || context->Corrupted)
    {
        context->Corrupted = 1;
        return;
    }

    while (length-- && !context->Corrupted)
    {
        context->Message_Block[context->Message_Block_Index++] = (*message_array & 0xFF);

        context->Length_Low += 8;

        context->Length_Low &= 0xFFFFFFFF;
        if (context->Length_Low == 0)
        {
            context->Length_High++;
            context->Length_High &= 0xFFFFFFFF;
            if (context->Length_High == 0)
                context->Corrupted = 1;
        }

        if (context->Message_Block_Index == 64)
        {
            SHA1ProcessMessageBlock(context);
        }
        message_array++;
    }
}

static char* sha1_hash(const char* source)
{
    SHA1Context sha;
    char* buff = NULL;

    SHA1Reset(&sha);
    SHA1Input(&sha, source, strlen(source));

    if (!SHA1Result(&sha))
        OTA_ERR("SHA1 ERROR: Could not compute message digest \r\n");
    else
    {
        buff = (char*)calloc(128, sizeof(char));
        sprintf(buff, "%08X%08X%08X%08X%08X",
                sha.Message_Digest[0],
                sha.Message_Digest[1],
                sha.Message_Digest[2],
                sha.Message_Digest[3],
                sha.Message_Digest[4]);
    }
    return buff;
}

static void https_getRandomString(char* buff, uint32_t len)
{
    uint32_t i;
    uint8_t temp;
    srand((int32_t)time(0));
    for (i = 0; i < len; i++)
    {
        temp = (uint8_t)(rand() % 256);
        if (temp == 0) //随机数不要0
            temp = 128;
        buff[i] = temp;
    }
}

/*******************************************************************************
 * 名称: ws_buildShakeKey
 * 功能: client端使用随机数构建握手用的key
 * 参数: *key: 随机生成的握手key
 * 返回: key的长度
 * 说明: 无
 ******************************************************************************/
static int32_t ws_buildShakeKey(char* key)
{
    char tempKey[16] = {0};
    https_getRandomString(tempKey, 16);
    return ws_base64_encode((const uint8_t*)tempKey, (char*)key, 16);
}
static int32_t ws_buildRespondShakeKey(char* acceptKey, uint32_t acceptKeyLen, char* respondKey)
{
    char* clientKey;
    char* sha1DataTemp;
    uint8_t* sha1Data;
    int32_t i, j, sha1DataTempLen, ret;
    const char guid[] = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    uint32_t guidLen;

    if (acceptKey == NULL)
        return 0;

    guidLen = sizeof(guid);
    clientKey = (char*)calloc(acceptKeyLen + guidLen + 10, sizeof(char));
    memcpy(clientKey, acceptKey, acceptKeyLen);
    memcpy(&clientKey[acceptKeyLen], guid, guidLen);

    sha1DataTemp = sha1_hash(clientKey);
    sha1DataTempLen = strlen((const char*)sha1DataTemp);
    sha1Data = (uint8_t*)calloc(sha1DataTempLen / 2 + 1, sizeof(char));

    //把hex字符串如"12ABCDEF",转为数值数组如{0x12,0xAB,0xCD,0xEF}
    for (i = j = 0; i < sha1DataTempLen;)
    {
        if (sha1DataTemp[i] > '9')
            sha1Data[j] = (10 + sha1DataTemp[i] - 'A') << 4;
        else
            sha1Data[j] = (sha1DataTemp[i] - '0') << 4;

        i += 1;

        if (sha1DataTemp[i] > '9')
            sha1Data[j] |= (10 + sha1DataTemp[i] - 'A');
        else
            sha1Data[j] |= (sha1DataTemp[i] - '0');

        i += 1;
        j += 1;
    }

    ret = ws_base64_encode((const uint8_t*)sha1Data, (char*)respondKey, j);

    free(sha1DataTemp);
    free(sha1Data);
    free(clientKey);
    return ret;
}

static int32_t ws_matchShakeKey(char* clientKey, int32_t clientKeyLen, char* acceptKey, int32_t acceptKeyLen)
{
    int32_t retLen;
    char tempKey[MY_BUF_SIZE] = {0};

    retLen = ws_buildRespondShakeKey(clientKey, clientKeyLen, tempKey);
    if (retLen != acceptKeyLen)
    {
        OTA_INFO("len err, clientKey[%d] != acceptKey[%d]\r\n", retLen, acceptKeyLen);
        return -1;
    }
    else if (strcmp((const char*)tempKey, (const char*)acceptKey) != 0)
    {
        OTA_INFO("strcmp err, clientKey[%s -> %s] != acceptKey[%s]\r\n", clientKey, tempKey, acceptKey);
        return -1;
    }
    return 0;
}
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

#define PORT_NUMBER 80
#define HOST "application.daguiot.com"
#define MESSAGE "GET /ota/error?version=1.0.0.1&msg=hello HTTP/1.1\r\nHost: application.daguiot.com\r\nConnection: keep-alive\r\nAccept: */*\r\n\r\n"

int mylink() {
    int sockfd;
    struct sockaddr_in server_addr;
    struct hostent *server;

    // 创建套接字
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("Error opening socket");
        exit(1);
    }

    // 获取服务器地址
    server = gethostbyname(HOST);
    if (server == NULL) {
        fprintf(stderr,"Error, no such host\n");
        exit(1);
    }

    // 设置服务器地址结构
    bzero((char *) &server_addr, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    bcopy((char *)server->h_addr, (char *)&server_addr.sin_addr.s_addr, server->h_length);
    server_addr.sin_port = htons(PORT_NUMBER);

    // 连接到服务器
    if (connect(sockfd, (struct sockaddr *) &server_addr, sizeof(server_addr)) < 0) {
        perror("Error connecting");
        exit(1);
    }
    SSL *myssl = NULL;
    SSL_CTX *ctx = NULL;
#if 0   
    wolfSSL_Init();
    ctx = SSL_CTX_new (SSLv23_client_method());
    if((ctx) == NULL)
    {
        OTA_ERR("Fun:%s\tSSL_CTX ERROR\n", __FUNCTION__);
        return -1;
    }
    OTA_INFO("tim add SSL_CTX_set_verify test############\n");
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, 0);//fix SSL_connect fail

    if( (myssl = SSL_new(ctx)) == NULL) {
        fprintf(stderr, "wolfSSL_new error.\n");
        //exit(EXIT_FAILURE);
		return -1;
    }

    SSL_set_fd(myssl, sockfd);
	//SSL_set_mode(myssl, SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
	//SSL_set_mode(myssl, SSL_MODE_AUTO_RETRY);

	
    int ssl_ret;
    int fgCycleFlag = 1;
    while(fgCycleFlag )
    {
        ssl_ret = SSL_connect(myssl);
        switch(SSL_get_error(myssl, ssl_ret))//这里出错
        {
            case SSL_ERROR_NONE:
                OTA_INFO("Fun:%s\tSSL_ERROR_NONE,ssl_ret = %d\n", __FUNCTION__,ssl_ret);
                fgCycleFlag = 0;
                usleep(100000);
                break;
            case SSL_ERROR_WANT_WRITE:
                OTA_ERR("Fun:%s\tSSL_ERROR_WANT_WRITE,ssl_ret = %d\n", __FUNCTION__,ssl_ret);
                usleep(100000);
                return -1;
            case SSL_ERROR_WANT_READ:
                OTA_ERR("Fun:%s\tSSL_ERROR_WANT_READ,ssl_ret = %d\n", __FUNCTION__,ssl_ret);
                usleep(100000);
                return -1;
            default:    
                OTA_ERR("SSL_connect:%s SSL_get_error= %d\n", __FUNCTION__,SSL_get_error(myssl, ssl_ret));
                return -1;
        }   
    }
#endif
    wolfSSL_Init();
        ctx = SSL_CTX_new(SSLv23_client_method());
        if (ctx == NULL) {
            OTA_INFO("Fun:%s\tSSL_CTX ERROR\n", __FUNCTION__);
            return -1;
        }
    
        OTA_INFO("tim add SSL_CTX_set_verify test############\n");
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, 0); //fix SSL_connect fail
    
        myssl = SSL_new(ctx);
        if (myssl == NULL) {
            fprintf(stderr, "wolfSSL_new error.\n");
            SSL_CTX_free(ctx); // 释放SSL上下文
            return -1;
        }
    
        SSL_set_fd(myssl, sockfd);
        int ssl_ret;
        int fgCycleFlag = 1;
        while (fgCycleFlag) {
            ssl_ret = SSL_connect(myssl);
            switch (ssl_ret) {
                case 1: // SSL连接成功
                    OTA_INFO("Fun:%s\tSSL connect successful\n", __FUNCTION__);
                    fgCycleFlag = 0;
                    usleep(100000);
                    break;
                case 0: // SSL连接失败
                case -1: // SSL连接出错
                    OTA_ERR("SSL_connect error in %s\n", __FUNCTION__);
                    //SSL_free(myssl); // 释放SSL对象
                    //SSL_CTX_free(ctx); // 释放SSL上下文
                    return -1;
                case -2: // 需要再次调用SSL_connect
                    OTA_ERR("Fun:%s\tSSL connect in progress\n", __FUNCTION__);
                    usleep(100000);
                    return -1;
                default:
                    OTA_ERR("Unknown SSL_connect return value\n");
                    //SSL_free(myssl); // 释放SSL对象
                    //SSL_CTX_free(ctx); // 释放SSL上下文
                    return -1;
            }
        }

    // 发送消息
    int n = write(sockfd, MESSAGE, strlen(MESSAGE));
    if (n < 0) {
        perror("Error writing to socket");
        exit(1);
    }

    // 从服务器接收响应
    char buffer[256];
    bzero(buffer, 256);
    while (read(sockfd, buffer, 255) > 0) {
        OTA_INFO("%s", buffer);
        bzero(buffer, 256);
    }

    // 关闭套接字
    close(sockfd);

    return 0;
}
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <wolfssl/ssl.h>

#define PORT_NUMBER 443
#define HOST "application.daguiot.com"
#define MESSAGE "GET /ota/error?version=1.0.0.1&msg=hello HTTP/1.1\r\nHost: application.daguiot.com\r\nConnection: keep-alive\r\nAccept: */*\r\n\r\n"


int myconnect() {
    int sockfd;
    struct sockaddr_in server_addr;
    struct hostent *server;
    WOLFSSL_CTX *ctx;
    WOLFSSL *ssl;

    // wolfSSL初始化
    wolfSSL_Init();

    // 创建套接字
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("Error opening socket");
        exit(1);
    }

    // 获取服务器地址
    server = gethostbyname(HOST);
    if (server == NULL) {
        fprintf(stderr, "Error, no such host\n");
        exit(1);
    }

    // 设置服务器地址结构
    bzero((char *) &server_addr, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    bcopy((char *)server->h_addr, (char *)&server_addr.sin_addr.s_addr, server->h_length);
    server_addr.sin_port = htons(PORT_NUMBER);

    // 连接到服务器
    if (connect(sockfd, (struct sockaddr *) &server_addr, sizeof(server_addr)) < 0) {
        perror("Error connecting");
        exit(1);
    }

    // 创建wolfSSL上下文
    ctx = wolfSSL_CTX_new(wolfSSLv23_client_method());
    if (ctx == NULL) {
        fprintf(stderr, "wolfSSL_CTX_new error.\n");
        close(sockfd);
        exit(1);
    }
    wolfSSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, 0);//fix SSL_connect fail

    // 创建wolfSSL对象
    ssl = wolfSSL_new(ctx);
    if (ssl == NULL) {
        fprintf(stderr, "wolfSSL_new error.\n");
        wolfSSL_CTX_free(ctx);
        close(sockfd);
        exit(1);
    }

    // 将wolfSSL对象与套接字关联
    wolfSSL_set_fd(ssl, sockfd);
    char errorString[80];

    // SSL连接
    int ret;
    while ((ret = wolfSSL_connect(ssl)) != SSL_SUCCESS) {
        int error = wolfSSL_get_error(ssl, ret);
        if (error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE) {
            // 连接仍在进行中，继续尝试
            continue;
        } else {
            wolfSSL_ERR_error_string(error, errorString); // 获取错误信息
            fprintf(stderr, "wolfSSL_connect error: %s\n", errorString);
            wolfSSL_free(ssl);
            wolfSSL_CTX_free(ctx);
            close(sockfd);
            exit(1);
        }
    }

    // 发送消息
    int n = wolfSSL_write(ssl, MESSAGE, strlen(MESSAGE));
    if (n < 0) {
        perror("Error writing to socket");
        wolfSSL_free(ssl);
        wolfSSL_CTX_free(ctx);
        close(sockfd);
        exit(1);
    }

    // 从服务器接收响应
    char buffer[256];
    bzero(buffer, 256);
    while (wolfSSL_read(ssl, buffer, 255) > 0) {
        printf("%s", buffer);
        bzero(buffer, 256);
    }

    // 关闭wolfSSL连接
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);

    // 关闭套接字
    close(sockfd);

    // wolfSSL清理
    wolfSSL_Cleanup();

    return 0;
}

int myconnect2() {
    int sockfd;
    struct sockaddr_in server_addr;
    struct hostent *server;
    WOLFSSL_CTX *ctx;
    WOLFSSL *ssl;

    // wolfSSL初始化
    wolfSSL_Init();

    // 创建套接字
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("Error opening socket");
        exit(1);
    }

    // 获取服务器地址
    server = gethostbyname(HOST);
    if (server == NULL) {
        fprintf(stderr, "Error, no such host\n");
        exit(1);
    }

    // 设置服务器地址结构
    bzero((char *) &server_addr, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    bcopy((char *)server->h_addr, (char *)&server_addr.sin_addr.s_addr, server->h_length);
    server_addr.sin_port = htons(PORT_NUMBER);

    // 连接到服务器
    if (connect(sockfd, (struct sockaddr *) &server_addr, sizeof(server_addr)) < 0) {
        perror("Error connecting");
        exit(1);
    }

    // 创建wolfSSL上下文
    ctx = wolfSSL_CTX_new(wolfSSLv23_client_method());
    if (ctx == NULL) {
        fprintf(stderr, "wolfSSL_CTX_new error.\n");
        close(sockfd);
        exit(1);
    }

    // 创建wolfSSL对象
    ssl = wolfSSL_new(ctx);
    if (ssl == NULL) {
        fprintf(stderr, "wolfSSL_new error.\n");
        wolfSSL_CTX_free(ctx);
        close(sockfd);
        exit(1);
    }

    // 将wolfSSL对象与套接字关联
    wolfSSL_set_fd(ssl, sockfd);

    // SSL连接
//    if (wolfSSL_connect(ssl) != SSL_SUCCESS) {
//        fprintf(stderr, "wolfSSL_connect error.\n");
//        wolfSSL_free(ssl);
//        wolfSSL_CTX_free(ctx);
//        close(sockfd);
//        exit(1);
//    }
    // SSL连接
    int ret;
    while ((ret = wolfSSL_connect(ssl)) != SSL_SUCCESS) {
        int error = wolfSSL_get_error(ssl, ret);
        if (error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE) {
            // 连接仍在进行中，继续尝试
            continue;
        } else {
            fprintf(stderr, "wolfSSL_connect error: %s\n", wolfSSL_ERR_error_string(error, 0));
            wolfSSL_free(ssl);
            wolfSSL_CTX_free(ctx);
            close(sockfd);
            exit(1);
        }
    }

    // 发送消息
    int n = wolfSSL_write(ssl, MESSAGE, strlen(MESSAGE));
    if (n < 0) {
        perror("Error writing to socket");
        wolfSSL_free(ssl);
        wolfSSL_CTX_free(ctx);
        close(sockfd);
        exit(1);
    }

    // 从服务器接收响应
    char buffer[256];
    bzero(buffer, 256);
    while (wolfSSL_read(ssl, buffer, 255) > 0) {
        printf("%s", buffer);
        bzero(buffer, 256);
    }

    // 关闭wolfSSL连接
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);

    // 关闭套接字
    close(sockfd);

    // wolfSSL清理
    wolfSSL_Cleanup();

    return 0;
}

//t32_t https_postServer(char* ip, int32_t port, char* path, int32_t timeoutMs)
int32_t https_postServer(char* ip, char* path, int32_t timeoutMs)
{
    int32_t ret, fd;
    int32_t timeoutCount = 0;
    char retBuff[512] = {0};
    char httpHead[512] = {0};
    char shakeKey[128] = {0};
    char tempIp[128] = {0};
    char* p;

    //服务器端网络地址结构体
    struct sockaddr_in report_addr;
    memset(&report_addr, 0, sizeof(report_addr)); //数据初始化--清零
    report_addr.sin_family = AF_INET;             //设置为IP通信
    //report_addr.sin_port = htons(port);           //服务器端口号
    report_addr.sin_port = 0; 

    //服务器IP地址, 自动域名转换
    //report_addr.sin_addr.s_addr = inet_addr(ip);
    if ((report_addr.sin_addr.s_addr = inet_addr(ip)) == INADDR_NONE)
    {
        ret = ws_getIpByHostName(ip, tempIp, 1000);
        if (ret < 0)
            return ret;
        else if (strlen((const char*)tempIp) < 7)
            return -ret;
        else
            timeoutCount += ret;
        if ((report_addr.sin_addr.s_addr = inet_addr(tempIp)) == INADDR_NONE)
            return -ret;
#ifdef OTA_DEBUG
        OTA_INFO("Host(%s) to IP(%s)\r\n", ip, tempIp);
#endif
    }

    //默认超时1秒
    if (timeoutMs == 0)
        timeoutMs = 1000;

    //create unix socket
    if ((fd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        OTA_ERR("socket error\r\n");
        return -1;
    }
    OTA_ERR("111111111111111\r\n");
    // 设置非阻塞
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);

    // 开始连接
    if (connect(fd, (struct sockaddr *)&report_addr, sizeof(struct sockaddr)) < 0)
    {
        if (errno == EINPROGRESS)
        {
            // 连接正在进行中，使用select等待连接完成
            fd_set writefds;
            struct timeval tv;
            FD_ZERO(&writefds);
            FD_SET(fd, &writefds);

            tv.tv_sec = timeoutMs / 1000;
            tv.tv_usec = (timeoutMs % 1000) * 1000;

            ret = select(fd + 1, NULL, &writefds, NULL, &tv);
            if (ret <= 0)
            {
                perror("select error");
                close(fd);
                return -1;
            }
        }
        else
        {
            perror("connect error");
            close(fd);
            return -1;
        }
    }

    //connect
    //timeoutCount = 0;
//    while (connect(fd, (struct sockaddr *)&report_addr, sizeof(struct sockaddr)) != 0)
//    {
//        if (++timeoutCount > timeoutMs)
//        {
//            OTA_ERR("connect to %s:%d timeout(%dms)\r\n", ip, timeoutCount);
//            close(fd);
//            return -timeoutCount;
//        }
//        usleep(1000);
//    }


    OTA_ERR("22222222222222\r\n");

    //非阻塞
//    ret = fcntl(fd, F_GETFL, 0);
//    fcntl(fd, F_SETFL, ret | O_NONBLOCK);

    //发送http协议头
    memset(shakeKey, 0, sizeof(shakeKey));
    ws_buildShakeKey(shakeKey);                                   //创建握手key
    memset(httpHead, 0, sizeof(httpHead));                        //创建协议包
    //https_buildHttpHead(ip, path, shakeKey, (char*)httpHead); //组装http请求头
    
    https_buildHttpHead(ip, path, shakeKey, (char*)httpHead); //组装http请求头
    send(fd, httpHead, strlen((const char*)httpHead), MSG_NOSIGNAL);

#ifdef OTA_DEBUG
    OTA_INFO("connect: %dms\r\n%s\r\n", timeoutCount, httpHead);
#endif
    while (1)
    {
        memset(retBuff, 0, sizeof(retBuff));
        ret = recv(fd, retBuff, sizeof(retBuff), MSG_NOSIGNAL);
        if (ret > 0)
        {
#ifdef OTA_DEBUG
            //显示http返回
            OTA_INFO("recv: len %d / %dms\r\n%s\r\n", ret, timeoutCount, retBuff);
#endif
            //返回的是http回应信息
            if (strncmp((const char*)retBuff, "HTTP", 4) == 0)
            {
                //定位到握手字符串
                if ((p = strstr((char*)retBuff, "Sec-WebSocket-Accept: ")) != NULL)
                {
                    p += strlen("Sec-WebSocket-Accept: ");
                    sscanf((const char*)p, "%s\r\n", p);
                    //比对握手信息
                    if (ws_matchShakeKey(shakeKey, strlen((const char*)shakeKey), p, strlen((const char*)p)) == 0)
                    {
	                    strcpy(httpHead,"hello");	
						send(fd, httpHead, strlen((const char*)httpHead), MSG_NOSIGNAL);
                        return fd;
                    }
					//握手信号不对, 重发协议包
                    else
                        ret = send(fd, httpHead, strlen((const char*)httpHead), MSG_NOSIGNAL);
                }
                //重发协议包
                else
                    ret = send(fd, httpHead, strlen((const char*)httpHead), MSG_NOSIGNAL);
            }
            //显示异常返回数据
            else
            {
                //#ifdef WS_DEBUG
                OTA_ERR("recv: len %d / unknown context\r\n%s\r\n", ret, retBuff);
                OTA_HEX(stderr, retBuff, ret);
                //#endif
            }
        }
        usleep(1000);
        //超时检查
        if (++timeoutCount > timeoutMs * 2)
            break;
    }
    //连接失败,返回耗时(负值)
    close(fd);
    return -timeoutCount;
}

struct resp_header//保持相应头信息
{
    int status_code;//HTTP/1.1 '200' OK
    char content_type[128];//Content-Type: application/gzip
    long content_length;//Content-Length: 11683079
    char file_name[256];
};

struct resp_header resp;//全剧变量以便在多个进程中使用
 
void parse_url(const char *url, char *domain, int *port, char *file_name)
{
    /*通过url解析出域名, 端口, 以及文件名*/
    int j = 0,i=0;
    int start = 0;
    *port = 80;
    char *patterns[] = {"http://", "https://", NULL};
 
    for ( i = 0; patterns[i]; i++)
        if (strncmp(url, patterns[i], strlen(patterns[i])) == 0)
            start = strlen(patterns[i]);
 
    //解析域名, 这里处理时域名后面的端口号会保留
    for ( i = start; url[i] != '/' && url[i] != '\0'; i++, j++)
        domain[j] = url[i];
    domain[j] = '\0';
 
    //解析端口号, 如果没有, 那么设置端口为80
    char *pos = strstr(domain, ":");
    if (pos)
        sscanf(pos, ":%d", port);
 
    //删除域名端口号
 
    for (i = 0; i < (int)strlen(domain); i++)
    {
        if (domain[i] == ':')
        {
            domain[i] = '\0';
            break;
        }
    }
 
    //获取下载文件名
    j = 0;
    for (i = start; url[i] != '\0'; i++)
    {
        if (url[i] == '/')
        {
            if (i !=  strlen(url) - 1)
                j = 0;
            continue;
        }
        else
            file_name[j++] = url[i];
    }
    file_name[j] = '\0';
}
 
struct resp_header get_resp_header(const char *response)
{
    /*获取响应头的信息*/
    struct resp_header resp;
 
    char *pos = strstr(response, "HTTP/");
    if (pos)
        sscanf(pos, "%*s %d", &resp.status_code);//返回状态码
 
    pos = strstr(response, "Content-Type:");//返回内容类型
    if (pos)
        sscanf(pos, "%*s %s", resp.content_type);
 
    pos = strstr(response, "Content-Length:");//内容的长度(字节)
    if (pos)
        sscanf(pos, "%*s %ld", &resp.content_length);
 
    return resp;
}
 
void get_ip_addr(char *domain, char *ip_addr)
{
     int i=0;
    /*通过域名得到相应的ip地址*/
    struct hostent *host = gethostbyname(domain);
    if (!host)
    {
        ip_addr = NULL;
        return;
    }
 
    for (i = 0; host->h_addr_list[i]; i++)
    {
        strcpy(ip_addr, inet_ntoa( * (struct in_addr*) host->h_addr_list[i]));
        break;
    }
}
 
 
void progressBar(long cur_size, long total_size)
{
    /*用于显示下载进度条*/
    float percent = (float) cur_size / total_size;
    const int numTotal = 50;
    int numShow = (int)(numTotal * percent);
 
    if (numShow == 0)
        numShow = 1;
 
    if (numShow > numTotal)
        numShow = numTotal;
 
    char sign[51] = {0};
    memset(sign, '=', numTotal);
 
 
    OTA_INFO("\r%.2f%%\t[%-*.*s] %.2f/%.2fMB", percent * 100, numTotal, numShow, sign, cur_size / 1024.0 / 1024.0, total_size / 1024.0 / 1024.0);
    fflush(stdout);
 
    if (numShow == numTotal)
        OTA_INFO("\n");
}
#if 0
void * download(void * socket_d)
{
    /*下载文件函数, 放在线程中执行*/
    int client_socket = *(int *) socket_d;
    int length = 0;
    int mem_size = 4096;//mem_size might be enlarge, so reset it
    int buf_len = mem_size;//read 4k each time
    int len;
 
    //创建文件描述符
    int fd = open(resp.file_name, O_CREAT | O_WRONLY, S_IRWXG | S_IRWXO | S_IRWXU);
    if (fd < 0)
    {
        OTA_INFO("Create file failed\n");
        exit(0);
    }
 
    char *buf = (char *) malloc(mem_size * sizeof(char));
 
    //从套接字中读取文件流
    while ((len = read(client_socket, buf, buf_len)) != 0 && length < resp.content_length)
    {
        write(fd, buf, len);
        length += len;
        progressBar(length, resp.content_length);
    }
 
    if (length == resp.content_length)
        OTA_INFO("Download successful ^_^\n\n");
}
#endif
//#include "md5.h"
#define READ_DATA_SIZE	1024
#define MD5_SIZE		16
#define MD5_STR_LEN		(MD5_SIZE * 2)

int Compute_file_md5(const char *file_path, char *md5_str)
{
	int i;
	int fd;
	int ret;
	unsigned char data[READ_DATA_SIZE];
	unsigned char md5_value[MD5_SIZE];
	MD5_CTX md5;
 
	fd = open(file_path, O_RDONLY);
	if (-1 == fd)
	{
		perror("open");
		return -1;
	}
 
	// init md5
	MD5Init(&md5);
    
	//MD5Init(&md5);
 
	while (1)
	{
		ret = read(fd, data, READ_DATA_SIZE);
		if (-1 == ret)
		{
			perror("read");
			return -1;
		}
 
		MD5Update(&md5, data, ret);
 
		if (0 == ret || ret < READ_DATA_SIZE)
		{
			break;
		}
	}
 
	close(fd);
 
	MD5Final(&md5, md5_value);
 
	for(i = 0; i < MD5_SIZE; i++)
	{
		snprintf(md5_str + i*2, 2+1, "%02x", md5_value[i]);
	}
	md5_str[MD5_STR_LEN] = '\0'; // add end
 
	return 0;
}
#define CFGINI  "/root/app.ini"

int  GetDevVer(char* ver_out)
{
	int ret = readStringValue("ipc", "ver", ver_out, CFGINI);
	if (ret == 1)
	{
	    // 读取配置值成功
	}
	else
	{
	    OTA_ERR("Error reading configuration value\n");
	    // 可以根据具体情况采取适当的处理措施
	}
}
//#define CFGINI2  "/media/mmcblk0/ota"
#define CFGINI2  "/tmp/ota.ini"

int  GetOtaApp(char* ver_out)
{
	int ret = readStringValue("file", "extest", ver_out, CFGINI2);
	if (ret == 1)
	{
	    // 读取配置值成功
	}
	else
	{
	    OTA_ERR("Error reading configuration value\n");
	    // 可以根据具体情况采取适当的处理措施
	}
}

int  SetDevVer(const char* ver_in)
{
	writeStringVlaue("ipc", "ver", ver_in, CFGINI);
}
void read_ini_node(const char *filename, const char *node) {
    FILE *file = fopen(filename, "r");
    if (file == NULL) {
        OTA_INFO("Error opening file\n");
        return;
    }

    char line[100];
	char command[100];
    char *key, *value;
    int count = 0;

    while (fgets(line, sizeof(line), file)) {
        if (strstr(line, node) != NULL) {
            while (fgets(line, sizeof(line), file)) {
                if (line[0] == '[') {
                    break;
                }

                key = strtok(line, "=");
                value = strtok(NULL, "=");

                if (key != NULL && value != NULL) {
                    OTA_INFO("Key: %s, Value: %s\n", key, value);
                    count++;

					OTA_INFO("!!!file_path%s\n",value);

					memset(command,0,100);
					sprintf(command, "cp /tmp/ota/%s %s", key, value);

					system(command);
                }
            }
            break;
        }
    }

    OTA_INFO("Total number of key-value pairs in node %s: %d\n", node, count);

    fclose(file);
}

int compare_versions(char *current_version, char *upgrade_version) {
    if (strcmp(upgrade_version, current_version) > 0) {
        return 1; // 需要升级
    } else {
        return 0; // 不需要升级
    }
}
#if 1
void * download(void * socket_d)
{
    /*下载文件函数, 放在线程中执行*/
    int client_socket = *(int *) socket_d;
    int length = 0;
    int mem_size = 4096;//mem_size might be enlarge, so reset it
    int buf_len = mem_size;//read 4k each time
    int len;
	char ver_str[64]={0};
	char tmpVer[64]={0};

	char ota_str[64]={0};
	char md5_get[32]={0};

    char *buf = (char *) malloc(mem_size * sizeof(char));
	if (buf != NULL)
	{
	    // 内存分配成功
	}
	else
	{
	    OTA_ERR("Error allocating memory\n");
	    pthread_exit(NULL);
	}

	if ((len = read(client_socket, buf, 64)) != 0)
	{
		if (len < 0) {
	        OTA_ERR("Error reading from socket\n");
	        free(buf);
	        pthread_exit(NULL);
	    } else if (len < 64) {
	        OTA_ERR("Incomplete data read\n");
	        free(buf);
	        pthread_exit(NULL);
	    }
		memcpy(ota_str,buf,64);
		ota_str[63]='\0';
		OTA_INFO("!!!ota_str%s\n",ota_str);
		
		memcpy(ver_str,ota_str+3,7);
		OTA_INFO("ver_str is %s\n",ver_str);
		
		GetDevVer(tmpVer);
		OTA_INFO("tmpVer is %s\n",tmpVer);
		
		if (compare_versions(tmpVer, ver_str)) {
			OTA_INFO("需要升级从 %s到版本 %s\n", tmpVer, ver_str);

		} else {
			if (strcmp(ver_str, "0.0.0.0") == 0){
				OTA_ERR("版本%s 强制升级\n",ver_str);
			}else{
				OTA_ERR("当前版本已是最新\n");
				free(buf);
				OTA_INFO("!!!reboot\n");
				//system("reboot");	
				//execl("/sbin/reboot", "reboot", NULL);
				pthread_exit(NULL);
			}
		}

		//SetDevVer(ver_str);
		memset(md5_get, 0, sizeof(md5_get));
		memcpy(md5_get,ota_str+10,32);

		OTA_INFO("%s\n", md5_get);			

        //write(fd, buf, len);
        //progressBar(length, resp.content_length);
    }
	memset(buf,0,4096);
	resp.content_length -= 64;

	//创建文件描述符
    int fd = open("upgrade.tar.lzma", O_CREAT | O_WRONLY, S_IRWXG | S_IRWXO | S_IRWXU);
    if (fd < 0)
    {
        OTA_ERR("Create file failed\n");
		pthread_exit(NULL);
    }
    //从套接字中读取文件流
    while ((len = read(client_socket, buf, buf_len)) != 0 && length < resp.content_length)
	{
		if (len != -1)
		{
			write(fd, buf, len);
			length += len;
			memset(buf,0,4096);
			progressBar(length, resp.content_length);
		}
		else
		{
		    OTA_ERR("Error reading data from socket\n");
		    // 可以根据具体情况采取适当的处理措施
		}
    }
 	free(buf);
	
    if (length == resp.content_length)
        OTA_ERR("Download successful length %dresp.content_length%d^_^\n\n",length,resp.content_length);
#if 1	
	int ret;
	const char *file_upgrade = "upgrade.tar.lzma";
	char md5_str[MD5_STR_LEN + 1];
 
	ret = Compute_file_md5(file_upgrade, md5_str);
	if (0 == ret)
	{
		OTA_INFO("[file - %s] md5 value:\n", file_upgrade);
		OTA_INFO("%s\n", md5_str);
	}
	else
	{
	    OTA_ERR("Error computing file MD5\n");
	    // 可以根据具体情况采取适当的处理措施
	}
	
	if (strncasecmp(md5_get, md5_str, 32) == 0)
	{
		OTA_INFO("md5_str is fuhe\n");
	}else{
		OTA_ERR("md5_str is bufuhe\n");

	}
	
	char SnOut[64]={0,0,0,0};
	ret = readStringValue("ipc", "sn", SnOut, "/root/app.ini");
	if (ret == 1)
	{
	    // 读取配置值成功
	}
	else
	{
	    OTA_ERR("Error reading configuration value\n");
	    // 可以根据具体情况采取适当的处理措施
	}
	OTA_INFO("%c %c %c %c\n",SnOut[3] , ota_str[42],SnOut[4] , ota_str[43]);
	if(SnOut[3] == ota_str[42]&&SnOut[4] == ota_str[43]){
		OTA_INFO("SN fuhe!!!!!!\n");
	}else{
		OTA_ERR("SN bufuhe!!!!!!\n");
		//execl("/sbin/reboot", "reboot", NULL);
		pthread_exit(NULL);
	}
	
	system("rm upgrade.tar");

	system("lzma -d upgrade.tar.lzma");
	system("./busybox tar xvf upgrade.tar -C /tmp");
	
	read_ini_node("/tmp/ota.ini", "file");

	
	ret = readStringValue("ota", "sv", ver_str, "/tmp/ota.ini");
	if (ret == 1)
	{
	    // 读取配置值成功
	}
	else
	{
	    OTA_ERR("Error reading configuration value\n");
	    // 可以根据具体情况采取适当的处理措施
	}

	SetDevVer(ver_str);
	OTA_ERR("!!!reboot\n");
	//execl("/sbin/reboot", "reboot", NULL);
	pthread_exit(NULL);
#endif
}
#endif
#include <dirent.h>

size_t getTotalFileSize(const char* directory) {
    size_t totalSize = 0;
    DIR* dir;
    struct dirent* entry;
    struct stat st;
    char path[256];

    dir = opendir(directory);
    if (dir == NULL) {
        fprintf(stderr, "Error: Cannot open directory\n");
        return 0;
    }

    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        sprintf(path, "%s/%s", directory, entry->d_name);

        if (stat(path, &st) == 0) {
            totalSize += st.st_size;
        }
    }

    closedir(dir);

    return totalSize;
}
#include <sys/sysinfo.h>
#include <sys/statvfs.h>

long getAvailableSpace()
{
    struct statvfs buf;
    if (statvfs("/root", &buf) == 0)
    {
        long available_space = buf.f_bsize * buf.f_bavail;
		
		OTA_ERR("available_space %ld\n",available_space);
        return available_space;
    }
    return -1; // 获取失败
}
//void curllink()
//{
//    CURL *curl;
//CURLcode res;
//curl = curl_easy_init();
//if(curl) {
//  curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "GET");
//  curl_easy_setopt(curl, CURLOPT_URL, "https://application.daguiot.com/ota/error?version=1.0.0.1&msg=%22%22");
//  curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
//  curl_easy_setopt(curl, CURLOPT_DEFAULT_PROTOCOL, "https");
//  struct curl_slist *headers = NULL;
//  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
//  res = curl_easy_perform(curl);
//}
//curl_easy_cleanup(curl);
//}
void * parseAndextract(void * arg)
{
    /*下载文件函数, 放在线程中执行*/
    int length = 0;
    int mem_size = 4096;//mem_size might be enlarge, so reset it
    int buf_len = mem_size;//read 4k each time
    int len;
	char ver_str[64]={0};
	char tmpVer[64]={0};

	char ota_str[64]={0};
	char md5_get[32]={0};

    int ota_fd = open("/tmp/upgrade.img", O_RDONLY);
    if (ota_fd < 0) {
        OTA_ERR("Error opening upgrade.img file\n");
        pthread_exit(NULL);
    }

    char *buf = (char *) malloc(mem_size * sizeof(char));
	if (buf != NULL)
	{
	    // 内存分配成功
	}
	else
	{
	    OTA_ERR("Error allocating memory\n");
		close(ota_fd);
	    pthread_exit(NULL);
	}

	if ((len = read(ota_fd, buf, 64)) != 0)
	{
		if (len < 0) {
	        OTA_ERR("Error reading from socket\n");
	        free(buf);
			close(ota_fd);
	        pthread_exit(NULL);
	    } else if (len < 64) {
	        OTA_ERR("Incomplete data read\n");
	        free(buf);
			close(ota_fd);
	        pthread_exit(NULL);
	    }
		memcpy(ota_str,buf,64);
		ota_str[63]='\0';
		OTA_INFO("!!!ota_str%s\n",ota_str);
		
		memcpy(ver_str,ota_str+3,7);
		OTA_INFO("ver_str is %s\n",ver_str);
		
		GetDevVer(tmpVer);
		OTA_INFO("tmpVer is %s\n",tmpVer);
		
		if (compare_versions(tmpVer, ver_str)) {
			OTA_INFO("需要升级从 %s到版本 %s\n", tmpVer, ver_str);

		} else {
			if (strcmp(ver_str, "0.0.0.0") == 0){
				OTA_ERR("版本%s 强制升级\n",ver_str);
			}else{
				OTA_ERR("当前版本已是最新\n");
				free(buf);
				close(ota_fd);
				OTA_INFO("!!!reboot\n");
				//system("reboot");	
				//execl("/sbin/reboot", "reboot", NULL);
				pthread_exit(NULL);
			}
		}

		//SetDevVer(ver_str);
		memset(md5_get, 0, sizeof(md5_get));
		memcpy(md5_get,ota_str+10,32);

		OTA_INFO("%s\n \n", md5_get);			

        //write(fd, buf, len);
        //progressBar(length, resp.content_length);
    }
	memset(buf,0,4096);
	resp.content_length -= 64;

	//创建文件描述符
    int fd = open("/tmp/upgrade.tar.lzma", O_CREAT | O_WRONLY, S_IRWXG | S_IRWXO | S_IRWXU);
    if (fd < 0)
    {
        OTA_ERR("Create file failed\n");
		pthread_exit(NULL);
    }
    //从套接字中读取文件流
    // while ((len = read(ota_fd, buf, buf_len)) != 0 && length < resp.content_length)
   
    while ((len = read(ota_fd, buf, buf_len)) != 0)
	{
		if (len != -1)
		{
			write(fd, buf, len);
			length += len;
			memset(buf,0,4096);
			//progressBar(length, resp.content_length);
		}
		else
		{
		    OTA_ERR("Error reading data from socket\n");
		    // 可以根据具体情况采取适当的处理措施
		}
    }
	system("cp /tmp/upgrade.tar.lzma /media/mmcblk0/");
 	free(buf);
	
#if 1
	int ret;
	const char *file_upgrade = "/tmp/upgrade.tar.lzma";
	char md5_str[MD5_STR_LEN + 1];
 
	ret = Compute_file_md5(file_upgrade, md5_str);
	if (0 == ret)
	{
		OTA_INFO("[file - %s] md5 value:\n", file_upgrade);
		OTA_INFO("%s\n", md5_str);
	}
	else
	{
	    OTA_ERR("Error computing file MD5\n");
	    // 可以根据具体情况采取适当的处理措施
	}
	
	if (strncasecmp(md5_get, md5_str, 32) == 0)
	{
		OTA_INFO("md5_str is fuhe\n");
	}else{
		OTA_ERR("md5_str is bufuhe\n");

	}
	
	char SnOut[64]={0,0,0,0};
	ret = readStringValue("ipc", "sn", SnOut, "/root/app.ini");
	if (ret == 1)
	{
	    // 读取配置值成功
	}
	else
	{
	    OTA_ERR("Error reading configuration value\n");
	    // 可以根据具体情况采取适当的处理措施
	}
	OTA_INFO("%c %c %c %c\n",SnOut[3] , ota_str[42],SnOut[4] , ota_str[43]);
	if(SnOut[3] == ota_str[42]&&SnOut[4] == ota_str[43]){
		OTA_INFO("SN fuhe!!!!!!\n");
	}else{
		OTA_ERR("SN bufuhe!!!!!!\n");
		//execl("/sbin/reboot", "reboot", NULL);
		pthread_exit(NULL);
	}
	
	system("rm /tmp/upgrade.tar");

	system("lzma -d /tmp/upgrade.tar.lzma");
	
	//system("mkdir /tmp/ota");
	system("mkdir /tmp/ota && ./busybox tar xvf /tmp/upgrade.tar -C /tmp/ota");
	const char* directory = "/tmp/ota"; // 存放解压文件的目录

    size_t totalSize = getTotalFileSize(directory);

	long flash_space = getAvailableSpace();

	//if (flash_space < totalSize)
	
	if (1)
	{
	
//https://application.daguiot.com/ota/error?version=1.0.0.1&msg=""
		char *ip = "application.daguiot.com";
		char *path ="/ota/error?version=1.0.0.1&msg=\"\"";
	    OTA_ERR("Flash空间不足flash_space %ldK Totalfilesize:%zuk bytes\n",flash_space/1024,totalSize/1024);
//        mylink();
        myconnect();
//		if ((fd = https_postServer(ip, path, 3000)) <= 0)
//	    {
//	        printf("connect failed !!\r\n");
//	        return -1;
//	    }
	}else{
		
		OTA_ERR("Flash空间充足flash_space %ldK Totalfilesize:%zuk bytes\n",flash_space/1024,totalSize/1024);
	}
	
	read_ini_node("/tmp/ota/ota.ini", "file");

	
	ret = readStringValue("ota", "sv", ver_str, "/tmp/ota/ota.ini");
	if (ret == 1)
	{
	    // 读取配置值成功
	}
	else
	{
	    OTA_ERR("Error reading configuration value\n");
	    // 可以根据具体情况采取适当的处理措施
	}

	//SetDevVer(ver_str);
	OTA_ERR("!!!reboot\n");
	//execl("/sbin/reboot", "reboot", NULL);
	pthread_exit(NULL);
#endif
}

int upgrade_from_card3(char *path)
{
	if(access(path, F_OK ) != -1 ) 
	{
		OTA_INFO("!!!file exist,%s\n",path);
		
		struct stat statbuf; 
		stat(path,&statbuf); 
		int size=statbuf.st_size;
		OTA_INFO("size %d\n",size);

		int length = 0;
		int mem_size = 4096;//mem_size might be enlarge, so reset it
		int buf_len = mem_size;//read 4k each time
		int len;
		char ver_str[64]={0};
		char tmpVer[64]={0};

		char ota_str[64];
		char md5_get[32];

		//创建文件描述符
		int fd = open("upgrade.tar.lzma", O_CREAT | O_WRONLY, S_IRWXG | S_IRWXO | S_IRWXU);
		if (fd < 0)
		{
			OTA_ERR("Create file failed\n");
			return -1;
		}

		char *buf = (char *) malloc(mem_size * sizeof(char));
		if (buf != NULL)
		{
		    // 内存分配成功
		}
		else
		{
		    OTA_ERR("Error allocating memory\n");
		    return -1;
		}

		int card_fd = open(path, O_RDONLY);
		if (card_fd < 0)
		{
			OTA_ERR("Create fd failed\n");
			free(buf);
			return -1;
		}
		
		if ((read(card_fd, buf, 64)) != 0)
		{
				memcpy(ota_str,buf,64);
				ota_str[63]='\0';
				OTA_INFO("!!!ota_str%s\n",ota_str);
				
				memcpy(ver_str,ota_str+3,7);
				OTA_INFO("ver_str is %s\n",ver_str);
				
				GetDevVer(tmpVer);
				OTA_INFO("tmpVer is %s\n",tmpVer);
				
				if (compare_versions(tmpVer, ver_str)) {
					OTA_INFO("需要升级从 %s到版本 %s\n", tmpVer, ver_str);

				} else {
					if (strcmp(ver_str, "0.0.0.0") == 0){
						OTA_ERR("版本%s 强制升级\n",ver_str);
					}else{
						OTA_ERR("当前版本已是最新\n");
						free(buf);
						close(fd);						
						close(card_fd);
						OTA_ERR("!!!reboot\n");
						//execl("/sbin/reboot", "reboot", NULL);
						return -1;
					}
				}

				//SetDevVer(ver_str);
				
				memcpy(md5_get,ota_str+10,32);
				OTA_INFO("%s\n", md5_get);		

		}
		memset(buf,0,sizeof(buf));
		//OTA_INFO("!!!sizeof(buf)%d\n",mem_size * sizeof(char));
		size -= 64;
		//从套接字中读取文件流
		while ((len = read(card_fd, buf, buf_len)) != 0 && length < size)
		{
			if (len != -1)
			{
				write(fd, buf, len);
				length += len;
				progressBar(length, size);
			}
			else
			{
			    OTA_ERR("Error reading data from socket\n");
			    // 可以根据具体情况采取适当的处理措施
			}
		}

		if (length == size)
			OTA_INFO("split successful length %d  size%d^_^\n\n",length,size);
#if 1	
		int ret;
		const char *file_upgrade = "upgrade.tar.lzma";
		char md5_str[MD5_STR_LEN + 1];

		ret = Compute_file_md5(file_upgrade, md5_str);
		if (0 == ret)
		{
			OTA_INFO("[file - %s] md5 value:\n", file_upgrade);
			OTA_INFO("%s\n", md5_str);
		}
		else
		{
		    OTA_ERR("Error computing file MD5\n");
		    // 可以根据具体情况采取适当的处理措施
		}

		if (strncasecmp(md5_get, md5_str, 32) == 0)
		{
			OTA_INFO("md5_str is fuhe\n");
		}else{
			OTA_ERR("md5_str is bufuhe\n");			
			//execl("/sbin/reboot", "reboot", NULL);			
			return -1;

		}

		char SnOut[64]={0,0,0,0};
		ret = readStringValue("ipc", "sn", SnOut, "/root/app.ini");
		if (ret == 1)
		{
		    // 读取配置值成功
		}
		else
		{
		    OTA_ERR("Error reading configuration value\n");
		    // 可以根据具体情况采取适当的处理措施
		}
		OTA_INFO("%c %c %c %c\n",SnOut[3] , ota_str[42],SnOut[4] , ota_str[43]);
		if(SnOut[3] == ota_str[42]&&SnOut[4] == ota_str[43]){
			OTA_INFO("SN fuhe!!!!!!\n");
		}else{
			OTA_ERR("SN bufuhe!!!!!!\n");
			//execl("/sbin/reboot", "reboot", NULL);
			return -1;
		}

		system("rm upgrade.tar");

		system("lzma -d upgrade.tar.lzma");
		system("./busybox tar xvf upgrade.tar");

		char file_path[64];
		ret = readStringValue("file", "extest", file_path, "./ota.ini");
		if (ret == 1)
		{
		    // 读取配置值成功
		}
		else
		{
		    OTA_ERR("Error reading configuration value\n");
		    // 可以根据具体情况采取适当的处理措施
		}
		OTA_INFO("!!!file_path%s\n",file_path);

		char extest[] = "extest";
		//char file_path[] = "/path/to/destination/file";

		char command[100];

		sprintf(command, "cp %s %s", extest, file_path);
		system(command);

		ret = readStringValue("file", "111", file_path, "./ota.ini");
		if (ret == 1)
		{
		    // 读取配置值成功
		}
		else
		{
		    OTA_ERR("Error reading configuration value\n");
		    // 可以根据具体情况采取适当的处理措施
		}
		OTA_INFO("!!!file_path%s\n",file_path);

		char eee[] = "111";
		//char file_path[] = "/path/to/destination/file";

		memset(command,0,100);
		sprintf(command, "cp %s %s", eee, file_path);

		system(command);

		ret = readStringValue("ota", "sv", ver_str, "./ota.ini");
		if (ret == 1)
		{
		    // 读取配置值成功
		}
		else
		{
		    OTA_ERR("Error reading configuration value\n");
		    // 可以根据具体情况采取适当的处理措施
		}

		SetDevVer(ver_str);
		OTA_INFO("!!!reboot\n");
		//execl("/sbin/reboot", "reboot", NULL);
		return -1;
#endif
	}else 
	{
		OTA_ERR("!!!file doesn't exist,exit\n");
		//exit(0);
		return -1;
	}

}


int upgrade_from_card2(char *path)
{
	if(access(path, F_OK ) != -1 ) 
	{
		OTA_INFO("!!!file exist,%s\n",path);
		char *buf = (char *) malloc(64 * sizeof(char));
		if (buf == NULL) {
			OTA_INFO("Memory allocation failed\n");
			exit(1);
		}
		
		struct stat statbuf; 
		stat(path,&statbuf); 
		int size=statbuf.st_size;
		OTA_INFO("size %d\n",size);
		int length=0;

		
		int fd = open(path, O_RDONLY);
		if (fd < 0)
		{
			OTA_INFO("Create fd failed\n");
			free(buf);
			exit(1);
		}
		int len = read(fd, buf, 64);
		if (len < 0) {
			OTA_INFO("Read file failed\n");
			free(buf);
			close(fd);
			exit(1);
		}
			for (int i = 0; i < len; i++)
		   {
			   OTA_INFO("%c", buf[i]);
		   }
		   OTA_INFO(" \r\n");
		char ver_str[32];
		memcpy(ver_str,buf+3,7);
		ver_str[7] = '\0';
		OTA_INFO("ver_str is %s\n",ver_str);
		
		char tmpVer[64]={0};
		GetDevVer(tmpVer);
		OTA_INFO("tmpVer is %s\n",tmpVer);
		if (compare_versions(tmpVer, ver_str)) {
			OTA_INFO("需要升级到版本 %s\n", ver_str);
			
			int split_fd = open("upgrade.tar.lzma", O_CREAT | O_WRONLY, S_IRWXG | S_IRWXO | S_IRWXU);
			if (split_fd < 0)
			{
				OTA_INFO("Create file failed\n");
				exit(0);
			}
			while ((len = read(fd, buf, 4096)) != 0 && length < size)
			{

				write(split_fd, buf, len);
				length += len;
			}
			free(buf);
			close(fd);
			
			OTA_INFO("!!!length%d\n",length);

			system("rm upgrade.tar");

			system("lzma -d upgrade.tar.lzma");
			system("busybox tar xvf upgrade.tar -C /tmp");
							
							char file_path[64]={0,0,0,0};
	//readStringValue("file", "extest", file_path, "./ota.ini");
	GetOtaApp(file_path);
	OTA_INFO("!!!file_path%s\n",file_path);
			OTA_INFO("11111111111\n");

			char command[100];
			//char file_path[64]={0};

			memset(file_path, 0, sizeof(64));
			
			readStringValue("file", "extest", file_path, "/tmp/ota.ini");
						sleep(2);
			OTA_INFO("22222222222\n");
			OTA_INFO("!!!file_path%s\n",file_path);
			
			char extest[] = "extest";
			//char file_path[] = "/path/to/destination/file";


			sprintf(command, "cp %s %s", extest, file_path);
			system(command);

			readStringValue("file", "111", file_path, "/tmp/ota.ini");
			OTA_INFO("!!!file_path%s\n",file_path);

			char eee[] = "111";
			//char file_path[] = "/path/to/destination/file";

			memset(command,0,100);
			sprintf(command, "cp %s %s", eee, file_path);

			system(command);
			SetDevVer(ver_str);
			OTA_INFO("!!!reboot\n");
			//execl("/sbin/reboot", "reboot", NULL);
			exit("0");

			return 1;
		} else {
			OTA_INFO("当前版本已是最新\n");
			free(buf);
			close(fd);
			return 0;
		}
		/*char upgrade_str[64];
		memcpy(upgrade_str,buf,64);
		upgrade_str[63]='\0';
		OTA_INFO("!!!upgrade_str%s\n",upgrade_str);*/
	} 
	else 
	{
		OTA_INFO("!!!file doesn't exist,exit\n");
		exit(0);
	}
}

int upgrade_from_card(char *path)
{
	if(access(path, F_OK ) != -1 ) 
	{
		OTA_INFO("!!!file exist,%s\n",path);
		
		struct stat statbuf; 
		stat(path,&statbuf); 
		int size=statbuf.st_size;
		OTA_INFO("size %d\n",size);

		int length = 0;
		int mem_size = 4096;//mem_size might be enlarge, so reset it
		int buf_len = mem_size;//read 4k each time
		int len;
		char ver_str[64]={0};
		char tmpVer[64]={0};

		char ota_str[64];
		char md5_get[32];

		//创建文件描述符
		int fd = open("upgrade.tar.lzma", O_CREAT | O_WRONLY, S_IRWXG | S_IRWXO | S_IRWXU);
		if (fd < 0)
		{
			OTA_ERR("Create file failed\n");
			return -1;
		}

		char *buf = (char *) malloc(mem_size * sizeof(char));
		if (buf != NULL)
		{
		    // 内存分配成功
		}
		else
		{
		    OTA_ERR("Error allocating memory\n");
		    return -1;
		}

		int card_fd = open(path, O_RDONLY);
		if (card_fd < 0)
		{
			OTA_ERR("Create fd failed\n");
			free(buf);
			return -1;
		}
		
		if ((read(card_fd, buf, 64)) != 0)
		{
				memcpy(ota_str,buf,64);
				ota_str[63]='\0';
				OTA_INFO("!!!ota_str%s\n",ota_str);
				
				memcpy(ver_str,ota_str+3,7);
				OTA_INFO("ver_str is %s\n",ver_str);
				
				GetDevVer(tmpVer);
				OTA_INFO("tmpVer is %s\n",tmpVer);
				
				if (compare_versions(tmpVer, ver_str)) {
					OTA_INFO("需要升级从 %s到版本 %s\n", tmpVer, ver_str);

				} else {
					if (strcmp(ver_str, "0.0.0.0") == 0){
						OTA_ERR("版本%s 强制升级\n",ver_str);
					}else{
						OTA_ERR("当前版本已是最新\n");
						free(buf);
						close(fd);						
						close(card_fd);
						OTA_ERR("!!!reboot\n");
						//execl("/sbin/reboot", "reboot", NULL);
						return -1;
					}
				}

				//SetDevVer(ver_str);
				
				memcpy(md5_get,ota_str+10,32);
				OTA_INFO("%s\n", md5_get);		

		}
		memset(buf,0,sizeof(buf));
		//OTA_INFO("!!!sizeof(buf)%d\n",mem_size * sizeof(char));
		size -= 64;
		//从套接字中读取文件流
		while ((len = read(card_fd, buf, buf_len)) != 0 && length < size)
		{
			if (len != -1)
			{
				write(fd, buf, len);
				length += len;
				progressBar(length, size);
			}
			else
			{
			    OTA_ERR("Error reading data from socket\n");
			    // 可以根据具体情况采取适当的处理措施
			}
		}

		if (length == size)
			OTA_INFO("split successful length %d  size%d^_^\n\n",length,size);
#if 1	
		int ret;
		const char *file_upgrade = "upgrade.tar.lzma";
		char md5_str[MD5_STR_LEN + 1];

		ret = Compute_file_md5(file_upgrade, md5_str);
		if (0 == ret)
		{
			OTA_INFO("[file - %s] md5 value:\n", file_upgrade);
			OTA_INFO("%s\n", md5_str);
		}
		else
		{
		    OTA_ERR("Error computing file MD5\n");
		    // 可以根据具体情况采取适当的处理措施
		}

		if (strncasecmp(md5_get, md5_str, 32) == 0)
		{
			OTA_INFO("md5_str is fuhe\n");
		}else{
			OTA_ERR("md5_str is bufuhe\n");			
			//execl("/sbin/reboot", "reboot", NULL);			
			return -1;

		}

		char SnOut[64]={0,0,0,0};
		ret = readStringValue("ipc", "sn", SnOut, "/root/app.ini");
		if (ret == 1)
		{
		    // 读取配置值成功
		}
		else
		{
		    OTA_ERR("Error reading configuration value\n");
		    // 可以根据具体情况采取适当的处理措施
		}
		OTA_INFO("%c %c %c %c\n",SnOut[3] , ota_str[42],SnOut[4] , ota_str[43]);
		if(SnOut[3] == ota_str[42]&&SnOut[4] == ota_str[43]){
			OTA_INFO("SN fuhe!!!!!!\n");
		}else{
			OTA_ERR("SN bufuhe!!!!!!\n");
			//execl("/sbin/reboot", "reboot", NULL);
			return -1;
		}

		system("rm upgrade.tar");

		system("lzma -d upgrade.tar.lzma");
		system("./busybox tar xvf upgrade.tar");

		read_ini_node("ota.ini", "file");

		ret = readStringValue("ota", "sv", ver_str, "./ota.ini");
		if (ret == 1)
		{
		    // 读取配置值成功
		}
		else
		{
		    OTA_ERR("Error reading configuration value\n");
		    // 可以根据具体情况采取适当的处理措施
		}

		SetDevVer(ver_str);
		OTA_INFO("!!!reboot\n");
		//execl("/sbin/reboot", "reboot", NULL);
		return -1;
#endif
	}else 
	{
		OTA_ERR("!!!file doesn't exist,exit\n");
		//exit(0);
		return -1;
	}

}

int KillProcessByName(char *processName) 
{
    FILE *fp;
    char buf[BUFFER_SIZE];
	
    char cmd[BUFFER_SIZE] = { 0 };
	sprintf(cmd, "ps aux | grep %s | grep -v grep | awk '{print $1}'", processName);
    // 使用popen调用ps命令获取进程信息
    //fp = popen("ps aux | grep cat | grep -v grep | awk '{print $1}'", "r");
	
    fp = popen(cmd, "r");
    if (fp == NULL) {
        fprintf(stderr, "Error opening pipe!\n");
        return -1;
    }
    // 逐行读取进程ID并杀死进程
    while (fgets(buf, sizeof(buf), fp) != NULL) {
		
		OTA_INFO(" processName %s pid: %s\n",processName, buf);
        int pid = atoi(buf);
        if (pid > 0) {
            //OTA_INFO("Killing process with PID: %d\n", pid);
            kill(pid, SIGKILL);
        }
    }

    pclose(fp);

    return 0;
}

int get4GSerialOutput(const char *strCmd, char *buffer) 
{
    char cmd[BUFFER_SIZE];
    sprintf(cmd, "%s && cat /dev/ttyUSB2", strCmd);
    
    //sprintf(cmd, "cat /dev/ttyUSB2 & %s;",strCmd);
    FILE *fp;
    char buf[BUFFER_SIZE];
    char tempBuf[BUFFER_SIZE] = "";
	unsigned int msgLine = 0;

    fp = popen(cmd, "r");
    if (fp == NULL) {
        fprintf(stderr, "Error opening pipe!\n");
        return -1;
    } else {
         //OTA_INFO("strCmd %s success\n", strCmd);
    }

    int fd = fileno(fp);
	
    fd_set readfds;
    struct timeval timeout;
    FD_ZERO(&readfds);
    FD_SET(fd, &readfds);

    timeout.tv_sec = TIMEOUT_SEC;
    timeout.tv_usec = 0;
	//system(strCmd);

	
    while (1) {
		int ret = select(fd + 1, &readfds, NULL, NULL, &timeout);
	    if (ret == -1) {
	        perror("select failed");
	        KillProcessByName("cat");
	        pclose(fp);
	        return -2;
	    } else if (ret == 0) {
			if(msgLine > 1){
				
				OTA_INFO("msg: %s \n",tempBuf);
				memcpy(buffer,tempBuf,BUFFER_SIZE);
			
				OTA_INFO("msgbuffer: %s \n",buffer);
				KillProcessByName("cat");
		        pclose(fp);				
				return 0;
			}else{				
				OTA_INFO("Timeout occurred strCmd %s\n", strCmd);
		        KillProcessByName("cat");
		        pclose(fp);
		        return -2;
			}
	    }else{
			if (fgets(buf, sizeof(buf), fp) != NULL) {
				if (strlen(buf) > 1) {
					msgLine++;
					OTA_INFO("Received data: msgLine:%d len:%d%s,%d\n",msgLine, strlen(buf),buf);
					strcat(tempBuf, buf);
					tempBuf[255]='\0';
					//OTA_INFO("tempBuf %s \n",tempBuf);

				}
			}
		}
		
        //usleep(10000);
    }
}
int Get4GOutputBySaveFile(const char *strCmd, char *buffer) 
{
    char cmd[BUFFER_SIZE];
    //sprintf(cmd, "%s && cat /dev/ttyUSB2", strCmd);
    
    //sprintf(cmd, "cat /dev/ttyUSB2 > ATOutput.txt &",strCmd);
    FILE *fp;
    char buf[BUFFER_SIZE];
    char tempBuf[BUFFER_SIZE] = "";
	unsigned int msgLine = 0;


	
	system("cat /dev/ttyUSB2 > ATOutput.txt &");
	system(strCmd);
	OTA_INFO("strCmd %s success\n", strCmd);
	
	fp = fopen("ATOutput.txt" , "r");
	if(fp == NULL) {
	   perror("打开文件时发生错误");
	   return(-1);
	}
    while (fgets(buf, sizeof(buf), fp) != NULL) {
        if (strlen(buf) > 1) {
            msgLine++;
            OTA_INFO("output_fd data: msgLine:%d len:%d%s,%d\n", msgLine, (int)strlen(buf), buf);
			strcat(tempBuf, buf);
			tempBuf[255]='\0';
			
            //if (msgLine >= 5) {
            //    break; // 限制读取的行数
            //}
        }
    }
	
	if(msgLine > 1){
				
		//OTA_ERR("msg: %s \n",tempBuf);
		memcpy(buffer,tempBuf,BUFFER_SIZE);
	
		OTA_INFO("msgbuffer: %s \n",buffer);
		KillProcessByName("cat");
        pclose(fp);				
		return 0;
	}else{				
		OTA_INFO("Timeout occurred strCmd %s\n", strCmd);
        KillProcessByName("cat");
        pclose(fp);
        return -1;
	}


}


void myprint(const char *format, int timestamp) {
    OTA_INFO(format, timestamp);
    OTA_INFO("\n");
}

void executeCmd(const char *cmd) {
    system(cmd);
}
int getATOutput(const char *strCmd, char *buffer) 
{
	
	int ret;
	int getCNT = 10;
	while(getCNT--){
		
    	char buf[BUFFER_SIZE] = {0};
		ret = Get4GOutputBySaveFile(strCmd,buf);
		if(!ret){
			
			OTA_INFO("strCmd %s \n buf %s\n buffer is %s\n", strCmd, buf,buffer);
			if (strstr(buf, buffer)) {
				strcpy(buffer, buf);
				OTA_INFO("strCmd %s buffer is %s\n", strCmd, buffer);
				return 0;
			} else if (strstr(buf, "OK")){
				
				OTA_INFO("OK\n");
			} else if (strstr(buf, "ERROR")){
				
				OTA_INFO("ERROR\n");
			}
			
			//return -1;

		}else{
			OTA_INFO("cant get ATOutput, try again\n");	
		}
	}
	OTA_INFO("cant get ATOutput, please try again\n");
}

int getTime() {
    // 获取时间 +CCLK: "24/01/09,07:41:32+32"
    time_t timestamp = 0; // UTC: 2024-01-01 00:00:00
    char buffer[1000] = {0};
    getATOutput("echo -e 'AT+CCLK?\r\n' > /dev/ttyUSB2", buffer);
    // Assuming getATOutput function is responsible for populating buffer with AT command output
    //char *strSrc = "+CCLK: \"24/01/09,07:41:32+32\"";
	
    char *strSrc = buffer;
    OTA_INFO("getTime: %s\n", strSrc);
//    [OTA_INFO] getTime(2516): getTime: 
//    Segmentation fault

    int nposBegin = strchr(strSrc, '\"') - strSrc + 1;
    int nposEnd = strchr(strSrc + nposBegin, '\"') - strSrc;
    
    if (strlen(strSrc) != 0 && nposBegin != -1 && nposEnd != -1) {
        char strR[20];
        strncpy(strR, strSrc + nposBegin, nposEnd - nposBegin);
        strR[nposEnd - nposBegin] = '\0';

        char strYear[3], strMon[3], strDate[3], strHour[3], strMin[3], strSec[3];
        strncpy(strYear, strR, 2);
        strncpy(strMon, strR + 3, 2);
        strncpy(strDate, strR + 6, 2);
        strncpy(strHour, strR + 9, 2);
        strncpy(strMin, strR + 12, 2);
        strncpy(strSec, strR + 15, 2);

        struct tm timeinfo = {0};

        // 设置本地时间信息
        timeinfo.tm_year = atoi(strYear) + 100; // 年份加上 100，相当于 2000 年之后的年份
        timeinfo.tm_mon = atoi(strMon) - 1; // 月份从 0 开始，0 表示一月
        timeinfo.tm_mday = atoi(strDate); // 日期
        timeinfo.tm_hour = atoi(strHour); // 小时
        timeinfo.tm_min = atoi(strMin); // 分钟
        timeinfo.tm_sec = atoi(strSec); // 秒钟

        // 将本地时间转换为 UTC 时间
        timestamp = mktime(&timeinfo);
    }
    myprint("getTime: %d", timestamp);
    return timestamp;
}

void setTime(time_t nTime) {
    struct tm *t;
    time_t now;
    if (nTime == 0) {
        executeCmd("date -s \"2024-01-09 10:26\"");
        time(&now);
        t = localtime(&now);
    } else {
        now = nTime;
        t = localtime(&now);
    }
    char strTime[100];
    snprintf(strTime, 99, "date -s \"%d-%02d-%02d %02d:%02d:%02d\"", t->tm_year + 1900, t->tm_mon + 1, t->tm_mday,
             t->tm_hour, t->tm_min, t->tm_sec);
    executeCmd(strTime);
}

int mySetTimeFrom4G() {
    for (size_t i = 0; i < 10; i++) {
        time_t nTime = getTime();
        if (nTime != 0) {
            setTime(nTime);
            break;
        }
        usleep(200 * 1000);
    }
    return 0;
}



//date -s "2024-05-08 06:34"
//1.0.0.1876B885EA47289377C60E97B9C73EE6222

int main(int argc, char const *argv[])
{
    mySetTimeFrom4G();
	//downloadFileFromTianyiYun("iotoos29000240327/ota/3/123/upgrade.img", "/tmp/upgrade.img");
	//return 0;
    char url[2048] = "127.0.0.1";
    char domain[64] = {0};
    char ip_addr[16] = {0};
    int port = 80;
    char file_name[256] = {0};
 
    if (argc == 1)
    {
        OTA_INFO("Input a valid URL please\n");
        //exit(0);
    }
    else{
		if (strncasecmp((const char*)argv[1], "iotoos", 4) == 0)
		{
			downloadFileFromTianyiYun("iotoos29000240327/ota/1/upgrade.img", "/tmp/upgrade.img");
		}else{
			upgrade_from_card(argv[1]);
			OTA_INFO("reboot -- p\n");
			system("reboot -- p");
			return 0;
		}
	}
	
	downloadFileFromTianyiYun("iotoos29000240327/ota/1/upgrade.img", "/tmp/upgrade.img");
	//return 0;
	struct statvfs buf2;
    if (statvfs("/root", &buf2) == 0) {
        unsigned long block_size = buf2.f_frsize; // 文件系统块大小
        unsigned long available_blocks = buf2.f_bavail; // 可用块数量
        unsigned long available_space = block_size * available_blocks;
        
        OTA_INFO("可用空间大小：%luk bytes\n", available_space/1024);
    } else {
        OTA_INFO("无法获取/root分区信息\n");
    }
	struct sysinfo sys_info;

    // 获取系统信息
    if (sysinfo(&sys_info) != 0) {
        perror("sysinfo");
        return 1;
    }

    // 打印可用内存大小
    OTA_INFO("Total RAM: %lu KB\n", sys_info.totalram / 1024);
    OTA_INFO("Free RAM: %lu KB\n", sys_info.freeram / 1024);

    // 打印可用Flash大小
    OTA_INFO("Total Swap: %lu KB\n", sys_info.totalswap / 1024);
    OTA_INFO("Free Swap: %lu KB\n", sys_info.freeswap / 1024);
	


    /*开新的线程下载文件*/
    pthread_t parse_thread;
    pthread_create(&parse_thread, NULL, parseAndextract, (void *) 0);
    pthread_join(parse_thread, NULL);


	OTA_INFO("reboot -- p\n");
	//system("reboot -- p");
}

int main2(int argc, char const *argv[])
{
	//downloadFileFromTianyiYun("iotoos29000240327/ota/1/upgrade.img", "/tmp/upgrade.img");
	//return 0;
    char url[2048] = "127.0.0.1";
    char domain[64] = {0};
    char ip_addr[16] = {0};
    int port = 80;
    char file_name[256] = {0};
 
    if (argc == 1)
    {
        OTA_INFO("Input a valid URL please\n");
        exit(0);
    }else{
		if (strncasecmp((const char*)argv[1], "HTTP", 4) == 0)
		{
			strcpy(url, argv[1]);
		}else{
			upgrade_from_card(argv[1]);
			OTA_INFO("reboot -- p\n");
			system("reboot -- p");
			return 0;
		}
	}
    parse_url(url, domain, &port, file_name);
 
    /*if (argc == 3)
        strcpy(file_name, argv[2]);*/
 
    get_ip_addr(domain, ip_addr);
    if (strlen(ip_addr) == 0)
    {
        OTA_INFO("can not get ip address\n");
        return 0;
    }
	
    puts("\n>>>>Detail<<<<");
    //设置http请求头信息
    char header[2048] = {0};
    sprintf(header, \
            "GET %s HTTP/1.1\r\n"\
            "Accept:text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\n"\
            "User-Agent:Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537(KHTML, like Gecko) Chrome/47.0.2526Safari/537.36\r\n"\
            "Host:%s\r\n"\
            "Connection:close\r\n"\
            "\r\n"\
        ,url, domain);
  OTA_INFO("\n>>>>GET header:<<<<\n%s", header);
 
    //创建套接字
    int client_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (client_socket < 0)
    {
        OTA_INFO("invalid socket descriptor: %d\n", client_socket);
		OTA_INFO("reboot -- p\n");
		system("reboot -- p");
        exit(-1);
    }
 
    //创建地址结构体
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr(ip_addr);
    addr.sin_port = htons(port);
 
    //连接服务器
    int res = connect(client_socket, (struct sockaddr *) &addr, sizeof(addr));
    if (res == -1)
    {
        OTA_INFO("connect failed, return: %d\n", res);
        exit(-1);
    }
 
    write(client_socket, header, strlen(header));
    int mem_size = 4096;
    int length = 0;
    int len;
    char *buf = (char *) malloc(mem_size * sizeof(char));
    char *response = (char *) malloc(mem_size * sizeof(char));
	memset(response,0,4096);	
	memset(buf,0,4096);
 
    //每次单个字符读取响应头信息, 仅仅读取的是响应部分的头部, 后面单独开线程下载
    while ((len = read(client_socket, buf, 1)) != 0)
    {
        if (length + len > mem_size)
        {
            //动态内存申请, 因为无法确定响应头内容长度
            mem_size *= 2;
            char * temp = (char *) realloc(response, sizeof(char) * mem_size);
            if (temp == NULL)
            {
                OTA_INFO("realloc failed\n");
                exit(-1);
            }
            response = temp;
        }
 
        buf[len] = '\0';
        strcat(response, buf);
 
        //找到响应头的头部信息, 两个"\n\r"为分割点
        int flag = 0;
		int i=0;
        for (i = strlen(response) - 1; response[i] == '\n' || response[i] == '\r'; i--, flag++);
        if (flag == 4)
            break;
 
        length += len;
    }
 
    OTA_INFO("\n>>>>Response header:<<<<\n%s", response);
    resp = get_resp_header(response);
    strcpy(resp.file_name, file_name);
	
	struct statvfs buf2;
    if (statvfs("/root", &buf2) == 0) {
        unsigned long block_size = buf2.f_frsize; // 文件系统块大小
        unsigned long available_blocks = buf2.f_bavail; // 可用块数量
        unsigned long available_space = block_size * available_blocks;
        
        OTA_INFO("可用空间大小：%lu bytes\n", available_space);
    } else {
        OTA_INFO("无法获取/root分区信息\n");
    }
	struct sysinfo sys_info;

    // 获取系统信息
    if (sysinfo(&sys_info) != 0) {
        perror("sysinfo");
        return 1;
    }

    // 打印可用内存大小
    OTA_INFO("Total RAM: %lu KB\n", sys_info.totalram / 1024);
    OTA_INFO("Free RAM: %lu KB\n", sys_info.freeram / 1024);

    // 打印可用Flash大小
    OTA_INFO("Total Swap: %lu KB\n", sys_info.totalswap / 1024);
    OTA_INFO("Free Swap: %lu KB\n", sys_info.freeswap / 1024);
	



    /*开新的线程下载文件*/
    pthread_t download_thread;
    pthread_create(&download_thread, NULL, download, (void *) &client_socket);
    pthread_join(download_thread, NULL);

	free(response);
    free(buf);
	OTA_INFO("reboot -- p\n");
	system("reboot -- p");
}
