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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <wolfssl/ssl.h>


#define SERIAL_PORT "/dev/ttyUSB2"
#define BUFFER_SIZE 256

#define TIMEOUT_SEC 3

#define false   0
#define true    1
#define MY_BUF_SIZE 256

char timeString[9]; // 用于存储时间的字符串

char *current_time() {
    time_t current_time;
    struct tm * time_info;
//    char timeString[9]; // 用于存储时间的字符串

    time(&current_time);
    time_info = localtime(&current_time);

    strftime(timeString, sizeof(timeString), "%H:%M:%S", time_info);
    //OTA_INFO("当前时间是：%s\n", timeString);

    return timeString;
}

#define NONE_LEVEL 0
#define INFO_LEVEL 1
#define ERR_LEVEL  2
	
	
#define LOG_LEVEL 1//打印级别控制的宏定义
	
#if(LOG_LEVEL == NONE_LEVEL)
#define OTA_INFO(...)
#define OTA_ERR(...) 
#elif(LOG_LEVEL == INFO_LEVEL)
#define OTA_INFO(...) fprintf(stdout, "[OTA_INFO:%s] %s(%d): ", current_time(), __FUNCTION__, __LINE__),fprintf(stdout, __VA_ARGS__)
#define OTA_ERR(...) fprintf(stderr, "[OTA_INFO:%s] %s(%d): ", current_time(), __FUNCTION__, __LINE__),fprintf(stderr, __VA_ARGS__)
#elif(LOG_LEVEL == ERR_LEVEL)
#define OTA_INFO(...) 
#define OTA_ERR(...) fprintf(stderr, "[OTA_INFO:%s] %s(%d): ", current_time(), __FUNCTION__, __LINE__),fprintf(stderr, __VA_ARGS__)
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
#if 0
enum  ErrorCode2{
  kSuccess = 0,   //升级成功
  kError = 1,  //升级失败
  kOmahaRequestError = 2, //请求action错误（action机制用于控制升级每个步骤）
  kOmahaResponseHandlerError = 3,   //返回handler action错误
  kFilesystemCopierError = 4,  //文件系统拷贝错误
  kPostinstallRunnerError = 5,   //预编译运行步骤错误（PostinstallRunner是一个升级步骤）
  kPayloadMismatchedType = 6,    //NOT NEED
  kInstallDeviceOpenError = 7, //安装设备打开错误
  kKernelDeviceOpenError = 8, //内核设备打开错误
  kDownloadTransferError = 9, //下载传输错误
  kPayloadHashMismatchError = 10, //升级包hash未匹配错误
  kPayloadSizeMismatchError = 11,   //升级包size未匹配错误
  kDownloadPayloadVerificationError = 12, //下载过程升级包校验错误
  kDownloadNewPartitionInfoError = 13, //下载过程新分区信息错误
  kDownloadWriteError = 14,   //下载过程数据写入错误
  kNewRootfsVerificationError = 15, //升级分区hash校验失败
  kNewKernelVerificationError = 16, //升级kernel校验失败
  kSignedDeltaPayloadExpectedError = 17,  //NOT NEED
  kDownloadPayloadPubKeyVerificationError = 18, //下载过程升级包public key公钥校验错误
  kPostinstallBootedFromFirmwareB = 19,   //NOT NEED
  kDownloadStateInitializationError = 20, //下载状态初始化错误
  kDownloadInvalidMetadataMagicString = 21, //NOT NEED
  kDownloadSignatureMissingInManifest = 22,  //下载过程manifest缺少签名错误
  kDownloadManifestParseError = 23, //下载过程manifest分析错误
  kDownloadMetadataSignatureError = 24,   //下载过程元数据签名错误
  kDownloadMetadataSignatureVerificationError = 25,   //下载过程元数据签名校验错误
  kDownloadMetadataSignatureMismatch = 26,   //下载过程元数据签名不匹配错误
  kDownloadOperationHashVerificationError = 27, //下载过程操作hash校验错误
  kDownloadOperationExecutionError = 28,  //下载过程操作执行错误
  kDownloadOperationHashMismatch = 29, //下载过程操作hash不匹配错误
  kOmahaRequestEmptyResponseError = 30,   //请求action无返回错误
  kOmahaRequestXMLParseError = 31,  //请求action分析xml错误
  kDownloadInvalidMetadataSize = 32,   //下载过程非法元数据大小
  kDownloadInvalidMetadataSignature = 33, //下载过程非法元数据签名
  kOmahaResponseInvalid = 34, //返回action非法错误
  kOmahaUpdateIgnoredPerPolicy = 35,   //NOT NEED（含义是接收已回滚版本，忽略此次升级）
  kOmahaUpdateDeferredPerPolicy = 36,  //NOT NEED（含义是因更新策略延迟，忽略此次升级）
  kOmahaErrorInHTTPResponse = 37,   //HTTP返回错误
  kDownloadOperationHashMissingError = 38,   //下载过程操作时缺失hash错误
  kDownloadMetadataSignatureMissingError = 39,  //下载过程元数据签名缺失错误
  kOmahaUpdateDeferredForBackoff = 40,    //NOT NEED（含义是忽略本次升级）
  kPostinstallPowerwashError = 41,  //NOT NEED（回滚报错，该版本已去除版本回滚限制）
  kUpdateCanceledByChannelChange = 42, //通道变化升级取消
  kPostinstallFirmwareRONotUpdatable = 43, //NOT NEED(需要升级固件firmware时才会取消，因为无法从FW B分区启动到FW A分区)
  kUnsupportedMajorPayloadVersion = 44, //获取manifest偏移量错误
  kUnsupportedMinorPayloadVersion = 45,   //未manifest可支持更小版本错误
  kOmahaRequestXMLHasEntityDecl = 46, //请求action xml hash非法错误
  kFilesystemVerifierError = 47, //文件系统校验错误（FilesystemVerifier是一个升级步骤）
  kUserCanceled = 48, //用户取消
  kNonCriticalUpdateInOOBE = 49, //NOT NEED（Ignoring a non-critical Omaha update before OOBE completion.）
  kOmahaUpdateIgnoredOverCellular = 50,   //NOT NEED（未设置设备策略，因此用户首选项需要覆盖是否允许通过蜂窝网络进行更新）
  kPayloadTimestampError = 51, //升级包时间戳错误 （payload.bin是OTA镜像打包文件）
  kUpdatedButNotActive = 52,  //升级分区非action状态错误
  kNoUpdate = 53, //无升级（There are no updates. Aborting.）
  kRollbackNotPossible = 54,  //NOT NEED
  kFirstActiveOmahaPingSentPersistenceError = 55,  //NOT NEED（用于旧设备的Omaha校验）
  kVerityCalculationError = 56,  //校验计算错误（在FilesystemVerifier步骤中进行分区校验时）
};
#endif
enum  ErrorCode{
  kSuccess = 0,   //升级成功
  kError = 1,  //升级失败
  kPayloadMD5MismatchError = 2,  //
  kInsufficientFlashsizeError,  //flash空间不足
  kSNMismatchError, //
  kFileNotExitInTF,
};
#define PORT_NUMBER 443
#define HOST "application.daguiot.com"
#define MESSAGE2 "GET /ota/error?version=1.0.0.1&msg=%s HTTP/1.1\r\nHost: application.daguiot.com\r\nConnection: keep-alive\r\nAccept: */*\r\n\r\n"


int myconnect(int data) {
    int sockfd;
    struct sockaddr_in server_addr;
    struct hostent *server;
    WOLFSSL_CTX *ctx;
    WOLFSSL *ssl;
    char msg[256];

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
    
    //OTA_INFO("MESSAGE %s\n",MESSAGE);
    char buffer[512];
    bzero(buffer, 512);
    
	char MESSAGE[] = "GET /ota/error?version=1.0.0.1&msg=%d HTTP/1.1\r\nHost: application.daguiot.com\r\nConnection: keep-alive\r\nAccept: */*\r\n\r\n";
	sprintf(buffer, MESSAGE, data);
    OTA_INFO("%s\n",buffer);
    // 发送消息
    int n = wolfSSL_write(ssl, buffer, strlen(buffer));
    if (n < 0) {
        perror("Error writing to socket");
        wolfSSL_free(ssl);
        wolfSSL_CTX_free(ctx);
        close(sockfd);
        exit(1);
    }

    // 从服务器接收响应
    bzero(buffer, 512);
    while (wolfSSL_read(ssl, buffer, 511) > 0) {
        OTA_INFO("%s", buffer);
        bzero(buffer, 512);
        break;
    }

    // 发送消息
//    n = wolfSSL_write(ssl, &data, sizeof(int)); // 上传整数参数
//    if (n < 0) {
//        perror("Error writing to socket");
//        wolfSSL_free(ssl);
//        wolfSSL_CTX_free(ctx);
//        close(sockfd);
//        exit(1);
//    }

    // 关闭wolfSSL连接
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);

    // 关闭套接字
    close(sockfd);

    // wolfSSL清理
    wolfSSL_Cleanup();

    return 0;
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
            close(fd);
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
//#define MD5_DIGEST_LENGTH 16
//
//int ComputeFileMD52(const char *file_path, char *md5_str) {
//    int ret = 0;
//    int fd;
//    unsigned char md5_value[MD5_DIGEST_LENGTH];
//    MD5_CTX md5_ctx;
//    unsigned char buffer[1024];
//
//    fd = open(file_path, O_RDONLY);
//    if (fd == -1) {
//        perror("open");
//        return -1;
//    }
//
//    MD5_Init(&md5_ctx);
//
//    while (1) {
//        ssize_t bytes_read = read(fd, buffer, sizeof(buffer));
//        if (bytes_read == -1) {
//            perror("read");
//            ret = -1;
//            break;
//        }
//        if (bytes_read == 0) {
//            break;
//        }
//
//        MD5_Update(&md5_ctx, buffer, bytes_read);
//    }
//
//    close(fd);
//
//    if (ret != -1) {
//        MD5_Final(md5_value, &md5_ctx);
//
//        for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
//            sprintf(&md5_str[i*2], "%02x", (unsigned int)md5_value[i]);
//        }
//        md5_str[MD5_DIGEST_LENGTH * 2] = '\0'; //add null terminator
//    }
//
//    return ret;
//}

//#define CFGINI  "/root/app.ini"
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

//int  SetDevVer(const char* ver_in)
//{
//	writeStringVlaue("ipc", "ver", ver_in, CFGINI);
//}

int SetDevVer(const char* ver_in) {
    if (ver_in == NULL) {
        printf("Error: ver_in is NULL\n");
        return -1;
    }
    // 检查section、key是否正确初始化
    const char* section = "ipc";
    const char* key = "ver";
    if (section == NULL || key == NULL) {
        printf("Error: section or key is NULL\n");
        return -1;
    }
    // 调用SetDevVer函数
    writeStringVlaue(section, key, ver_in, CFGINI);
}

void read_ini_node(const char *filename, const char *node) {
    FILE *file = fopen(filename, "r");
    if (file == NULL) {
        OTA_INFO("Error opening file %s\n", filename);
        return;
    }

    char line[100];
    char command[200];
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

                    // Extract directory from value
                    char directory[100];
                    char *last_slash = strrchr(value, '/');
                    if (last_slash != NULL) {
                        int path_length = last_slash - value;
                        strncpy(directory, value, path_length);
                        directory[path_length] = '\0';

                        struct stat sb;
                        if (stat(directory, &sb) == 0 && S_ISREG(sb.st_mode)) {
                            // If directory exists as a file, remove it
                            if (remove(directory) != 0) {
                                OTA_INFO("Error removing file %s\n", directory);
                            }
                        }

                        // Check if directory exists
//                        if (stat(directory, &sb) != 0 || !S_ISDIR(sb.st_mode)) {
//                            // Directory does not exist, create it
//                            sprintf(command, "mkdir -p %s", directory);
//                            if (system(command) != 0) {
//                                OTA_INFO("Error creating directory %s\n", directory);
//                            }else
//                                
//                                OTA_INFO("Succe creating directory %s\n", directory);
//                        }
                        // Check if directory exists before creating
                        if (stat(directory, &sb) != 0 || !S_ISDIR(sb.st_mode)) {
                            // Directory does not exist, try creating directory
                            if (mkdir(directory, 0777) != 0) {
                                OTA_INFO("Error creating directory %s\n", directory);
                                //continue; // Skip further operations and continue with the next key-value pair
                            }
                        }



                        // Remove the file if it exists
                        if (access(value, F_OK) != -1) {
                            if (remove(value) != 0) {
                                OTA_INFO("Error removing file %s\n", value);
                                //continue; // Skip further operations and continue with the next key-value pair
                            }else
                        
                                OTA_INFO("Succe removing file %s\n", value);
                        }

                        // Copy the file
                        sprintf(command, "cp /tmp/ota/%s %s", key, value);
                        if (system(command) != 0) {
                            OTA_INFO("Error copying file %s to %s\n", key, value);
                        }else
                        
                            OTA_INFO("Succe copying file %s to %s\n", key, value);
                    } else {
                        OTA_INFO("Invalid file path: %s\n", value);
                    }
                }
            }
            break;
        }
    }

    OTA_INFO("Total number of key-value pairs in node %s: %d\n", node, count);

    fclose(file);
    
    OTA_INFO("fclose succe\n");
}

void read_ini_node2(const char *filename, const char *node) {
    FILE *file = fopen(filename, "r");
    if (file == NULL) {
        OTA_INFO("Error opening file\n");
        return;
    }

    char line[100];
    char command[200];
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

                    // Extract directory from value
                    char directory[100];
                    char *last_slash = strrchr(value, '/');
                    if (last_slash != NULL) {
                        int path_length = last_slash - value;
                        strncpy(directory, value, path_length);
                        directory[path_length] = '\0';

                        struct stat sb;
                        if (stat(directory, &sb) == 0 && S_ISREG(sb.st_mode)) {
                            // If directory exists as a file, remove it
                            remove(directory);
                        }

                        // Check if directory exists
                        if (stat(directory, &sb) != 0 || !S_ISDIR(sb.st_mode)) {
                            // Directory does not exist, create it
                            sprintf(command, "mkdir -p %s", directory);
                            system(command);
                        }
                        // rm the file
                        memset(command, 0,200);
                        sprintf(command, "rm %s", value);
                        system(command);

                        // Copy the file
                        sprintf(command, "cp /tmp/ota/%s %s", key, value);
                        system(command);
                    } else {
                        OTA_INFO("Invalid file path: %s\n", value);
                    }
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

	
	ret = readStringValue("ota", "sv", ver_str, "/tmp/ota/ota.ini");
	if (ret == 1)
	{
	    OTA_ERR("Succe reading configuration value\n");
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

// 定义结构体用于存储键值对
typedef struct {
    char key[50];
    char value[100];
} KeyValue;

// 定义函数用于解析INI文件
void parseIniFile(const char* filename, KeyValue* keyValueArray, int *count) {
    FILE* file = fopen(filename, "r");
    if (file == NULL) {
        OTA_INFO("can't open %s\n",filename);
        return;
    }

    char line[256];
    *count = 0;
    while (fgets(line, sizeof(line), file)) {
        if (line[0] == '[') {
            if (strstr(line, "ota") != NULL) {
                continue; // 不处理ota部分的内容
            }
        } else {
            char key[50], value[100];
            if(sscanf(line, "%[^=]=%s", key, value) == 2) {
                strcpy(keyValueArray[*count].key, key);
                strcpy(keyValueArray[*count].value, value);
                (*count)++;
            }
        }
    }
    fclose(file);
}

// 定义函数用于获取文件大小
long getFileSize(const char* filename) {
        OTA_INFO("filename%s\n",filename);

    FILE* file = fopen(filename, "rb");
    if (file == NULL) {
        OTA_INFO("can't open %s\n",filename);
        return -1;
    }

    fseek(file, 0, SEEK_END);
    long size = ftell(file);
    fclose(file);
    return size;
}

int getAllUpgradeFilesSize() {
    KeyValue keyValueArray[100];
    int count;
    parseIniFile("/tmp/ota/ota.ini", keyValueArray, &count);

    long totalSize = 0;
    for (int i = 0; i < count; i++) {
        long size = getFileSize(keyValueArray[i].value);
        if (size > 0) {
            totalSize += size;
        }
    }

    OTA_INFO("totalSize:%ld \n", totalSize);

    return totalSize;
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
			OTA_INFO("need upgrade from %s to %s\n", tmpVer, ver_str);

		} else {
			if (strcmp(ver_str, "0.0.0.0") == 0){
				OTA_ERR("ver%s force\n",ver_str);
			}else{
				OTA_ERR("already latest\n");
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

		OTA_INFO("packet head md5_get:%s\n \n", md5_get);			

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
	//system("cp /tmp/upgrade.tar.lzma /media/mmcblk0p1");
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
        //myconnect(kPayloadMD5MismatchError);
	}
	
	if (strncasecmp(md5_get, md5_str, 32) == 0)
	{
		OTA_INFO("md5_str is fuhe\n");
	}else{
		OTA_ERR("md5_str is bufuhe\n");
        myconnect(kPayloadMD5MismatchError);
        
		pthread_exit(NULL);
	}
	
	char SnOut[64]={0,0,0,0};
	ret = readStringValue("ipc", "sn", SnOut, "/tmp/app.ini");
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
		
        myconnect(kSNMismatchError);
		pthread_exit(NULL);
	}
	
	system("rm /tmp/upgrade.tar");
    
	system("sync");

	system("echo 3 > /proc/sys/vm/drop_caches");

	system("lzma -d /tmp/upgrade.tar.lzma");
	
	//system("mkdir /tmp/ota");
	
	//system("busybox tar xvf /tmp/upgrade.tar -C /tmp/ota");
	system("mkdir /tmp/ota; busybox tar xvf /tmp/upgrade.tar -C /tmp/ota");
	const char* directory = "/tmp/ota"; // 存放解压文件的目录

    size_t totalSize = getTotalFileSize(directory);
    size_t totalExitSize = getAllUpgradeFilesSize();

	long flash_space = getAvailableSpace();

    int v = totalSize - totalExitSize;
        
	if (v > 0 && flash_space < v)
	
	//if (0)
	{
	
//https://application.daguiot.com/ota/error?version=1.0.0.1&msg=""
    OTA_ERR("Flash not enough:flash_space %ld Totalfilesize:%zu bytes\n",flash_space,totalSize,totalExitSize);

	    OTA_ERR("Flash not enough:flash_space %ldK Totalfilesize:%zuk bytes totalExitSize:%zuk bytes\n",flash_space/1024,totalSize/1024,totalExitSize/1024);
        myconnect(kInsufficientFlashsizeError);
		pthread_exit(NULL);

	}else{
		
		OTA_ERR("Flash is enough:flash_space %ldK Totalfilesize:%zuk bytes\n",flash_space/1024,totalSize/1024);
	}
	
	read_ini_node("/tmp/ota/ota.ini", "file");

	
	ret = readStringValue("ota", "sv", ver_str, "/tmp/ota/ota.ini");
	if (ret == 1)
	{
	    OTA_ERR("Succe reading configuration value%s\n",ver_str);
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
		int fd = open("/tmp/upgrade.tar.lzma", O_CREAT | O_WRONLY, S_IRWXG | S_IRWXO | S_IRWXU);
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
				
//				memcpy(ver_str,ota_str+3,7);
//				OTA_INFO("ver_str is %s\n",ver_str);
//				
//				GetDevVer(tmpVer);
//				OTA_INFO("tmpVer is %s\n",tmpVer);
//				
//				if (compare_versions(tmpVer, ver_str)) {
//					OTA_INFO("需要升级从 %s到版本 %s\n", tmpVer, ver_str);
//
//				} else {
//					if (strcmp(ver_str, "0.0.0.0") == 0){
//						OTA_ERR("版本%s 强制升级\n",ver_str);
//					}else{
//						OTA_ERR("当前版本已是最新\n");
//						free(buf);
//						close(fd);						
//						close(card_fd);
//						OTA_ERR("!!!reboot\n");
//						//execl("/sbin/reboot", "reboot", NULL);
//						return -1;
//					}
//				}

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
				//progressBar(length, size);
			}
			else
			{
			    OTA_ERR("Error reading data from socket\n");
			    // 可以根据具体情况采取适当的处理措施
			}
		}
        //system("cp /tmp/upgrade.tar.lzma /media/mmcblk0/");
        free(buf);

		if (length == size)
			OTA_INFO("split successful length %d  size%d^_^\n\n",length,size);
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
			//execl("/sbin/reboot", "reboot", NULL);
            myconnect(kPayloadMD5MismatchError);
			return -1;

		}

		//char SnOut[64]={0,0,0,0};
        //if (access("/root/app.ini", F_OK) != -1) {
//    		ret = readStringValue("ipc", "sn", SnOut, "/root/app.ini");
//    		if (ret == 1)
//    		{
//    		    // 读取配置值成功
//    		}
//    		else
//    		{
//    		    OTA_ERR("Error reading configuration value\n");
//    		    // 可以根据具体情况采取适当的处理措施
//    		}
//        }else{
//    		ret = readStringValue("ipc", "sn", SnOut, "/tmp/app.ini");
//    		if (ret == 1)
//    		{
//    		    // 读取配置值成功
//    		}
//    		else
//    		{
//    		    OTA_ERR("Error reading configuration value\n");
//    		    // 可以根据具体情况采取适当的处理措施
//    		}
//        //}
//		OTA_INFO("%c %c %c %c\n",SnOut[3] , ota_str[42],SnOut[4] , ota_str[43]);
//		if(SnOut[3] == ota_str[42]&&SnOut[4] == ota_str[43]){
//			OTA_INFO("SN fuhe!!!!!!\n");
//		}else{
//			OTA_ERR("SN bufuhe!!!!!!\n");
//			//execl("/sbin/reboot", "reboot", NULL);
//			
//            myconnect(kSNMismatchError);
//			return -1;
//		}

		system("rm /tmp/upgrade.tar");

		system("lzma -d /tmp/upgrade.tar.lzma");
		//system("./busybox tar xvf /tmpupgrade.tar");
		system("mkdir /tmp/ota && busybox tar xvf /tmp/upgrade.tar -C /tmp/ota");

        const char* directory = "/tmp/ota"; // 存放解压文件的目录
    
        size_t totalSize = getTotalFileSize(directory);
        size_t totalExitSize = getAllUpgradeFilesSize();
    
        long flash_space = getAvailableSpace();
    
        int v = totalSize - totalExitSize;
            
        if (v > 0 && flash_space < v)
        
        //if (0)
        {
        
    //https://application.daguiot.com/ota/error?version=1.0.0.1&msg=""
        OTA_ERR("Flash空间不足flash_space %ld Totalfilesize:%zu bytes\n",flash_space,totalSize,totalExitSize);
    
            OTA_ERR("Flash空间不足flash_space %ldK Totalfilesize:%zuk bytes totalExitSize:%zuk bytes\n",flash_space/1024,totalSize/1024,totalExitSize/1024);
            myconnect(kInsufficientFlashsizeError);
            pthread_exit(NULL);
    
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

		SetDevVer(ver_str);
		OTA_INFO("!!!reboot\n");
		//execl("/sbin/reboot", "reboot", NULL);
		return -1;
#endif
	}else 
	{
		OTA_ERR("!!!file doesn't exist,exit\n");
        
        myconnect(kFileNotExitInTF);
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
    //if (nTime == 0) {
    if (0) {
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
#define VERSION "1.0.0"

int main(int argc, char const *argv[])
{
    //mySetTimeFrom4G();
	//downloadFileFromTianyiYun("iotoos29000240327/ota/3/123/upgrade.img", "/tmp/upgrade.img");
	//return 0;
	//downloadFileFromTianyiYun("ota/1/upgrade.img", "/tmp/ppp.img");
	//sleep(10);
    char url[2048] = "127.0.0.1";
    char domain[64] = {0};
    char ip_addr[16] = {0};
    int port = 80;
    char file_name[256] = {0};
    
    if (argc > 1 && strcmp(argv[1], "-v") == 0) {
        OTA_INFO("current version:%s\n", VERSION);
        return 0;
    }
    
    if (argc != 2)
    {
        OTA_INFO("Input a valid URL please\n");

        exit(0);
    }
    else{
//		if (strncasecmp((const char*)argv[1], "iotoos", 4) == 0)
//		{
//			downloadFileFromTianyiYun(argv[1], "/tmp/upgrade.img");
//            system("cp /tmp/upgrade.img /media/mmcblk0/");
//		}else{
//			upgrade_from_card(argv[1]);
//			OTA_INFO("reboot -- p\n");
//			system("reboot -- p");
//			return 0;
//		}
        if (strncasecmp((const char*)argv[1], "/media", 4) == 0)
		{
            upgrade_from_card(argv[1]);
            if (mkdir("/root/otaflag", 0777) != 0) {
                OTA_INFO("Error creating otaflag\n");
                //continue; // Skip further operations and continue with the next key-value pair
            }
            
            OTA_INFO("reboot -- p\n");
            if(access("/root/otareb", F_OK ) == -1 ) 
            {
                system("reboot -- p");
            }
			return 0;

		}else{
            system("rm /tmp/upgrade.img");
            
			downloadFileFromTianyiYun(argv[1], "/tmp/upgrade.img");
            //system("cp /tmp/upgrade.img /media/mmcblk0/");

		}
	}
	
	//return 0;
//	struct statvfs buf2;
//    if (statvfs("/root", &buf2) == 0) {
//        unsigned long block_size = buf2.f_frsize; // 文件系统块大小
//        unsigned long available_blocks = buf2.f_bavail; // 可用块数量
//        unsigned long available_space = block_size * available_blocks;
//        
//        OTA_INFO("可用空间大小：%luk bytes\n", available_space/1024);
//    } else {
//        OTA_INFO("无法获取/root分区信息\n");
//    }
//	struct sysinfo sys_info;
//
//    // 获取系统信息
//    if (sysinfo(&sys_info) != 0) {
//        perror("sysinfo");
//        return 1;
//    }
//
//    // 打印可用内存大小
//    OTA_INFO("Total RAM: %lu KB\n", sys_info.totalram / 1024);
//    OTA_INFO("Free RAM: %lu KB\n", sys_info.freeram / 1024);
//
//    // 打印可用Flash大小
//    OTA_INFO("Total Swap: %lu KB\n", sys_info.totalswap / 1024);
//    OTA_INFO("Free Swap: %lu KB\n", sys_info.freeswap / 1024);
	


    /*开新的线程解析文件*/
    pthread_t parse_thread;
    pthread_create(&parse_thread, NULL, parseAndextract, (void *) 0);
    pthread_join(parse_thread, NULL);
    
    if (mkdir("/root/otaflag", 0777) != 0) {
        OTA_INFO("Error creating otaflag\n");
        //continue; // Skip further operations and continue with the next key-value pair
    }

	OTA_INFO("reboot -- p\n");
    if(access("/root/otareb", F_OK ) == -1 ) 
	{
    	system("reboot -- p");
    }
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
