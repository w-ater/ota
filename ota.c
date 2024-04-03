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
 
#define OTA_DEBUG //开启debug打印
#ifdef OTA_DEBUG
#define OTA_INFO(...) fprintf(stdout, "[OTA_INFO] %s(%d): ", __FUNCTION__, __LINE__),fprintf(stdout, __VA_ARGS__)
#define OTA_ERR(...) fprintf(stderr, "[OTA_ERR] %s(%d): ", __FUNCTION__, __LINE__),fprintf(stderr, __VA_ARGS__)
#else
#define OTA_INFO(...)
#define OTA_ERR(...) 
#endif

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
 
 
    OTA_ERR("\r%.2f%%\t[%-*.*s] %.2f/%.2fMB", percent * 100, numTotal, numShow, sign, cur_size / 1024.0 / 1024.0, total_size / 1024.0 / 1024.0);
    fflush(stdout);
 
    if (numShow == numTotal)
        OTA_ERR("\n");
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
        OTA_ERR("Create file failed\n");
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
        OTA_ERR("Download successful ^_^\n\n");
}
#endif
#include "md5.h"
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
	readStringValue("ipc", "ver", ver_out, CFGINI);
}
//#define CFGINI2  "/media/mmcblk0/ota"
#define CFGINI2  "/tmp/ota.ini"

int  GetOtaApp(char* ver_out)
{
	readStringValue("file", "extest", ver_out, CFGINI2);
}

int  SetDevVer(const char* ver_in)
{
	writeStringVlaue("ipc", "ver", ver_in, CFGINI);
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

    char *buf = (char *) malloc(mem_size * sizeof(char));
	char ver_str[64]={0};
	char tmpVer[64]={0};

	char ota_str[64]={0};
	char md5_get[32]={0};

	if ((read(client_socket, buf, 64)) != 0)
	{
			memcpy(ota_str,buf,64);
			ota_str[63]='\0';
			OTA_ERR("!!!ota_str%s\n",ota_str);
			
			memcpy(ver_str,ota_str+3,7);
			OTA_ERR("ver_str is %s\n",ver_str);
			
			GetDevVer(tmpVer);
			OTA_ERR("tmpVer is %s\n",tmpVer);
			
			if (compare_versions(tmpVer, ver_str)) {
				OTA_ERR("需要升级从 %s到版本 %s\n", tmpVer, ver_str);

			} else {
				if (strcmp(ver_str, "0.0.0.0") == 0){
					OTA_ERR("版本%s 强制升级\n",ver_str);
				}else{
					OTA_ERR("当前版本已是最新\n");
					free(buf);
					OTA_ERR("!!!reboot\n");
					system("reboot");					
					pthread_exit(NULL);
				}
			}

			//SetDevVer(ver_str);
			
			memcpy(md5_get,ota_str+10,32);
			for (int i = 0; i < 64; i++)
		   {
			   printf("0x%02x ", md5_get[i]);
		   }
		   OTA_ERR(" \r\n");
			

        //write(fd, buf, len);
        //progressBar(length, resp.content_length);
    }
	memset(buf,0,4096);
	OTA_ERR("!!!sizeof(buf)%d\n",mem_size * sizeof(char));
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
		/*if(length<4096){
			memcpy(ota_str,buf,64);
			ota_str[63]='\0';
			OTA_ERR("!!!ota_str%s",ota_str);

		}*/
		//OTA_ERR("!!!len%d\n",len);
        write(fd, buf, len);
        length += len;
		memset(buf,0,4096);
        progressBar(length, resp.content_length);
    }
 
    if (length == resp.content_length)
        OTA_ERR("Download successful length %dresp.content_length%d^_^\n\n",length,resp.content_length);
#if 1	
	int ret;
	const char *file_upgrade = "upgrade.tar.lzma";
	char md5_str[MD5_STR_LEN + 1];
 
	ret = Compute_file_md5(file_upgrade, md5_str);
	if (0 == ret)
	{
		OTA_ERR("[file - %s] md5 value:\n", file_upgrade);
		OTA_ERR("%s\n", md5_str);
	}
	
	if (strncasecmp(md5_get, md5_str, 32) == 0)
	{
		OTA_ERR("md5_str is fuhe\n");
	}else{
		OTA_ERR("md5_str is bufuhe\n");

	}
	
	char SnOut[64]={0,0,0,0};
	readStringValue("ipc", "sn", SnOut, "/root/app.ini");
	OTA_ERR("%c %c %c %c\n",SnOut[3] , ota_str[42],SnOut[4] , ota_str[43]);
	if(SnOut[3] == ota_str[42]&&SnOut[4] == ota_str[43]){
		OTA_ERR("SN fuhe!!!!!!\n");
	}else{
		OTA_ERR("SN bufuhe!!!!!!\n");
		system("reboot");
		exit(0);
	}
	
	system("rm upgrade.tar");

	system("lzma -d upgrade.tar.lzma");
	system("./busybox tar xvf upgrade.tar");
	
	char file_path[64]={0,0,0,0};
	readStringValue("file", "extest", file_path, "./ota.ini");
	OTA_ERR("!!!file_path%s\n",file_path);
	
	char extest[] = "extest";
    //char file_path[] = "/path/to/destination/file";

    char command[100];
	memset(command,0,100);

    sprintf(command, "cp %s %s", extest, file_path);
    system(command);

	memset(file_path,0,64);
	readStringValue("file", "111", file_path, "./ota.ini");
		OTA_ERR("!!!file_path%s\n",file_path);

	char eee[] = "111";
    //char file_path[] = "/path/to/destination/file";

    memset(command,0,100);
    sprintf(command, "cp %s %s", eee, file_path);

    system(command);
	
	readStringValue("ota", "sv", ver_str, "./ota.ini");

	SetDevVer(ver_str);
	OTA_ERR("!!!reboot\n");
	system("reboot");
#endif
}
#endif

#include <sys/stat.h>

int upgrade_from_card(char *path)
{
	if(access(path, F_OK ) != -1 ) 
	{
		OTA_ERR("!!!file exist,%s\n",path);
		
		struct stat statbuf; 
		stat(path,&statbuf); 
		int size=statbuf.st_size;
		OTA_ERR("size %d\n",size);

		int length = 0;
		int mem_size = 4096;//mem_size might be enlarge, so reset it
		int buf_len = mem_size;//read 4k each time
		int len;

		//创建文件描述符
		int fd = open("upgrade.tar.lzma", O_CREAT | O_WRONLY, S_IRWXG | S_IRWXO | S_IRWXU);
		if (fd < 0)
		{
			OTA_ERR("Create file failed\n");
			exit(0);
		}

		char *buf = (char *) malloc(mem_size * sizeof(char));
		char ver_str[64]={0};
		char tmpVer[64]={0};

		char ota_str[64];
		char md5_get[32];

		int card_fd = open(path, O_RDONLY);
		if (card_fd < 0)
		{
			OTA_ERR("Create fd failed\n");
			free(buf);
			exit(1);
		}
		
		if ((read(card_fd, buf, 64)) != 0)
		{
				memcpy(ota_str,buf,64);
				ota_str[63]='\0';
				OTA_ERR("!!!ota_str%s\n",ota_str);
				
				memcpy(ver_str,ota_str+3,7);
				OTA_ERR("ver_str is %s\n",ver_str);
				
				GetDevVer(tmpVer);
				OTA_ERR("tmpVer is %s\n",tmpVer);
				
				if (compare_versions(tmpVer, ver_str)) {
					OTA_ERR("需要升级从 %s到版本 %s\n", tmpVer, ver_str);

				} else {
					if (strcmp(ver_str, "0.0.0.0") == 0){
						OTA_ERR("版本%s 强制升级\n",ver_str);
					}else{
						OTA_ERR("当前版本已是最新\n");
						free(buf);
						close(fd);						
						close(card_fd);
						OTA_ERR("!!!reboot\n");
						system("reboot");
					}
				}

				//SetDevVer(ver_str);
				
				memcpy(md5_get,ota_str+10,32);
				for (int i = 0; i < 64; i++)
			   {
				   printf("0x%02x ", md5_get[i]);
			   }
			   OTA_ERR(" \r\n");
				

			//write(fd, buf, len);
			//progressBar(length, resp.content_length);
		}
		memset(buf,0,sizeof(buf));
		OTA_ERR("!!!sizeof(buf)%d\n",mem_size * sizeof(char));
		size -= 64;
		//从套接字中读取文件流
		while ((len = read(card_fd, buf, buf_len)) != 0 && length < size)
		{
			write(fd, buf, len);
			length += len;
		}

		if (length == size)
			OTA_ERR("split successful length %d  size%d^_^\n\n",length,size);
#if 1	
		int ret;
		const char *file_upgrade = "upgrade.tar.lzma";
		char md5_str[MD5_STR_LEN + 1];

		ret = Compute_file_md5(file_upgrade, md5_str);
		if (0 == ret)
		{
			OTA_ERR("[file - %s] md5 value:\n", file_upgrade);
			OTA_ERR("%s\n", md5_str);
		}

		if (strncasecmp(md5_get, md5_str, 32) == 0)
		{
			OTA_ERR("md5_str is fuhe\n");
		}else{
			OTA_ERR("md5_str is bufuhe\n");			
			system("reboot");			
			exit(0);

		}

		char SnOut[64]={0,0,0,0};
		readStringValue("ipc", "sn", SnOut, "/root/app.ini");
		OTA_ERR("%c %c %c %c\n",SnOut[3] , ota_str[42],SnOut[4] , ota_str[43]);
		if(SnOut[3] == ota_str[42]&&SnOut[4] == ota_str[43]){
			OTA_ERR("SN fuhe!!!!!!\n");
		}else{
			OTA_ERR("SN bufuhe!!!!!!\n");
			system("reboot");
			exit(0);
		}

		system("rm upgrade.tar");

		system("lzma -d upgrade.tar.lzma");
		system("./busybox tar xvf upgrade.tar");

		char file_path[64];
		readStringValue("file", "extest", file_path, "./ota.ini");
		OTA_ERR("!!!file_path%s\n",file_path);

		char extest[] = "extest";
		//char file_path[] = "/path/to/destination/file";

		char command[100];

		sprintf(command, "cp %s %s", extest, file_path);
		system(command);

		readStringValue("file", "111", file_path, "./ota.ini");
			OTA_ERR("!!!file_path%s\n",file_path);

		char eee[] = "111";
		//char file_path[] = "/path/to/destination/file";

		memset(command,0,100);
		sprintf(command, "cp %s %s", eee, file_path);

		system(command);

		readStringValue("ota", "sv", ver_str, "./ota.ini");

		SetDevVer(ver_str);
		OTA_ERR("!!!reboot\n");
		system("reboot");
#endif
	}else 
	{
		OTA_ERR("!!!file doesn't exist,exit\n");
		exit(0);
	}

}


int upgrade_from_card2(char *path)
{
	if(access(path, F_OK ) != -1 ) 
	{
		OTA_ERR("!!!file exist,%s\n",path);
		char *buf = (char *) malloc(64 * sizeof(char));
		if (buf == NULL) {
			OTA_ERR("Memory allocation failed\n");
			exit(1);
		}
		
		struct stat statbuf; 
		stat(path,&statbuf); 
		int size=statbuf.st_size;
		OTA_ERR("size %d\n",size);
		int length=0;

		
		int fd = open(path, O_RDONLY);
		if (fd < 0)
		{
			OTA_ERR("Create fd failed\n");
			free(buf);
			exit(1);
		}
		int len = read(fd, buf, 64);
		if (len < 0) {
			OTA_ERR("Read file failed\n");
			free(buf);
			close(fd);
			exit(1);
		}
			for (int i = 0; i < len; i++)
		   {
			   printf("%c", buf[i]);
		   }
		   OTA_ERR(" \r\n");
		char ver_str[32];
		memcpy(ver_str,buf+3,7);
		ver_str[7] = '\0';
		OTA_ERR("ver_str is %s\n",ver_str);
		
		char tmpVer[64]={0};
		GetDevVer(tmpVer);
		OTA_ERR("tmpVer is %s\n",tmpVer);
		if (compare_versions(tmpVer, ver_str)) {
			OTA_ERR("需要升级到版本 %s\n", ver_str);
			
			int split_fd = open("upgrade.tar.lzma", O_CREAT | O_WRONLY, S_IRWXG | S_IRWXO | S_IRWXU);
			if (split_fd < 0)
			{
				OTA_ERR("Create file failed\n");
				exit(0);
			}
			while ((len = read(fd, buf, 4096)) != 0 && length < size)
			{

				write(split_fd, buf, len);
				length += len;
			}
			free(buf);
			close(fd);
			
			OTA_ERR("!!!length%d\n",length);

			system("rm upgrade.tar");

			system("lzma -d upgrade.tar.lzma");
			system("busybox tar xvf upgrade.tar -C /tmp");
							
							char file_path[64]={0,0,0,0};
	//readStringValue("file", "extest", file_path, "./ota.ini");
	GetOtaApp(file_path);
	OTA_ERR("!!!file_path%s\n",file_path);
			OTA_ERR("11111111111\n");

			char command[100];
			//char file_path[64]={0};

			memset(file_path, 0, sizeof(64));
			
			readStringValue("file", "extest", file_path, "/tmp/ota.ini");
						sleep(2);
			OTA_ERR("22222222222\n");
			OTA_ERR("!!!file_path%s\n",file_path);
			
			char extest[] = "extest";
			//char file_path[] = "/path/to/destination/file";


			sprintf(command, "cp %s %s", extest, file_path);
			system(command);

			readStringValue("file", "111", file_path, "/tmp/ota.ini");
			OTA_ERR("!!!file_path%s\n",file_path);

			char eee[] = "111";
			//char file_path[] = "/path/to/destination/file";

			memset(command,0,100);
			sprintf(command, "cp %s %s", eee, file_path);

			system(command);
			SetDevVer(ver_str);
			OTA_ERR("!!!reboot\n");
			//system("reboot");
			exit("0");

			return 1;
		} else {
			OTA_ERR("当前版本已是最新\n");
			free(buf);
			close(fd);
			return 0;
		}
		/*char upgrade_str[64];
		memcpy(upgrade_str,buf,64);
		upgrade_str[63]='\0';
		OTA_ERR("!!!upgrade_str%s\n",upgrade_str);*/
	} 
	else 
	{
		OTA_ERR("!!!file doesn't exist,exit\n");
		exit(0);
	}
}

int main(int argc, char const *argv[])
{
	//check_upgradeimg();
	//return 0;
    char url[2048] = "127.0.0.1";
    char domain[64] = {0};
    char ip_addr[16] = {0};
    int port = 80;
    char file_name[256] = {0};
 
    if (argc == 1)
    {
        printf("Input a valid URL please\n");
        exit(0);
    }
    else{
		if (strncasecmp((const char*)argv[1], "HTTP", 4) == 0)
		{
			strcpy(url, argv[1]);
		}else{
			upgrade_from_card(argv[1]);
			return 0;
		}
	}
    parse_url(url, domain, &port, file_name);
 
    /*if (argc == 3)
        strcpy(file_name, argv[2]);*/
 
    get_ip_addr(domain, ip_addr);
    if (strlen(ip_addr) == 0)
    {
        printf("can not get ip address\n");
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
  printf("\n>>>>GET header:<<<<\n%s", header);
 
    //创建套接字
    int client_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (client_socket < 0)
    {
        printf("invalid socket descriptor: %d\n", client_socket);
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
        printf("connect failed, return: %d\n", res);
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
                printf("realloc failed\n");
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
 
    printf("\n>>>>Response header:<<<<\n%s", response);
    resp = get_resp_header(response);
    strcpy(resp.file_name, file_name);
 
    /*开新的线程下载文件*/
    pthread_t download_thread;
    pthread_create(&download_thread, NULL, download, (void *) &client_socket);
    pthread_join(download_thread, NULL);

	free(response);
    free(buf);
}
