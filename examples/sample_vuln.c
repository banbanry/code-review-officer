#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// 含多类漏洞的测试样本
int main(int argc, char *argv[]) {
    char buf[64];
    char *data = malloc(1024);
    char *ptr = malloc(256);
    FILE *fp;
    char password[] = "admin123";  // 硬编码密钥

    gets(buf);                     // 危险函数
    sprintf(data, "%s", buf);      // 缓冲区溢出
    fp = fopen("config.txt", "r");
    fread(buf, 1, 32, fp);         // fopen 未检查 NULL
    system(data);                  // 命令注入
    free(data);
    printf("%s", data);            // use-after-free
    return 0;
}
