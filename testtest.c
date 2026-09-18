#include<stdio.h>
#include<stdlib.h>
int main(){
    char link[64],name,status;
    int pid;
    printf("shu ru ni de pid,name,status:");
    scanf("%d %c %d",&pid,&name,&status);
    snprintf(link,sizeof(link),"womendepidwei:%d%c%d",pid,name,status);
    printf("%s",link);
    return 0;
}
