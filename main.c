#include<string.h>
#include<stdio.h>
 int main(void){
     char buf[32];
     printf("(minidbg) ");
     while(1){
        if(scanf("%31s",buf)!=1){break;}
        if(strcmp(buf,"s")==0){printf("ni shi ru de shi S\n");
               }else if(strcmp(buf,"x")==0){printf("ni shu ru de shi X\n");
                      }else if(strcmp(buf,"q")==0){break;
                        }else{
                              printf("unknow input:%s\n",buf);
                             }
     
    }
     return 0;
 }
 
