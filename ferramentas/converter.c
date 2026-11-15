#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>

struct list_type {
        char question[80];
        char answer1[30];
        char answer2[30];
        char answer3[30];
        char answer4[30];
        int  right;
};

struct list_type questions;

char line[256];
int count = 0;

int main(int argc, char *argv[])
{
    if (argc < 2)
    {
        printf("Usage: %s <filename>\n", argv[0]);
        return 1;
    }
    FILE *filein;
    FILE *fileout;

    filein = fopen(argv[1], "r");
    fileout = fopen(argv[2], "wb");

    // contamos o numero de linhas
    while (fgets(line, sizeof(line), filein))
    {
	count++;
    }

    // Move o cursor para o incio do arquivo novamente
    fseek(filein, 0, SEEK_SET);
    
    // Escreve o numero de linhas no arquivo
    //fprintf(fileout, "%d\n", count);
    fwrite(&count, sizeof(count), 1, fileout);

    // Le linha por linha do arquivo
    // Quebra pelo divisor '|'
    while (fgets(line, sizeof(line), filein))
    {
        strcpy(questions.question,strtok(line, "|"));
        strcpy(questions.answer1,strtok(NULL,"|"));
        strcpy(questions.answer2,strtok(NULL,"|"));
        strcpy(questions.answer3,strtok(NULL,"|"));
        strcpy(questions.answer4,strtok(NULL,"|"));
        questions.right=atoi(strtok(NULL,"|"));

        fwrite(&questions,sizeof(struct list_type),1,fileout);
    }

    printf("Number of lines: %d\n", count);
    fclose(fileout);
    fclose(filein);

}
