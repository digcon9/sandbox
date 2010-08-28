#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "path.h"

/* Global variables */
#define MAX_LEN 2048
char max_path[MAX_LEN];


int is_absolute_path(char *pathname){
	if(strlen(pathname) > 0 && pathname[0] == '/')
		return 1;
	return 0;
}

void resolve_path(char *path){
	puts("in resolve path");
	char ret[MAX_LEN], ret1[MAX_LEN], *tok;
	char** tokens = string_to_tokens(path, "/");
	int i = 0, len = 0;
	while(tokens[len] != NULL){
		len++;
	}
	int two_dots = 0;
	strcpy(ret, "\b");
	for(i = len - 1; i >= 0; i--){
		if(strlen(tokens[i]) <= 0 || !strcmp(tokens[i], ".") || !strcmp(tokens[i], "/")) continue;
		if(!strcmp(tokens[i], "..")) {++two_dots; continue;}
		if(two_dots > 0){	
			--two_dots;
			continue;
		}
		if(i == len - 1) 
			sprintf(ret1, "%s", tokens[i]);
		else
			sprintf(ret1, "%s/%s", tokens[i], ret);
		strcpy(ret, ret1);	
	}
	free(tokens);
	// '\a' is used as an empty character
	sprintf(path, "%c%s", (strlen(path) && path[0] == '/') ? '/' : '\a', ret);
}

/* Converts string to array of tokens that ends with null element. Result should be freed from caller */
char** string_to_tokens(char *str, char *delim){
	#define MAX_TOKEN 256
	int index = 0;
	int *ret = malloc(sizeof(char*) * MAX_TOKEN);
	char *tok = strtok(str, delim);
	while(tok != NULL){
		ret[index++] = tok;			
		tok = strtok(NULL, delim);
	}		
	ret[index] = NULL;
	return ret;
}

char* complete_path(char* cur_dir, char* pathname){
	if(strlen(pathname) <= 0 || !strcmp(pathname, ".") || !strcmp(pathname, "./")){
		return cur_dir;
	}	
	if(is_absolute_path(pathname)){
		return pathname;
	}
	sprintf(max_path, "%s/%s", cur_dir, pathname);
	printf("before resolving: %s\n", max_path);
	resolve_path(max_path);
	return max_path;
}

char *full_path(char* filepath){
	char *cur_dir = get_current_dir_name();
	return complete_path(cur_dir, filepath);	
}


