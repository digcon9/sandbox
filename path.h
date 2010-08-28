#ifndef PATH_H
#define PATH_H

int is_absolute_path(char *pathname);
void resolve_path(char *path);
char** string_to_tokens(char *str, char *delim);
/* Converts string to array of tokens that ends with null element. Result should be freed from caller */
char** string_to_tokens(char *str, char *delim);
char* complete_path(char* cur_dir, char* pathname);
char* full_path(char *filepath);


#endif
