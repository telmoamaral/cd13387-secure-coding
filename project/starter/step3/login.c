#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define MAX_LINE_LENGTH 200
#define MAX_USERNAME_LENGTH 50
#define MAX_PASSWORD_LENGTH 50
#define MAX_COMMAND_LENGTH 50
#define FILE_HASHED_USERS "hashed_users.txt"
#define MAX_HASH_LENGTH 65
#define HEX_SALT_LENGTH 5

// Function to trim newline characters
void trim_newline(char* str) {
    char* pos;
    if ((pos = strchr(str, '\n')) != NULL)
        *pos = '\0';
}

// Function to check if username and password match an entry in users.txt
int check_login(const char* username, const char* password) {

    FILE* file = fopen(FILE_HASHED_USERS, "r");
    if (file == NULL) {
        printf("Could not open hashed_users.txt\n");
        return 0;
    }

    char line[MAX_LINE_LENGTH];
    char file_username[MAX_USERNAME_LENGTH];
    char file_salt_hex[HEX_SALT_LENGTH];
    char file_hashed_password[MAX_HASH_LENGTH];

    while (fgets(line, sizeof(line), file)) {
        // Remove the newline character
        trim_newline(line);
        printf("debug read line: %s\n", line);


        // Split the line into username and password
        char* token = strtok(line, ":");
        if (token != NULL) {
            strcpy(file_username, token);
            token = strtok(NULL, ":");
            if (token != NULL) {
                strcpy(file_salt_hex, token);
                token = strtok(NULL, "\n");
                if (token != NULL) {
                    strcpy(file_hashed_password, token);
                }
            }
        }
        printf("debug read username: %s\n", file_username);
        printf("debug read salt_hex: %s\n", file_salt_hex);
        printf("debug read hashed_password: %s\n", file_hashed_password);
        printf("debug extracted values: %s, %s, %s\n", file_username, file_salt_hex, file_hashed_password);

        // Compare entered username and password with the file's values
        // if (strcmp(username, file_username) == 0 && strcmp(password, file_password) == 0) {
        //     fclose(file);
        //     return 1;  // Login successful
        // }
    }

    fclose(file);
    return 0;  // Login failed
}

int main() {
    char username[MAX_USERNAME_LENGTH];
    char password[MAX_PASSWORD_LENGTH];
    char command[MAX_COMMAND_LENGTH];

    printf("Running login...\n");

    // Prompt user for username and password
    printf("Enter username: ");
    fgets(username, sizeof(username), stdin);
    trim_newline(username);  // Remove newline character

    printf("Enter password: ");
    fgets(password, sizeof(password), stdin);
    trim_newline(password);  // Remove newline character

    // Check login credentials
    if (check_login(username, password)) {
        printf("Login successful!\n");

        // Command prompt loop
        while (1) {
            printf("> ");
            scanf("%s", command);

            if (strcmp(command, "exit") == 0) {
                break;
            } else {
                printf("Unknown command.\nAllowed command is exit.\n");
            }
        }
    } else {
        printf("Login failed.\n");
    }

    return 0;
}