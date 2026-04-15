#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "hash_utils.h"

#define MAX_LINE_LENGTH 200
#define MAX_USER_INPUT_LENGTH 100
#define MAX_USERNAME_LENGTH 50
#define MAX_PASSWORD_LENGTH 50
#define MAX_COMMAND_LENGTH 50

#define FILE_HASHED_USERS "hashed_users.txt"
#define MAX_HASH_LENGTH 65
#define HEX_SALT_LENGTH 5
#define SALT_LENGTH 2

// Function to convert hexadecimal string to bytes
int hex_to_bytes(const char *hex_str, unsigned char *out) {
    size_t len = strlen(hex_str);

    // Length must be even
    if (len % 2 != 0) {
        return -1;
    }

    size_t byte_len = len / 2;

    for (size_t i = 0; i < byte_len; i++) {
        unsigned int value;

        // Read two hex characters at a time
        if (sscanf(&hex_str[i * 2], "%2x", &value) != 1) {
            return -1; // invalid hex
        }

        out[i] = (unsigned char)value;
    }

    return (int)byte_len; // return number of bytes written
}

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
    char file_counter[2];
    unsigned char file_salt[SALT_LENGTH];
    char hashed_password[MAX_HASH_LENGTH];

    while (fgets(line, sizeof(line), file)) {
        // Remove the newline character
        trim_newline(line);

        // Split the line into username, salt hex, hashed password and counter
        char* token = strtok(line, ":");
        if (token != NULL) {
            strcpy(file_username, token);
            token = strtok(NULL, ":");
            if (token != NULL) {
                strcpy(file_salt_hex, token);
                token = strtok(NULL, ":");
                if (token != NULL) {
                    strcpy(file_hashed_password, token);
                    token = strtok(NULL, "\n");
                    if (token != NULL) {
                        strcpy(file_counter, token);
                    }
                }
            }
        }

        hex_to_bytes(file_salt_hex, file_salt);
        hash_password(password, file_salt, hashed_password);

        // Compare entered username and password with the file's values
        if (strcmp(username, file_username) == 0
            && strcmp(hashed_password, file_hashed_password) == 0) {
            fclose(file);
            return 1;  // Login successful
        }
    }

    fclose(file);
    return 0;  // Login failed
}

void sanitize_user_input(const char* user_input, char* output, uint len){
    // Safe copy

    // Ensure null termination
}

int main() {
    char user_input[MAX_USER_INPUT_LENGTH];
    char user_input_2[MAX_USER_INPUT_LENGTH];
    char username[MAX_USERNAME_LENGTH];
    char password[MAX_PASSWORD_LENGTH];
    char command[MAX_COMMAND_LENGTH];

    // Prompt user for username and password
    printf("Enter username: ");
    fgets(user_input, sizeof(user_input), stdin);
    trim_newline(user_input);  // Remove newline character
    strncpy(username, user_input, MAX_USERNAME_LENGTH - 1);
    username[MAX_USERNAME_LENGTH - 1] = '\0';
    printf("debug username: %s\n", username);

    printf("Enter password: ");
    fgets(user_input_2, sizeof(user_input_2), stdin);
    trim_newline(user_input_2);  // Remove newline character
    strncpy(password, user_input_2, MAX_PASSWORD_LENGTH - 1);
    password[MAX_PASSWORD_LENGTH - 1] = '\0';
    printf("debug password: %s\n", password);

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
