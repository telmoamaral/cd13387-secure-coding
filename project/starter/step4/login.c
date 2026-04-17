#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/time.h>
#include <stdbool.h>
#include "hash_utils.h"

#define MAX_LINE_LENGTH 200
#define MAX_USERNAME_LENGTH 50
#define MAX_PASSWORD_LENGTH 50
#define MAX_COMMAND_LENGTH 50

#define FILE_HASHED_USERS "hashed_users.txt"
#define FILE_HASHED_USERS_TEMP "hashed_users_temp.txt"
#define MAX_HASH_LENGTH 65
#define HEX_SALT_LENGTH 5
#define SALT_LENGTH 2
#define COUNTER_STR_LENGH 2
#define TIME_STR_LENGTH 14 // For string with time in ms since Epoch and a \0
#define MAX_LOGIN_ATTEMPTS 3
#define BLOCKED_USER_TIMER 5000

// Function to trim newline characters
void trim_newline(char* str) {
    char* pos;
    if ((pos = strchr(str, '\n')) != NULL)
        *pos = '\0';
}

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

// Function to return the number of milliseconds ellapsed since the Epoch
unsigned long get_milliseconds_since_epoch() {
    struct timeval time_value;
    gettimeofday(&time_value, NULL);
    return time_value.tv_sec * 1000 + time_value.tv_usec / 1000;
}

// Function to extract user information from one line of hashed_users.txt
void extract_user_info(
    char* line,
    char* file_username,
    char* file_salt_hex,
    char* file_hashed_password,
    char* file_counter_str,
    char* file_time_str
) {
    // Remove the newline character
    trim_newline(line);
    
    // Split the line into username, salt hex, hashed password, failed
    // login counter and time since last failed login
    char* token = strtok(line, ":");
    if (token != NULL) {
        strcpy(file_username, token);
        token = strtok(NULL, ":");
        if (token != NULL) {
            strcpy(file_salt_hex, token);
            token = strtok(NULL, ":");
            if (token != NULL) {
                strcpy(file_hashed_password, token);
                token = strtok(NULL, ":");
                if (token != NULL) {
                    strcpy(file_counter_str, token);
                    token = strtok(NULL, "\n");
                    if (token != NULL) {
                        strcpy(file_time_str, token);
                    }
                }
            }
        }
    }

    return;
}

// Function to update the counter of failed login attempts for a given user in
// hashed_users.txt, as well as the time of the last failed login
int update_failed_login_counter(char* username, int counter) {
    FILE* input_file = fopen(FILE_HASHED_USERS, "r");
    if (input_file == NULL) {
        printf("Could not open hashed_users.txt\n");
        return 0;
    }
    FILE* output_file = fopen(FILE_HASHED_USERS_TEMP, "w");
    if (output_file == NULL) {
        printf("Could not create hashed_users_temp.txt\n");
        return 0;
    }

    char line[MAX_LINE_LENGTH];
    char file_username[MAX_USERNAME_LENGTH];
    char file_salt_hex[HEX_SALT_LENGTH];
    char file_hashed_password[MAX_HASH_LENGTH];
    char file_counter_str[COUNTER_STR_LENGH];
    char file_time_str[TIME_STR_LENGTH];

    // Read file contents and update counter and time for the given user
    while (fgets(line, sizeof(line), input_file)) {
        extract_user_info(
            line,
            file_username,
            file_salt_hex,
            file_hashed_password,
            file_counter_str,
            file_time_str
        );

        if (strcmp(username, file_username) == 0) {
            sprintf(file_counter_str, "%d\0", counter);
            sprintf(file_time_str, "%ld\0", get_milliseconds_since_epoch());
        }

        fprintf(
            output_file,
            "%s:%s:%s:%s:%s\n",
            file_username,
            file_salt_hex,
            file_hashed_password,
            file_counter_str,
            file_time_str
        );
    }

    fclose(input_file);
    fclose(output_file);

    rename(FILE_HASHED_USERS_TEMP, FILE_HASHED_USERS);
    remove(FILE_HASHED_USERS_TEMP);

    return 1;
}

// Function to decide if a login attempt is successful or not
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
    char file_counter_str[COUNTER_STR_LENGH];
    char file_time_str[TIME_STR_LENGTH];
    unsigned char file_salt[SALT_LENGTH];
    char hashed_password[MAX_HASH_LENGTH];
    bool user_found = false;

    // Look up user in hash file
    while (fgets(line, sizeof(line), file)) {
        extract_user_info(
            line,
            file_username,
            file_salt_hex,
            file_hashed_password,
            file_counter_str,
            file_time_str
        );

        // Compare entered username with the file's value
        if (strcmp(username, file_username) == 0) {
            user_found = true;
            break;
        }
    }

    fclose(file);

    // Decide whether to grant access
    if (user_found) {
        unsigned int counter = atoi(file_counter_str);
        unsigned long time = atol(file_time_str);

        // Hash entered password salted with the file's salt
        hex_to_bytes(file_salt_hex, file_salt);
        hash_password(password, file_salt, hashed_password);

        // Compare entered password with the file's value
        bool password_ok = (strcmp(hashed_password, file_hashed_password) == 0);

        if (counter < MAX_LOGIN_ATTEMPTS - 1) {
            if (password_ok) {
                update_failed_login_counter(username, 0);
                return 1;
            }
            else {
                update_failed_login_counter(username, counter + 1);                
                return 0;
            }
        }
        else if (counter == MAX_LOGIN_ATTEMPTS - 1) {
            if (password_ok) {
                update_failed_login_counter(username, 0);
                return 1;
            }
            else {
                // Set counter to the limit and start the timer
                update_failed_login_counter(username, MAX_LOGIN_ATTEMPTS);
                printf(
                    "Too many failed attempts. Please wait %0.1f seconds to retry.\n",
                    BLOCKED_USER_TIMER / 1000.0
                );
                return 0;
            }
        }
        else {  // counter == MAX_LOGIN_ATTEMPTS
            unsigned long time_ellapsed = get_milliseconds_since_epoch() - time;
            bool timer_running = (time_ellapsed < BLOCKED_USER_TIMER);

            if (timer_running) {
                printf(
                    "Too many failed attempts. Please wait %0.1f seconds to retry.\n",
                    (BLOCKED_USER_TIMER - time_ellapsed) / 1000.0
                );
                return 0;
            }
            else {
                if (password_ok) {
                    update_failed_login_counter(username, 0);
                    return 1;
                }
                else {
                    // Keep the counter at the limit, and restart the timer on
                    // every new failed login
                    update_failed_login_counter(username, MAX_LOGIN_ATTEMPTS);
                    printf(
                        "Too many failed attempts. Please wait %0.1f seconds to retry.\n",
                        BLOCKED_USER_TIMER / 1000.0
                    );
                    return 0;
                }
            }
        }
    }
    else {  // No user found
        return 0;
    }
}

int main() {
    char username[MAX_USERNAME_LENGTH];
    char password[MAX_PASSWORD_LENGTH];
    char command[MAX_COMMAND_LENGTH];

    // Prompt user for username and password
    printf("Enter username: ");
    fgets(username, sizeof(username), stdin);
    trim_newline(username);  // Remove newline character
    printf("Enter password: ");
    fgets(password, sizeof(password), stdin);
    trim_newline(password);  // Remove newline character

    if (check_login(username, password)) {
        printf("Login successful!\n");

        // Command prompt loop
        while (1) {
            printf("> ");
            scanf("%s", command);

            if (strcmp(command, "exit") == 0) {
                break;
            }
            else {
                printf("Unknown command.\nAllowed command is exit.\n");
            }
        }
    }
    else {
        printf("Login failed.\n");
    }

    return 0;
}
