#include "common.h"
#include <signal.h>

// Defaults (can be overridden via NM_HOST / NM_PORT env vars or argv)
// If you need to connect to some network service, use computer = my own machine, and port = 8000.
char nm_host_global[64] = "127.0.0.1"; //my computer
int nm_port_global = 8000; //with port 8000


// "socket" is a software endpoint for communication between two processes, allowing them to exchange data across a network
int nm_socket = -1; //name server socket is not connected yet to any server
char current_user[MAX_USERNAME] = ""; //no user logged in yet

// forward declaration
void register_with_nm(const char *username);

void connect_to_nm(void) {
    struct sockaddr_in nm_addr;

    // AF_INET is IPv4, SOCK_STREAM is TCP , value >= 0 means success 
    nm_socket = socket(AF_INET, SOCK_STREAM, 0);
    // value < 0 means error
    if (nm_socket < 0) {
        printf("ERROR: Cannot create socket\n");
        return;
    }
    
    nm_addr.sin_family = AF_INET;
    nm_addr.sin_addr.s_addr = inet_addr(nm_host_global);
    nm_addr.sin_port = htons(nm_port_global);
    // this means trying to connect to the server fails by client
    if (connect(nm_socket, (struct sockaddr *)&nm_addr, sizeof(nm_addr)) < 0) {
        printf("ERROR: Cannot connect to Name Server\n");
        return;
    }
}

// Helper: ensure connection to Name Server, reconnecting and re-registering if needed
int ensure_connected_to_nm(void) {
    if (nm_socket >= 0) return 1;
    connect_to_nm();
    if (nm_socket < 0) return 0;
    // after the connection is re-established, re-register the user
    register_with_nm(current_user);
    return 1;
}

void register_with_nm(const char *username) {
    char msg[MAX_BUFFER];
    // Allow overriding advertised client IP/PORT via env vars
    char *client_ip = getenv("CLIENT_IP");
    char *client_port = getenv("CLIENT_PORT");
    if (!client_ip) client_ip = "127.0.0.1";
    if (!client_port) client_port = "9200";
    // storing the user details in msg
    snprintf(msg, sizeof(msg), "TYPE:REGISTER_CLIENT\nUSER:%s\nIP:%s\nPORT:%s", username, client_ip, client_port);
    // printing the message to be sent to nm
    send_message(nm_socket, msg);
    // if message sent, wait for response
    char *response = receive_message(nm_socket);
    if (response) free(response);
}

int connect_to_ss(const char *ip, int port) {
    int ss_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (ss_socket < 0) return -1;
    
    // giving the socket ,the server address to connect to 
    struct sockaddr_in ss_addr;
    ss_addr.sin_family = AF_INET;
    ss_addr.sin_addr.s_addr = inet_addr(ip);
    ss_addr.sin_port = htons(port);
    
    // if connection fails
    if (connect(ss_socket, (struct sockaddr *)&ss_addr, sizeof(ss_addr)) < 0) {
        close(ss_socket);
        return -1;
    }
    
    return ss_socket;
}

void handle_view_command(const char *args) {
    // #define MAX_BUFFER 8192
    char msg[MAX_BUFFER];
    char flags[32] = "";
    // #define MAX_FILENAME 256
    char filename[MAX_FILENAME] = "";

    // Parse args: flags (start with '-') and optional filename
    if (strlen(args) > 0) {
        // Tokenize by whitespace
        char tmp[MAX_BUFFER];
        strncpy(tmp, args, sizeof(tmp));
        tmp[sizeof(tmp)-1] = '\0';
        char *tok = strtok(tmp, " \t\n");
        while (tok) {
            if (tok[0] == '-') {
                // merge flags
                strncat(flags, tok + 1, sizeof(flags) - strlen(flags) - 1);
            } else {
                if (filename[0] == '\0') {
                    strncpy(filename, tok, sizeof(filename)-1);
                    filename[sizeof(filename)-1] = '\0';
                }
            }
            tok = strtok(NULL, " \t\n");
        }
    }

    if (filename[0]) {
        snprintf(msg, sizeof(msg), "TYPE:VIEW\nUSER:%s\nFLAGS:%s\nFILENAME:%s", current_user, flags, filename);
    } else {
        snprintf(msg, sizeof(msg), "TYPE:VIEW\nUSER:%s\nFLAGS:%s", current_user, flags);
    }

    send_message(nm_socket, msg);
    char *response = receive_message(nm_socket);
    if (!response) {
        printf("ERROR: No response from Name Server\n");
        return;
    }

    char *data = strstr(response, "DATA:");
    if (data) {
        printf("%s", data + 5);
    } else {
        printf("%s\n", response);
    }
    free(response);
}

void handle_create_command(const char *filename) {
    char msg[MAX_BUFFER];
    snprintf(msg, sizeof(msg), "TYPE:CREATE\nUSER:%s\nFILENAME:%s", current_user, filename);
    if (!ensure_connected_to_nm()) {
        printf("ERROR: Not connected to Name Server\n");
        return;
    }
    send_message(nm_socket, msg);
    char *response = receive_message(nm_socket);
    if (!response) {
        // Try reconnect once
        close(nm_socket);
        nm_socket = -1;
        if (!ensure_connected_to_nm()) {
            printf("ERROR: No response from Name Server\n");
            return;
        }
        send_message(nm_socket, msg);
        response = receive_message(nm_socket);
        if (!response) {
            printf("ERROR: No response from Name Server\n");
            return;
        }
    }

    if (strstr(response, "ERROR_CODE:0")) {
        printf("File created successfully!\n");
    } else {
        char *error_msg = strstr(response, "ERROR_MSG:");
        if (error_msg) {
            printf("ERROR: %s\n", error_msg + 10);
        } else {
            printf("ERROR: Failed to create file\n");
        }
    }
    free(response);
}

void handle_read_command(const char *filename) {
    char msg[MAX_BUFFER];
    snprintf(msg, sizeof(msg), "TYPE:READ\nUSER:%s\nFILENAME:%s", current_user, filename);
    send_message(nm_socket, msg);
    char *response = receive_message(nm_socket);
    if (!response) {
        printf("ERROR: No response from Name Server\n");
        return;
    }

    if (strstr(response, "ERROR_CODE:0")) {
        char *ip = strstr(response, "IP:");
        char *port_str = strstr(response, "PORT:");
        
        if (ip && port_str) {
            char ss_ip[16];
            int ss_port;
            sscanf(ip, "IP:%s", ss_ip);
            sscanf(port_str, "PORT:%d", &ss_port);
            
            int ss_socket = connect_to_ss(ss_ip, ss_port);
            if (ss_socket < 0) {
                printf("ERROR: Cannot connect to storage server\n");
                free(response);
                return;
            }
            
            char read_msg[MAX_BUFFER];
            snprintf(read_msg, sizeof(read_msg), "TYPE:READ\nFILENAME:%s", filename);
            send_message(ss_socket, read_msg);
            
            char *ss_response = receive_message(ss_socket);
            if (!ss_response) {
                printf("ERROR: No response from Storage Server\n");
                close(ss_socket);
                free(response);
                return;
            }
            char *data = strstr(ss_response, "DATA:");
            if (data) {
                printf("%s\n", data + 5);
            }
            free(ss_response);
            close(ss_socket);
        }
    } else {
        char *error_msg = strstr(response, "ERROR_MSG:");
        if (error_msg) {
            printf("ERROR: %s\n", error_msg + 10);
        }
    }
    free(response);
}

void handle_write_command(const char *args) {
    char filename[MAX_FILENAME];
    int sentence_num = -1;

    // 1. Input Validation (Fixes Segfault on empty args)
    // Matches usage: WRITE <filename> <sentence_num>
    if (sscanf(args, "%s %d", filename, &sentence_num) != 2) {
        printf("ERROR: Invalid format. Usage: WRITE <filename> <sentence_num>\n");
        return;
    }

    // 2. Contact Name Server
    char msg[MAX_BUFFER];
    snprintf(msg, sizeof(msg), "TYPE:WRITE\nUSER:%s\nFILENAME:%s", current_user, filename);
    send_message(nm_socket, msg);

    char *response = receive_message(nm_socket);
    if (!response) {
        printf("ERROR: No response from Name Server\n");
        return;
    }

    // 3. Parse NM Response (Check if file exists/user has access)
    if (strstr(response, "ERROR_CODE:0")) {
        char *ip = strstr(response, "IP:");
        char *port_str = strstr(response, "PORT:");

        if (ip && port_str) {
            char ss_ip[32];
            int ss_port;
            sscanf(ip, "IP:%s", ss_ip);
            sscanf(port_str, "PORT:%d", &ss_port);

            // 4. Connect to Storage Server
            int ss_socket = connect_to_ss(ss_ip, ss_port);
            if (ss_socket < 0) {
                printf("ERROR: Cannot connect to storage server\n");
                free(response);
                return;
            }

            // 5. Initiate Write Session (Sentence Locking)
            char write_msg[MAX_BUFFER];
            snprintf(write_msg, sizeof(write_msg), "TYPE:WRITE\nFILENAME:%s\nSENTENCE:%d", 
                filename, sentence_num);
            send_message(ss_socket, write_msg);

            char *ss_response = receive_message(ss_socket);
            if (!ss_response) {
                printf("ERROR: Storage Server connection failed\n");
                close(ss_socket);
                free(response);
                return;
            }

            // Check if SS accepted (e.g., Sentence might be locked - T4.9)
            if (!strstr(ss_response, "ERROR_CODE:0")) {
                char *error_msg = strstr(ss_response, "ERROR_MSG:");
                if (error_msg) {
                    printf("ERROR: %s\n", error_msg + 10); // Prints "Sentence locked..." or "Index out of range"
                } else {
                    printf("ERROR: Write session rejected by Storage Server.\n");
                }
                free(ss_response);
                close(ss_socket);
                free(response);
                return;
            }
            free(ss_response);

            // 6. Interactive Write Loop (T4.4, T4.5, T4.6)
            printf("Write mode active. Enter updates in format: <word_index> <content>\n");
            printf("Type 'ETIRW' to save and exit.\n");
                printf("Indexes are 0-based (first word = 0). Negative indexes are not allowed.\n");
            
            char input[MAX_BUFFER];
            while (1) {
                printf("> ");
                fflush(stdout);

                if (!fgets(input, sizeof(input), stdin)) break;
                input[strcspn(input, "\n")] = 0; // Remove newline

                // Handle Exit Command
                if (strcmp(input, "ETIRW") == 0) {
                    send_message(ss_socket, "TYPE:ETIRW");
                    
                    // Wait for final confirmation from SS
                    char *final_response = receive_message(ss_socket);
                    if (final_response) {
                        if (strstr(final_response, "ERROR_CODE:0")) {
                            printf("Write successful!\n");
                        } else {
                            char *err = strstr(final_response, "ERROR_MSG:");
                            if (err) printf("ERROR: %s\n", err + 10);
                        }
                        free(final_response);
                    }
                    break;
                }

                // Handle Word Update
                int word_idx;
                char content[MAX_BUFFER];
                // We use complex scanf to allow spaces in content if needed, 
                // though spec says words are space-separated.
                if (sscanf(input, "%d %[^\n]", &word_idx, content) == 2) {
                    // Reject negative indexes locally to give faster feedback
                    if (word_idx < 0) {
                        printf("ERROR: Word index must be >= 0\n");
                        continue;
                    }
                    char update_msg[MAX_BUFFER];
                    snprintf(update_msg, sizeof(update_msg), "WORD_INDEX:%d\nCONTENT:%s", 
                        word_idx, content);
                    send_message(ss_socket, update_msg);

                    // IMPORTANT: We MUST wait for SS acknowledgment after every word update
                    // Otherwise the socket buffer fills up or desyncs.
                    char *update_response = receive_message(ss_socket);
                    if (update_response) {
                        if (!strstr(update_response, "ERROR_CODE:0")) {
                            // Handles T4.7 (Invalid Word Index)
                            char *error_msg = strstr(update_response, "ERROR_MSG:");
                            if (error_msg) {
                                printf("ERROR: %s\n", error_msg + 10);
                            }
                        }
                        free(update_response);
                    } else {
                        printf("ERROR: Lost connection to Storage Server\n");
                        break;
                    }
                } else {
                    printf("Invalid format. Use: <word_index> <content>\n");
                }
            }

            close(ss_socket);
        }
    } else {
        // Handle NM Errors (T4.8 No write access, File not found)
        char *error_msg = strstr(response, "ERROR_MSG:");
        if (error_msg) {
            printf("ERROR: %s\n", error_msg + 10);
        } else {
            printf("ERROR: Request failed.\n");
        }
    }

    if (response) free(response);
}


void handle_delete_command(const char *filename) {
    char msg[MAX_BUFFER];
    snprintf(msg, sizeof(msg), "TYPE:DELETE\nUSER:%s\nFILENAME:%s", current_user, filename);
    send_message(nm_socket, msg);
    char *response = receive_message(nm_socket);
    
    if (strstr(response, "ERROR_CODE:0")) {
        printf("File '%s' deleted successfully!\n", filename);
    } else {
        char *error_msg = strstr(response, "ERROR_MSG:");
        if (error_msg) {
            printf("ERROR: %s\n", error_msg + 10);
        }
    }
}

void handle_undo_command(const char *filename) {
    char msg[MAX_BUFFER];
    snprintf(msg, sizeof(msg), "TYPE:READ\nUSER:%s\nFILENAME:%s", current_user, filename);
    send_message(nm_socket, msg);
    char *response = receive_message(nm_socket);
    
    if (strstr(response, "ERROR_CODE:0")) {
        char *ip = strstr(response, "IP:");
        char *port_str = strstr(response, "PORT:");
        
        if (ip && port_str) {
            char ss_ip[16];
            int ss_port;
            sscanf(ip, "IP:%s", ss_ip);
            sscanf(port_str, "PORT:%d", &ss_port);
            
            int ss_socket = connect_to_ss(ss_ip, ss_port);
            if (ss_socket < 0) {
                printf("ERROR: Cannot connect to storage server\n");
                return;
            }
            
            char undo_msg[MAX_BUFFER];
            snprintf(undo_msg, sizeof(undo_msg), "TYPE:UNDO\nFILENAME:%s", filename);
            send_message(ss_socket, undo_msg);
            
            char *ss_response = receive_message(ss_socket);
            if (strstr(ss_response, "ERROR_CODE:0")) {
                printf("Undo successful!\n");
            } else {
                char *error_msg = strstr(ss_response, "ERROR_MSG:");
                if (error_msg) {
                    printf("ERROR: %s\n", error_msg + 10);
                }
            }
            
            close(ss_socket);
        }
    } else {
        char *error_msg = strstr(response, "ERROR_MSG:");
        if (error_msg) {
            printf("ERROR: %s\n", error_msg + 10);
        }
    }
}

void handle_stream_command(const char *filename) {
    char msg[MAX_BUFFER];
    snprintf(msg, sizeof(msg), "TYPE:READ\nUSER:%s\nFILENAME:%s", current_user, filename);
    send_message(nm_socket, msg);
    char *response = receive_message(nm_socket);
    
    if (strstr(response, "ERROR_CODE:0")) {
        char *ip = strstr(response, "IP:");
        char *port_str = strstr(response, "PORT:");
        
        if (ip && port_str) {
            char ss_ip[16];
            int ss_port;
            sscanf(ip, "IP:%s", ss_ip);
            sscanf(port_str, "PORT:%d", &ss_port);
            
            int ss_socket = connect_to_ss(ss_ip, ss_port);
            if (ss_socket < 0) {
                printf("ERROR: Cannot connect to storage server\n");
                return;
            }
            
            char stream_msg[MAX_BUFFER];
            snprintf(stream_msg, sizeof(stream_msg), "TYPE:STREAM\nFILENAME:%s", filename);
            send_message(ss_socket, stream_msg);
            
            // Receive streaming words
            while (1) {
                char *ss_response = receive_message(ss_socket);
                if (ss_response == NULL) {
                    printf("\nERROR: Storage server disconnected during streaming\n");
                    break;
                }
                if (strstr(ss_response, "TYPE:stream_end")) {
                    free(ss_response);
                    break;
                }
                char *data = strstr(ss_response, "DATA:");
                if (data) {
                    char *word = data + 5;
                    // Check if word is a delimiter (single char and is . ! ?)
                    if (strlen(word) == 1 && (word[0] == '.' || word[0] == '!' || word[0] == '?')) {
                        printf("%s", word);
                    } else {
                        printf("%s ", word);
                    }
                    fflush(stdout);
                }
                free(ss_response);
            }
            printf("\n");
            close(ss_socket);
        }
    } else {
        char *error_msg = strstr(response, "ERROR_MSG:");
        if (error_msg) {
            printf("ERROR: %s\n", error_msg + 10);
        }
    }
}

void handle_info_command(const char *filename) {
    char msg[MAX_BUFFER];
    snprintf(msg, sizeof(msg), "TYPE:INFO\nUSER:%s\nFILENAME:%s", current_user, filename);
    send_message(nm_socket, msg);
    char *response = receive_message(nm_socket);
    
    char *data = strstr(response, "DATA:");
    if (data) {
        printf("%s", data + 5);
    } else {
        char *error_msg = strstr(response, "ERROR_MSG:");
        if (error_msg) {
            printf("ERROR: %s\n", error_msg + 10);
        }
    }
}

void handle_list_command(void) {
    char msg[MAX_BUFFER];
    snprintf(msg, sizeof(msg), "TYPE:LIST\nUSER:%s", current_user);
    send_message(nm_socket, msg);
    char *response = receive_message(nm_socket);
    
    char *data = strstr(response, "DATA:");
    if (data) {
        printf("%s", data + 5);
    }
}

void handle_addaccess_command(const char *args) {
    char flag[10], filename[MAX_FILENAME], target_user[MAX_USERNAME];
    sscanf(args, "%s %s %s", flag, filename, target_user);
    
    char access_type[10];
    if (strcmp(flag, "-R") == 0) {
        strcpy(access_type, "R");
    } else if (strcmp(flag, "-W") == 0) {
        strcpy(access_type, "RW");
    } else {
        printf("ERROR: Invalid flag. Use -R for read or -W for write\n");
        return;
    }
    
    char msg[MAX_BUFFER];
    snprintf(msg, sizeof(msg), "TYPE:ADDACCESS\nUSER:%s\nFILENAME:%s\nTARGET:%s\nACCESS:%s", 
        current_user, filename, target_user, access_type);
    send_message(nm_socket, msg);
    char *response = receive_message(nm_socket);
    
    if (strstr(response, "ERROR_CODE:0")) {
        printf("Access granted successfully!\n");
    } else {
        char *error_msg = strstr(response, "ERROR_MSG:");
        if (error_msg) {
            printf("ERROR: %s\n", error_msg + 10);
        }
    }
}

void handle_remaccess_command(const char *args) {
    char filename[MAX_FILENAME], target_user[MAX_USERNAME];
    sscanf(args, "%s %s", filename, target_user);
    
    char msg[MAX_BUFFER];
    snprintf(msg, sizeof(msg), "TYPE:REMACCESS\nUSER:%s\nFILENAME:%s\nTARGET:%s", 
        current_user, filename, target_user);
    send_message(nm_socket, msg);
    char *response = receive_message(nm_socket);
    
    if (strstr(response, "ERROR_CODE:0")) {
        printf("Access removed successfully!\n");
    } else {
        char *error_msg = strstr(response, "ERROR_MSG:");
        if (error_msg) {
            printf("ERROR: %s\n", error_msg + 10);
        }
    }
}

// ======== ACCESS REQUEST COMMANDS (BONUS FEATURE) ========

void handle_requestaccess_command(const char *args) {
    char filename[MAX_FILENAME], permission[8] = "R";
    char *token = strtok((char*)args, " ");
    
    // Parse -R or -W flag
    if (token && strcmp(token, "-R") == 0) {
        strcpy(permission, "R");
        token = strtok(NULL, " ");
    } else if (token && strcmp(token, "-W") == 0) {
        strcpy(permission, "W");
        token = strtok(NULL, " ");
    }
    
    if (token) {
        strcpy(filename, token);
    } else {
        printf("Usage: REQUESTACCESS [-R|-W] <filename>\n");
        return;
    }
    
    char msg[MAX_BUFFER];
    snprintf(msg, sizeof(msg), "TYPE:REQUESTACCESS\nUSER:%s\nFILENAME:%s\nPERMISSION:%s", 
        current_user, filename, permission);
    send_message(nm_socket, msg);
    char *response = receive_message(nm_socket);
    
    if (strstr(response, "ERROR_CODE:0")) {
        printf("Access request sent to file owner!\n");
    } else {
        char *error_msg = strstr(response, "ERROR_MSG:");
        if (error_msg) {
            printf("ERROR: %s\n", error_msg + 10);
        }
    }
}

void handle_viewrequests_command(const char *args) {
    char msg[MAX_BUFFER];
    if (args && strlen(args) > 0) {
        // View requests for specific file
        snprintf(msg, sizeof(msg), "TYPE:VIEWREQUESTS\nUSER:%s\nFILENAME:%s\n", 
            current_user, args);
    } else {
        // View all requests for user's files
        snprintf(msg, sizeof(msg), "TYPE:VIEWREQUESTS\nUSER:%s\n", current_user);
    }
    
    send_message(nm_socket, msg);
    char *response = receive_message(nm_socket);
    
    char *data = strstr(response, "DATA:");
    if (data) {
        // Skip "DATA:" and print everything until \n\n
        char *end = strstr(data, "\n\n");
        if (end) {
            *end = '\0';
        }
        printf("%s\n", data + 5);
    } else {
        char *error_msg = strstr(response, "ERROR_MSG:");
        if (error_msg) {
            printf("ERROR: %s\n", error_msg + 10);
        }
    }
}

void handle_approverequest_command(const char *args) {
    char filename[MAX_FILENAME], requester[MAX_USERNAME];
    sscanf(args, "%s %s", filename, requester);
    
    char msg[MAX_BUFFER];
    snprintf(msg, sizeof(msg), "TYPE:APPROVEREQUEST\nUSER:%s\nFILENAME:%s\nREQUESTER:%s", 
        current_user, filename, requester);
    send_message(nm_socket, msg);
    char *response = receive_message(nm_socket);
    
    if (strstr(response, "ERROR_CODE:0")) {
        printf("Request approved! Access granted.\n");
    } else {
        char *error_msg = strstr(response, "ERROR_MSG:");
        if (error_msg) {
            printf("ERROR: %s\n", error_msg + 10);
        }
    }
}

void handle_denyrequest_command(const char *args) {
    char filename[MAX_FILENAME], requester[MAX_USERNAME];
    sscanf(args, "%s %s", filename, requester);
    
    char msg[MAX_BUFFER];
    snprintf(msg, sizeof(msg), "TYPE:DENYREQUEST\nUSER:%s\nFILENAME:%s\nREQUESTER:%s", 
        current_user, filename, requester);
    send_message(nm_socket, msg);
    char *response = receive_message(nm_socket);
    
    if (strstr(response, "ERROR_CODE:0")) {
        printf("Request denied.\n");
    } else {
        char *error_msg = strstr(response, "ERROR_MSG:");
        if (error_msg) {
            printf("ERROR: %s\n", error_msg + 10);
        }
    }
}

// ======== END ACCESS REQUEST COMMANDS ========

// ======== FOLDER COMMANDS (BONUS FEATURE) ========

void handle_createfolder_command(const char *args) {
    char folder_path[MAX_PATH];
    sscanf(args, "%s", folder_path);
    
    char msg[MAX_BUFFER];
    snprintf(msg, sizeof(msg), "TYPE:CREATEFOLDER\nUSER:%s\nPATH:%s", 
        current_user, folder_path);
    send_message(nm_socket, msg);
    char *response = receive_message(nm_socket);
    
    if (strstr(response, "ERROR_CODE:0")) {
        printf("Folder created successfully!\n");
    } else {
        char *error_msg = strstr(response, "ERROR_MSG:");
        if (error_msg) {
            printf("ERROR: %s\n", error_msg + 10);
        }
    }
}

void handle_move_command(const char *args) {
    char filename[MAX_FILENAME], dest_folder[MAX_PATH];
    sscanf(args, "%s %s", filename, dest_folder);
    
    char msg[MAX_BUFFER];
    snprintf(msg, sizeof(msg), "TYPE:MOVE\nUSER:%s\nFILENAME:%s\nDEST:%s", 
        current_user, filename, dest_folder);
    send_message(nm_socket, msg);
    char *response = receive_message(nm_socket);
    
    if (strstr(response, "ERROR_CODE:0")) {
        printf("File moved successfully!\n");
    } else {
        char *error_msg = strstr(response, "ERROR_MSG:");
        if (error_msg) {
            printf("ERROR: %s\n", error_msg + 10);
        }
    }
}

void handle_viewfolder_command(const char *args) {
    char msg[MAX_BUFFER];
    if (args && strlen(args) > 0) {
        snprintf(msg, sizeof(msg), "TYPE:VIEWFOLDER\nUSER:%s\nPATH:%s\n", 
            current_user, args);
    } else {
        snprintf(msg, sizeof(msg), "TYPE:VIEWFOLDER\nUSER:%s\n", current_user);
    }
    // Ensure we're connected; if not, try to reconnect once
    if (!ensure_connected_to_nm()) {
        printf("ERROR: Not connected to Name Server\n");
        return;
    }

    send_message(nm_socket, msg);
    char *response = receive_message(nm_socket);
    if (!response) {
        // Try to reconnect once
        close(nm_socket);
        nm_socket = -1;
        if (!ensure_connected_to_nm()) {
            printf("ERROR: No response from Name Server\n");
            return;
        }
        send_message(nm_socket, msg);
        response = receive_message(nm_socket);
        if (!response) {
            printf("ERROR: No response from Name Server\n");
            return;
        }
    }

    char *data = strstr(response, "DATA:");
    if (data) {
        char *end = strstr(data, "\n\n");
        if (end) {
            *end = '\0';
        }
        printf("%s\n", data + 5);
    } else {
        char *error_msg = strstr(response, "ERROR_MSG:");
        if (error_msg) {
            printf("ERROR: %s\n", error_msg + 10);
        }
    }
    free(response);
}

// ======== END FOLDER COMMANDS ========

// ======== CHECKPOINT COMMANDS ========

void handle_checkpoint_command(const char *args) {
    char filename[MAX_FILENAME], tag[MAX_TAG_LENGTH] = "";
    
    // Parse: CHECKPOINT <filename> [tag]
    if (sscanf(args, "%s %[^\n]", filename, tag) < 1) {
        printf("Usage: CHECKPOINT <filename> [tag]\n");
        return;
    }
    
    char msg[MAX_BUFFER];
    if (strlen(tag) > 0) {
        snprintf(msg, sizeof(msg), "TYPE:CHECKPOINT\nUSER:%s\nFILENAME:%s\nTAG:%s\n", 
            current_user, filename, tag);
    } else {
        snprintf(msg, sizeof(msg), "TYPE:CHECKPOINT\nUSER:%s\nFILENAME:%s\nTAG:\n", 
            current_user, filename);
    }
    
    send_message(nm_socket, msg);
    char *response = receive_message(nm_socket);
    
    char *data = strstr(response, "DATA:");
    if (data) {
        printf("%s", data + 5);
    } else {
        char *error_msg = strstr(response, "ERROR_MSG:");
        if (error_msg) {
            printf("ERROR: %s\n", error_msg + 10);
        }
    }
}

void handle_listcheckpoints_command(const char *filename) {
    char msg[MAX_BUFFER];
    snprintf(msg, sizeof(msg), "TYPE:LISTCHECKPOINTS\nUSER:%s\nFILENAME:%s\n", 
        current_user, filename);
    
    send_message(nm_socket, msg);
    char *response = receive_message(nm_socket);
    
    char *data = strstr(response, "DATA:");
    if (data) {
        printf("%s", data + 5);
    } else {
        char *error_msg = strstr(response, "ERROR_MSG:");
        if (error_msg) {
            printf("ERROR: %s\n", error_msg + 10);
        }
    }
}

void handle_viewcheckpoint_command(const char *args) {
    char filename[MAX_FILENAME];
    char tag[MAX_TAG_LENGTH];
    
    if (sscanf(args, "%s %s", filename, tag) != 2) {
        printf("Usage: VIEWCHECKPOINT <filename> <tag>\n");
        return;
    }
    
    char msg[MAX_BUFFER];
    snprintf(msg, sizeof(msg), "TYPE:VIEWCHECKPOINT\nUSER:%s\nFILENAME:%s\nTAG:%s\n", 
        current_user, filename, tag);
    
    send_message(nm_socket, msg);
    char *response = receive_message(nm_socket);
    
    char *data = strstr(response, "DATA:");
    if (data) {
        printf("%s", data + 5);
    } else {
        char *error_msg = strstr(response, "ERROR_MSG:");
        if (error_msg) {
            printf("ERROR: %s\n", error_msg + 10);
        }
    }
}

void handle_revert_command(const char *args) {
    char filename[MAX_FILENAME];
    char tag[MAX_TAG_LENGTH];
    
    if (sscanf(args, "%s %s", filename, tag) != 2) {
        printf("Usage: REVERT <filename> <tag>\n");
        return;
    }
    
    char msg[MAX_BUFFER];
    snprintf(msg, sizeof(msg), "TYPE:REVERT\nUSER:%s\nFILENAME:%s\nTAG:%s\n", 
        current_user, filename, tag);
    
    send_message(nm_socket, msg);
    char *response = receive_message(nm_socket);
    
    char *data = strstr(response, "DATA:");
    if (data) {
        printf("%s", data + 5);
    } else {
        char *error_msg = strstr(response, "ERROR_MSG:");
        if (error_msg) {
            printf("ERROR: %s\n", error_msg + 10);
        }
    }
}

// ======== END CHECKPOINT COMMANDS ========

void handle_exec_command(const char *filename) {
    char msg[MAX_BUFFER];
    snprintf(msg, sizeof(msg), "TYPE:EXEC\nUSER:%s\nFILENAME:%s", current_user, filename);
    send_message(nm_socket, msg);
    char *response = receive_message(nm_socket);
    
    char *data = strstr(response, "DATA:");
    if (data) {
        printf("%s", data + 5);
    } else {
        char *error_msg = strstr(response, "ERROR_MSG:");
        if (error_msg) {
            printf("ERROR: %s\n", error_msg + 10);
        }
    }
}

void show_help(void) {
    printf("\n=== LangOS Commands ===\n");
    printf("CREATE <file>                - Create file\n");
    printf("READ <file>                  - Read file contents\n");
    printf("WRITE <file> <sentence_num>  - Write to file\n");
    printf("DELETE <file>                - Delete file\n");
    printf("UNDO <file>                  - Undo last change\n");
    printf("VIEW [-a|-l|-al]             - View files\n");
    printf("INFO <file>                  - File information\n");
    printf("STREAM <file>                - Stream file content\n");
    printf("LIST                         - List users\n");
    printf("ADDACCESS -R/-W <file> <user> - Grant access\n");
    printf("REMACCESS <file> <user>      - Remove access\n");
    printf("REQUESTACCESS [-R|-W] <file> - Request access to file\n");
    printf("VIEWREQUESTS [file]          - View pending requests\n");
    printf("APPROVEREQUEST <file> <user> - Approve access request\n");
    printf("DENYREQUEST <file> <user>    - Deny access request\n");
    printf("CREATEFOLDER <path>          - Create a folder\n");
    printf("MOVE <file> <folder>         - Move file to folder\n");
    printf("VIEWFOLDER [path]            - List folder contents\n");
    printf("CHECKPOINT <file> [tag]      - Save checkpoint\n");
    printf("LISTCHECKPOINTS <file>       - List all checkpoints\n");
    printf("VIEWCHECKPOINT <file> <ver>  - View checkpoint content\n");
    printf("REVERT <file> <version>      - Revert to checkpoint\n");
    printf("EXEC <file>                  - Execute file as shell commands\n");
    printf("EXIT                         - Quit\n\n");
}

int main(void) {
    // Ignore SIGPIPE so write/send to closed sockets don't kill the client
    signal(SIGPIPE, SIG_IGN);

    // Allow overriding Name Server host/port via environment variables
    char *env_nm_host = getenv("NM_HOST");
    char *env_nm_port = getenv("NM_PORT");
    if (env_nm_host) {
        strncpy(nm_host_global, env_nm_host, sizeof(nm_host_global)-1);
        nm_host_global[sizeof(nm_host_global)-1] = '\0';
    }
    if (env_nm_port) {
        nm_port_global = atoi(env_nm_port);
    }
    printf("=== LangOS Client ===\n");
    printf("Username: ");
    fgets(current_user, sizeof(current_user), stdin);
    current_user[strcspn(current_user, "\n")] = 0;
    
    if (strlen(current_user) == 0) {
        printf("Invalid username\n");
        return 1;
    }
    
    connect_to_nm();
    if (nm_socket < 0) {
        printf("Failed to connect to Name Server\n");
        return 1;
    }
    
    register_with_nm(current_user);
    
    printf("Connected to LangOS!\n");
    printf("Type HELP for commands\n\n");
    
    char input[MAX_BUFFER];
    while (1) {
        printf("$ ");
        fflush(stdout);
        
        if (!fgets(input, sizeof(input), stdin)) break;
        input[strcspn(input, "\n")] = 0;
        
        if (strlen(input) == 0) continue;
        
        char command[64] = "", args[MAX_BUFFER] = "";
        sscanf(input, "%s", command);
        
        // Extract args (everything after command)
        if (strlen(input) > strlen(command)) {
            strcpy(args, input + strlen(command) + 1);
        }
        
        if (strcmp(command, "EXIT") == 0) {
            break;
        } else if (strcmp(command, "HELP") == 0) {
            show_help();
        } else if (strcmp(command, "CREATE") == 0) {
            handle_create_command(args);
        } else if (strcmp(command, "READ") == 0) {
            handle_read_command(args);
        } else if (strcmp(command, "WRITE") == 0) {
            handle_write_command(args);
        } else if (strcmp(command, "DELETE") == 0) {
            handle_delete_command(args);
        } else if (strcmp(command, "UNDO") == 0) {
            handle_undo_command(args);
        } else if (strcmp(command, "VIEW") == 0) {
            handle_view_command(args);
        } else if (strcmp(command, "INFO") == 0) {
            handle_info_command(args);
        } else if (strcmp(command, "STREAM") == 0) {
            handle_stream_command(args);
        } else if (strcmp(command, "LISTCHECKPOINTS") == 0) {
            handle_listcheckpoints_command(args);
        } else if (strcmp(command, "LIST") == 0) {
            handle_list_command();
        } else if (strcmp(command, "ADDACCESS") == 0) {
            handle_addaccess_command(args);
        } else if (strcmp(command, "REMACCESS") == 0) {
            handle_remaccess_command(args);
        } else if (strcmp(command, "REQUESTACCESS") == 0) {
            handle_requestaccess_command(args);
        } else if (strcmp(command, "VIEWREQUESTS") == 0) {
            handle_viewrequests_command(args);
        } else if (strcmp(command, "APPROVEREQUEST") == 0) {
            handle_approverequest_command(args);
        } else if (strcmp(command, "DENYREQUEST") == 0) {
            handle_denyrequest_command(args);
        } else if (strcmp(command, "CREATEFOLDER") == 0) {
            handle_createfolder_command(args);
        } else if (strcmp(command, "MOVE") == 0) {
            handle_move_command(args);
        } else if (strcmp(command, "VIEWFOLDER") == 0) {
            handle_viewfolder_command(args);
        } else if (strcmp(command, "CHECKPOINT") == 0) {
            handle_checkpoint_command(args);
        } else if (strcmp(command, "VIEWCHECKPOINT") == 0) {
            handle_viewcheckpoint_command(args);
        } else if (strcmp(command, "REVERT") == 0) {
            handle_revert_command(args);
        } else if (strcmp(command, "EXEC") == 0) {
            handle_exec_command(args);
        } else {
            printf("Unknown command. Type HELP for list of commands.\n");
        }
    }
    
    close(nm_socket);
    printf("Goodbye!\n");
    return 0;
}
