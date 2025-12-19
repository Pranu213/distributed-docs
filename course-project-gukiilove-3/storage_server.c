// ...existing code...
#include "common.h"
#include <dirent.h>
#include <errno.h>
#include <signal.h>

// Ensure DT_REG is defined
#ifndef DT_REG
#define DT_REG 8
#endif

#define SS_CLIENT_PORT 9100
#define SERVER_ID 0  // Match Name Server's assignment (first SS = ID 0)

// Configurable network settings (defaults kept for backward compatibility)
char nm_host_global[64] = "127.0.0.1";
char ss_advertised_ip[64] = "127.0.0.1";
int nm_port_global = 8000;

void calculate_file_stats(const char *content, int *word_count, int *char_count, int *sentence_count);

StoredFile files[MAX_FILES];
int file_count = 0;
int nm_socket = -1;
pthread_mutex_t file_lock = PTHREAD_MUTEX_INITIALIZER;

void save_file(const char *filename) {
    // NOTE: Caller must hold file_lock
    for (int i = 0; i < file_count; i++) {
        if (strcmp(files[i].filename, filename) == 0) {
            // UNIQUE FACTOR: Calculate metadata first, then try to compress content before saving
            int word_count, char_count, sentence_count;
            calculate_file_stats(files[i].content, &word_count, &char_count, &sentence_count);
            files[i].metadata.word_count = word_count;
            files[i].metadata.char_count = char_count;
            files[i].metadata.sentence_count = sentence_count;
            files[i].metadata.size_bytes = strlen(files[i].content);

            // Now attempt compression
            size_t original_size = strlen(files[i].content);
            char *compressed_buffer = malloc(MAX_COMPRESSED_SIZE);
            size_t compressed_size = MAX_COMPRESSED_SIZE;
            
            if (compressed_buffer && original_size > 100 &&  // Only compress if > 100 bytes
                compress_data(files[i].content, original_size, compressed_buffer, &compressed_size) == 0 &&
                compressed_size < original_size * 0.9) {  // Only if saves at least 10%
                
                // Mark compressed on-disk but keep in-memory content unchanged
                files[i].compressed = 1;
                files[i].original_size = original_size;
                files[i].compressed_size = compressed_size;
                
                log_message("INFO", "File compressed: %s (%zu -> %zu bytes, %.1f%% savings)", 
                           filename, original_size, compressed_size, 
                           100.0 * (1.0 - (double)compressed_size / original_size));
                log_audit("system", "COMPRESS", filename, 
                         "compressed successfully", 1);
            } else {
                files[i].compressed = 0;
                files[i].original_size = original_size;
                files[i].compressed_size = original_size;
            }
            
            if (compressed_buffer) free(compressed_buffer);
            
            // Save to disk
            char path[512];
            snprintf(path, sizeof(path), "%s/%s", STORAGE_DIR, filename);
            FILE *f = fopen(path, "w");
            if (f) {
                // Calculate stats before saving and store in memory
                int word_count, char_count, sentence_count;
                calculate_file_stats(files[i].content, &word_count, &char_count, &sentence_count);
                files[i].metadata.word_count = word_count;
                files[i].metadata.char_count = char_count;
                files[i].metadata.sentence_count = sentence_count;
                files[i].metadata.size_bytes = strlen(files[i].content);
                // Keep metadata owner/filename and timestamps in sync
                strncpy(files[i].metadata.filename, files[i].filename, MAX_FILENAME);
                strncpy(files[i].metadata.owner, files[i].owner, MAX_USERNAME);
                strncpy(files[i].metadata.created, files[i].created, 64);
                strncpy(files[i].metadata.last_modified, files[i].last_modified, 64);
                fprintf(f, "OWNER:%s\nCREATED:%s\nLAST_MODIFIED:%s\n", 
                    files[i].owner, files[i].created, files[i].last_modified);
                fprintf(f, "COMPRESSED:%d\nORIG_SIZE:%zu\nCOMP_SIZE:%zu\n",
                    files[i].compressed, files[i].original_size, files[i].compressed_size);
                // Write metadata
                fprintf(f, "WORD_COUNT:%d\nCHAR_COUNT:%d\nSENTENCE_COUNT:%d\n", word_count, char_count, sentence_count);
                fprintf(f, "CONTENT:\n%s\n", files[i].content);
                fclose(f);
                log_message("INFO", "Saved %s to disk (words=%d, chars=%d, sentences=%d)", filename, word_count, char_count, sentence_count);
            }
            break;
        }
    }
}

void load_files() {
    DIR *dir = opendir(STORAGE_DIR);
    if (!dir) return;
    
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type == DT_REG && file_count < MAX_FILES) {
            char path[512];
            snprintf(path, sizeof(path), "%s/%s", STORAGE_DIR, entry->d_name);
            FILE *f = fopen(path, "r");
            if (f) {
                char line[MAX_BUFFER];
                char owner[MAX_USERNAME], created[64], last_modified[64];
                char content[MAX_BUFFER * 10] = "";
                int compressed = 0;
                size_t orig_size = 0, comp_size = 0;
                int md_word_count = 0, md_char_count = 0, md_sentence_count = 0;
                
                // Read metadata
                if (fgets(line, sizeof(line), f)) sscanf(line, "OWNER:%s", owner);
                if (fgets(line, sizeof(line), f)) sscanf(line, "CREATED:%s", created);
                if (fgets(line, sizeof(line), f)) sscanf(line, "LAST_MODIFIED:%s", last_modified);

                // Check for compression info (new format)
                if (fgets(line, sizeof(line), f)) {
                    if (sscanf(line, "COMPRESSED:%d", &compressed) == 1) {
                        // New format with compression
                        if (fgets(line, sizeof(line), f)) sscanf(line, "ORIG_SIZE:%zu", &orig_size);
                        if (fgets(line, sizeof(line), f)) sscanf(line, "COMP_SIZE:%zu", &comp_size);
                        // Read metadata if present
                        if (fgets(line, sizeof(line), f)) sscanf(line, "WORD_COUNT:%d", &md_word_count);
                        if (fgets(line, sizeof(line), f)) sscanf(line, "CHAR_COUNT:%d", &md_char_count);
                        if (fgets(line, sizeof(line), f)) sscanf(line, "SENTENCE_COUNT:%d", &md_sentence_count);
                        if (fgets(line, sizeof(line), f)) {} // Skip "CONTENT:" line
                        // Store metadata in struct if needed
                        // (You can add fields to StoredFile if you want to keep them)
                    } else {
                        // Old format without compression - line contains "CONTENT:"
                        compressed = 0;
                    }
                }

                // Read content
                while (fgets(line, sizeof(line), f)) {
                    strcat(content, line);
                }

                // Remove trailing newline
                if (strlen(content) > 0 && content[strlen(content)-1] == '\n') {
                    content[strlen(content)-1] = '\0';
                }

                // Store file
                strcpy(files[file_count].filename, entry->d_name);
                strcpy(files[file_count].owner, owner);
                strcpy(files[file_count].created, created);
                strcpy(files[file_count].last_modified, last_modified);
                strncpy(files[file_count].metadata.filename, entry->d_name, MAX_FILENAME);
                strncpy(files[file_count].metadata.owner, owner, MAX_USERNAME);
                strncpy(files[file_count].metadata.created, created, 64);
                strncpy(files[file_count].metadata.last_modified, last_modified, 64);
                strcpy(files[file_count].content, content);
                // If metadata lines were present (for compressed files) use them, otherwise recalculate
                int wc = 0, cc = 0, sc = 0;
                if (compressed) {
                    // If file is compressed, use the parsed metadata from the header if available
                    if (md_word_count || md_char_count || md_sentence_count) {
                        wc = md_word_count;
                        cc = md_char_count;
                        sc = md_sentence_count;
                    } else {
                        // Fallback: attempt to calculate (may be wrong for compressed)
                        calculate_file_stats(files[file_count].content, &wc, &cc, &sc);
                    }
                } else {
                    calculate_file_stats(files[file_count].content, &wc, &cc, &sc);
                }
                files[file_count].metadata.word_count = wc;
                files[file_count].metadata.char_count = cc;
                files[file_count].metadata.sentence_count = sc;
                files[file_count].metadata.size_bytes = strlen(files[file_count].content);
                files[file_count].metadata.size_bytes = strlen(files[file_count].content);
                files[file_count].locked = 0;
                files[file_count].undo_content = NULL;
                files[file_count].compressed = compressed;
                files[file_count].original_size = orig_size ? orig_size : strlen(content);
                files[file_count].compressed_size = comp_size ? comp_size : strlen(content);
                init_sentence_locks(files[file_count].sentence_locks, MAX_SENTENCES);

                log_message("INFO", "Loaded file: %s (words=%d, chars=%d, sentences=%d) %s", entry->d_name, wc, cc, sc, compressed ? "(compressed)" : "");

                file_count++;
                fclose(f);
            }
        }
    }
    closedir(dir);
}

void handle_create_file(int client_socket, const char *message) {
    char filename[MAX_FILENAME], username[MAX_USERNAME];
    sscanf(message, "TYPE:CREATE\nUSER:%s\nFILENAME:%s", username, filename);
    
    pthread_mutex_lock(&file_lock);
    
    for (int i = 0; i < file_count; i++) {
        if (strcmp(files[i].filename, filename) == 0) {
            char response[MAX_BUFFER];
            create_error_response(response, ERR_FILE_EXISTS, "File already exists");
            send_message(client_socket, response);
            pthread_mutex_unlock(&file_lock);
            return;
        }
    }
    
    if (file_count >= MAX_FILES) {
        char response[MAX_BUFFER];
        create_error_response(response, ERR_GENERAL, "Storage full");
        send_message(client_socket, response);
        pthread_mutex_unlock(&file_lock);
        return;
    }
    
    StoredFile *file = &files[file_count];
    strcpy(file->filename, filename);
    strcpy(file->owner, username);
    strcpy(file->created, get_timestamp());
    strcpy(file->last_modified, get_timestamp());
    file->content[0] = '\0';
    file->locked = 0;
    file->undo_content = NULL;
    file->compressed = 0;         // Not compressed initially
    file->original_size = 0;
    file->compressed_size = 0;
    init_sentence_locks(file->sentence_locks, MAX_SENTENCES);

    // Initialize metadata fields
    strncpy(file->metadata.filename, filename, MAX_FILENAME);
    strncpy(file->metadata.owner, username, MAX_USERNAME);
    strncpy(file->metadata.created, file->created, 64);
    strncpy(file->metadata.last_modified, file->last_modified, 64);
    file->metadata.word_count = 0;
    file->metadata.char_count = 0;
    file->metadata.sentence_count = 0;
    file->metadata.size_bytes = 0;

    file_count++;

    save_file(filename);
    log_message("INFO", "File created: %s by %s", filename, username);
    log_audit(username, "CREATE", filename, "file created", 1);  // Audit trail

    char response[MAX_BUFFER];
    create_response(response, ERR_SUCCESS, "File created");
    send_message(client_socket, response);

    pthread_mutex_unlock(&file_lock);
}

void handle_read_file(int client_socket, const char *message) {
    char filename[MAX_FILENAME];
    sscanf(message, "TYPE:READ\nFILENAME:%s", filename);
    
    pthread_mutex_lock(&file_lock);
    
    for (int i = 0; i < file_count; i++) {
        if (strcmp(files[i].filename, filename) == 0) {
            // Update last accessed metadata
            strncpy(files[i].metadata.last_accessed, get_timestamp(), 64);
            // Only update last_accessed_by if username is available
            char username[MAX_USERNAME] = "";
            char *user_ptr = strstr(message, "USER:");
            if (user_ptr) {
                sscanf(user_ptr, "USER:%s", username);
                strncpy(files[i].metadata.last_accessed_by, username, MAX_USERNAME);
            }
            // Persist last accessed info to disk
            save_file(filename);
            // Decompress if needed (transparent decompression - UNIQUE FACTOR)
            char *content_to_send = files[i].content;
            char *decompressed = NULL;
            
            if (files[i].compressed) {
                decompressed = malloc(MAX_BUFFER * 10);
                if (decompressed) {
                    size_t output_len = MAX_BUFFER * 10;
                    if (decompress_data(files[i].content, files[i].compressed_size, 
                                       decompressed, &output_len) == 0) {
                        decompressed[output_len] = '\0';
                        content_to_send = decompressed;
                        log_message("INFO", "File decompressed: %s (%zu -> %zu bytes)", 
                                   filename, files[i].compressed_size, output_len);
                    } else {
                        free(decompressed);
                        decompressed = NULL;
                    }
                }
            }
            
            // Dynamically allocate response to handle large file content safely
            size_t resp_size = strlen(content_to_send) + 100;
            char *response = malloc(resp_size);
            if (!response) {
                if (decompressed) free(decompressed);
                char err_resp[MAX_BUFFER];
                create_error_response(err_resp, ERR_GENERAL, "Memory allocation failed");
                send_message(client_socket, err_resp);
                pthread_mutex_unlock(&file_lock);
                log_audit("system", "READ", filename, "memory allocation failed", 0);
                return;
            }
            snprintf(response, resp_size, 
                "TYPE:response\nERROR_CODE:0\nDATA:%s", 
                content_to_send);
            send_message(client_socket, response);
            free(response);
            if (decompressed) free(decompressed);
            log_message("INFO", "File read: %s", filename);
            log_audit("system", "READ", filename, "file read successfully", 1);
            pthread_mutex_unlock(&file_lock);
            return;
        }
    }
    
    char response[MAX_BUFFER];
    create_error_response(response, ERR_FILE_NOT_FOUND, "File not found");
    send_message(client_socket, response);
    
    pthread_mutex_unlock(&file_lock);
}

// Helper function to calculate file statistics
void calculate_file_stats(const char *content, int *word_count, int *char_count, int *sentence_count) {
    *word_count = 0;
    *char_count = strlen(content);
    *sentence_count = 0;
    
    if (*char_count == 0) {
        return;  // Empty file
    }
    
    // Count words by splitting on whitespace
    int in_word = 0;
    for (const char *p = content; *p; p++) {
        if (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') {
            in_word = 0;
        } else {
            if (!in_word) {
                (*word_count)++;
                in_word = 1;
            }
        }
    }
    
    // Count sentences by looking for .!? delimiters
    for (const char *p = content; *p; p++) {
        if (*p == '.' || *p == '!' || *p == '?') {
            (*sentence_count)++;
        }
    }
    
    // If no sentence delimiters found but there are words, count as 1 sentence
    if (*sentence_count == 0 && *word_count > 0) {
        *sentence_count = 1;
    }
}

// Handler for GET_METADATA request from Name Server
void handle_get_metadata(int client_socket, const char *message) {
    char filename[MAX_FILENAME];
    sscanf(message, "TYPE:GET_METADATA\nFILENAME:%s", filename);
    pthread_mutex_lock(&file_lock);
    StoredFile *file = NULL;
    for (int i = 0; i < file_count; i++) {
        if (strcmp(files[i].filename, filename) == 0) {
            file = &files[i];
            break;
        }
    }
    char resp[MAX_BUFFER];
    if (file) {
        // Use stored metadata if available (persisted on save/load)
        snprintf(resp, sizeof(resp),
            "TYPE:METADATA\nFILENAME:%s\nWORD_COUNT:%d\nCHAR_COUNT:%d\nSENTENCE_COUNT:%d\nSIZE:%d\nLAST_ACCESSED:%s\nLAST_ACCESSED_BY:%s",
            filename, file->metadata.word_count, file->metadata.char_count, file->metadata.sentence_count, file->metadata.size_bytes,
            file->metadata.last_accessed, file->metadata.last_accessed_by);
    } else {
        snprintf(resp, sizeof(resp), "TYPE:METADATA\nFILENAME:%s\nWORD_COUNT:0\nCHAR_COUNT:0\nSENTENCE_COUNT:0\nSIZE:0\nLAST_ACCESSED:\nLAST_ACCESSED_BY:", filename);
    }
    send_message(client_socket, resp);
    pthread_mutex_unlock(&file_lock);
}

// Helper function to notify Name Server of file metadata updates
void update_nameserver_metadata(const char *filename) {
    // Find the file
    StoredFile *file = NULL;
    for (int i = 0; i < file_count; i++) {
        if (strcmp(files[i].filename, filename) == 0) {
            file = &files[i];
            break;
        }
    }
    
    if (!file) {
        log_message("WARNING", "Cannot send metadata update: file '%s' not found", filename);
        return;
    }
    
    // Use stored metadata if available; otherwise calculate
    int word_count = file->metadata.word_count;
    int char_count = file->metadata.char_count;
    int sentence_count = file->metadata.sentence_count;
    int size_bytes = file->metadata.size_bytes;
    if (word_count == 0 && char_count == 0 && sentence_count == 0) {
        calculate_file_stats(file->content, &word_count, &char_count, &sentence_count);
        size_bytes = strlen(file->content);
    }
    
    // Create a NEW socket connection for this metadata update
    // This ensures we always have a fresh, reliable connection
    int meta_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (meta_socket < 0) {
        log_message("ERROR", "Cannot create socket for metadata update");
        return;
    }
    
    struct sockaddr_in nm_addr_local;
    nm_addr_local.sin_family = AF_INET;
    nm_addr_local.sin_addr.s_addr = inet_addr(nm_host_global);
    nm_addr_local.sin_port = htons(nm_port_global);
    
    if (connect(meta_socket, (struct sockaddr *)&nm_addr_local, sizeof(nm_addr_local)) < 0) {
        log_message("ERROR", "Cannot connect to Name Server for metadata update %s:%d: %s", nm_host_global, nm_port_global, strerror(errno));
        close(meta_socket);
        return;
    }
    
    // Send update to Name Server
    char msg[MAX_BUFFER];
    snprintf(msg, sizeof(msg), 
        "TYPE:UPDATE_METADATA\nFILENAME:%s\nWORD_COUNT:%d\nCHAR_COUNT:%d\nSENTENCE_COUNT:%d\nSIZE:%d\nLAST_ACCESSED:%s\nLAST_ACCESSED_BY:%s",
        filename, word_count, char_count, sentence_count, size_bytes,
        file->metadata.last_accessed, file->metadata.last_accessed_by);
    
    send_message(meta_socket, msg);
    
    log_message("INFO", "Sent metadata update to NM: %s (words=%d, chars=%d, sentences=%d)",
                filename, word_count, char_count, sentence_count);
    
    // Close the socket after sending
    close(meta_socket);
}

void handle_write_session(int client_socket, const char *initial_message) {
    char filename[MAX_FILENAME];
    int sentence_num;
    sscanf(initial_message, "TYPE:WRITE\nFILENAME:%s\nSENTENCE:%d", filename, &sentence_num);
    
    pthread_mutex_lock(&file_lock);
    
    StoredFile *file = NULL;
    for (int i = 0; i < file_count; i++) {
        if (strcmp(files[i].filename, filename) == 0) {
            file = &files[i];
            break;
        }
    }
    
    if (!file) {
        char resp[MAX_BUFFER];
        create_error_response(resp, ERR_FILE_NOT_FOUND, "File not found");
        send_message(client_socket, resp);
        pthread_mutex_unlock(&file_lock);
        return;
    }
    
    // Parse current content
    FileContent parsed;
    parse_content(file->content, &parsed);
    
    // Only allow appending a new sentence if previous ends with delimiter
    if (sentence_num < 0 || sentence_num > parsed.sentence_count ||
        (sentence_num == parsed.sentence_count && parsed.sentence_count > 0)) {
        // If trying to append a new sentence, check delimiter
        if (sentence_num == parsed.sentence_count && parsed.sentence_count > 0) {
            Sentence *prev = &parsed.sentences[parsed.sentence_count - 1];
            int last_word_ok = 0;
            if (prev->word_count > 0) {
                char *last_word = prev->words[prev->word_count - 1];
                int len = strlen(last_word);
                if (len > 0) {
                    char last_char = last_word[len - 1];
                    if (last_char == '.' || last_char == '!' || last_char == '?') {
                        last_word_ok = 1;
                    }
                }
            }
            if (!last_word_ok) {
                char resp[MAX_BUFFER];
                create_error_response(resp, ERR_INVALID_INDEX, "Sentence index out of range");
                send_message(client_socket, resp);
                free_parsed(&parsed);
                pthread_mutex_unlock(&file_lock);
                return;
            }
        } else {
            char resp[MAX_BUFFER];
            create_error_response(resp, ERR_INVALID_INDEX, "Sentence index out of range");
            send_message(client_socket, resp);
            free_parsed(&parsed);
            pthread_mutex_unlock(&file_lock);
            return;
        }
    }
    
    free_parsed(&parsed);
    
    // Validate sentence number to avoid out-of-bounds access
    if (sentence_num < 0 || sentence_num >= MAX_SENTENCES) {
        char resp[MAX_BUFFER];
        create_error_response(resp, ERR_INVALID_INDEX, "Sentence index out of range");
        send_message(client_socket, resp);
        pthread_mutex_unlock(&file_lock);
        return;
    }

    // Lock sentence
    if (pthread_mutex_trylock(&file->sentence_locks[sentence_num]) != 0) {
        char resp[MAX_BUFFER];
        create_error_response(resp, ERR_FILE_LOCKED, "Sentence locked by another user");
        send_message(client_socket, resp);
        pthread_mutex_unlock(&file_lock);
        return;
    }
    
    // Save undo
    if (file->undo_content != NULL) {
        free(file->undo_content);
    }
    file->undo_content = malloc(strlen(file->content) + 1);
    strcpy(file->undo_content, file->content);
    
    // Send acknowledgment that write session started
    char ack[MAX_BUFFER];
    create_response(ack, ERR_SUCCESS, "Write session started");
    send_message(client_socket, ack);
    
    // Unlock file_lock to allow other operations
    pthread_mutex_unlock(&file_lock);
    
    // Loop for word updates
    char *msg;
    while (1) {
        msg = receive_message(client_socket);
            // Handle real disconnect or timeout
            if (!msg) {
                log_message("INFO", "Write session ended: client disconnected or timed out");
                break;
            }

            // Ignore empty packets
            if (msg[0] == '\0') {
                free(msg);
                continue;
            }

            if (strncmp(msg, "TYPE:ETIRW", 10) == 0) {
                free(msg);
                break;
            }
        
        int word_idx;
        char new_word[MAX_BUFFER];
        sscanf(msg, "WORD_INDEX:%d\nCONTENT:%[^\n]", &word_idx, new_word);
        free(msg);
        
        // Enforce 0-based indexing for all word operations
        // Reject negative indexes explicitly.
        if (word_idx < 0) {
            char resp[MAX_BUFFER];
            create_error_response(resp, ERR_INVALID_INDEX, "Word index must be >= 0");
            send_message(client_socket, resp);
            continue;
        }
        int adjusted_word_idx = word_idx; // word_idx is already 0-based from client
        log_message("DEBUG", "WRITE word_idx=%d (0-based) content='%s' to sentence %d", 
                    word_idx, new_word, sentence_num);
        
        // Re-parse with current content
        pthread_mutex_lock(&file_lock);
        parse_content(file->content, &parsed);
        log_message("DEBUG", "After parse: %d sentences, sentence[0] has %d words", 
                    parsed.sentence_count, parsed.sentence_count > 0 ? parsed.sentences[0].word_count : 0);
        
        if (sentence_num == parsed.sentence_count) {
            if (sentence_num >= MAX_SENTENCES) {
                char resp[MAX_BUFFER];
                create_error_response(resp, ERR_GENERAL, "Too many sentences");
                send_message(client_socket, resp);
                free_parsed(&parsed);
                pthread_mutex_unlock(&file_lock);
                continue;
            }
            Sentence *new_sentence_entry = &parsed.sentences[parsed.sentence_count];
            new_sentence_entry->word_count = 0;
            new_sentence_entry->words = malloc(MAX_WORDS * sizeof(char*));
            new_sentence_entry->delimiter = '\0';
            parsed.sentence_count++;
        }

        // Word-level writes: The challenge is that words with delimiters create new
        // sentences when reparsed. To handle sequential word writes (0,1,2...) to the
        // same sentence_num, we treat them as absolute positions in a single logical
        // sentence being built.
        //
        // Strategy: If word_idx matches the TOTAL word count across all sentences,
        // append as a new sentence. Otherwise, validate normally.
        
        int total_words = 0;
        for (int i = 0; i < parsed.sentence_count; i++) {
            total_words += parsed.sentences[i].word_count;
        }
        
        // If word_idx matches total words AND the client is targeting the
        // next-new sentence (sentence_num == parsed.sentence_count), create
        // a new sentence and append. This avoids accidentally creating a new
        // sentence when the client intended to edit an existing one.
        if (word_idx == total_words && sentence_num == parsed.sentence_count) {
            if (parsed.sentence_count < MAX_SENTENCES) {
                int new_idx = parsed.sentence_count;
                parsed.sentences[new_idx].word_count = 0;
                parsed.sentences[new_idx].words = malloc(MAX_WORDS * sizeof(char*));
                parsed.sentences[new_idx].words[0] = strdup(new_word);
                parsed.sentences[new_idx].word_count = 1;
                parsed.sentences[new_idx].delimiter = '\0';
                parsed.sentence_count++;
                // Don't do the normal add/replace logic below
                word_idx = -1; // Flag to skip normal logic
            }
        }
        
        if (word_idx >= 0) {
            // Normal path: validate sentence exists
            if (sentence_num >= parsed.sentence_count) {
                char resp[MAX_BUFFER];
                create_error_response(resp, ERR_INVALID_INDEX, "Invalid sentence index");
                send_message(client_socket, resp);
                free_parsed(&parsed);
                pthread_mutex_unlock(&file_lock);
                continue;
            }

            Sentence *sent = &parsed.sentences[sentence_num];

            // If the sentence is empty (no words yet), accept any non-negative
            // index as a valid insertion point. Otherwise enforce 0..word_count.
            if (sent->word_count > 0) {
                if (adjusted_word_idx < 0 || adjusted_word_idx > sent->word_count) {
                    char resp[MAX_BUFFER];
                    create_error_response(resp, ERR_INVALID_INDEX, "Invalid word index");
                    send_message(client_socket, resp);
                    free_parsed(&parsed);
                    pthread_mutex_unlock(&file_lock);
                    continue;
                }
            } else {
                // Empty sentence: only reject negative indexes (already handled).
                // Treat indices larger than 0 as append positions; we will
                // normalize insert_idx below to be within [0..word_count].
            }

            if (sent->word_count >= MAX_WORDS) {
                char resp[MAX_BUFFER];
                create_error_response(resp, ERR_GENERAL, "Too many words in sentence");
                send_message(client_socket, resp);
                free_parsed(&parsed);
                pthread_mutex_unlock(&file_lock);
                continue;
            }

            // Insert at the specified position (client uses 1-based index):
            // place new tokens before the Nth word where N = word_idx.
            // This ensures inserting at index 4 inserts before the 4th word
            // instead of after the 4th word (which could place tokens after
            // a sentence delimiter).
            int insert_idx = adjusted_word_idx;
            if (insert_idx < 0) insert_idx = 0;
            if (insert_idx > sent->word_count) insert_idx = sent->word_count;

            // Support multi-word content: split new_word by whitespace and
            // insert each token as a separate word, preserving order.
            char tmp[MAX_BUFFER];
            strncpy(tmp, new_word, sizeof(tmp));
            tmp[sizeof(tmp)-1] = '\0';
            char *tok = NULL;
            char *saveptr = NULL;
            int tok_count = 0;
            char *token_list[MAX_WORDS];
            tok = strtok_r(tmp, " \t\n", &saveptr);
            while (tok && tok_count < MAX_WORDS) {
                token_list[tok_count++] = tok;
                tok = strtok_r(NULL, " \t\n", &saveptr);
            }

            if (tok_count == 0) {
                // Nothing to insert
                char resp[MAX_BUFFER];
                create_error_response(resp, ERR_GENERAL, "No content to insert");
                send_message(client_socket, resp);
                free_parsed(&parsed);
                pthread_mutex_unlock(&file_lock);
                continue;
            }

            if (sent->word_count + tok_count > MAX_WORDS) {
                char resp[MAX_BUFFER];
                create_error_response(resp, ERR_GENERAL, "Too many words in sentence");
                send_message(client_socket, resp);
                free_parsed(&parsed);
                pthread_mutex_unlock(&file_lock);
                continue;
            }

            // Shift existing words to the right to make space for all tokens
            for (int i = sent->word_count - 1; i >= insert_idx; i--) {
                sent->words[i + tok_count] = sent->words[i];
            }

            // Insert each token
            for (int t = 0; t < tok_count; t++) {
                sent->words[insert_idx + t] = strdup(token_list[t]);
            }
            sent->word_count += tok_count;
        }
        
        // Rebuild full content from all sentences
        char new_content[MAX_BUFFER * 10] = "";
        size_t content_len = 0;
        for (int s = 0; s < parsed.sentence_count; s++) {
            for (int w = 0; w < parsed.sentences[s].word_count; w++) {
                size_t word_len = strlen(parsed.sentences[s].words[w]);
                if (content_len + word_len + 2 >= sizeof(new_content)) {
                    // Buffer full - stop adding
                    log_message("ERROR", "WRITE: Content too large, truncating");
                    break;
                }
                strcat(new_content, parsed.sentences[s].words[w]);
                content_len += word_len;
                if (w < parsed.sentences[s].word_count - 1) {
                    strcat(new_content, " ");
                    content_len++;
                }
            }
            // Don't add delimiter if last word already ends with one
            int needs_delimiter = 1;
            if (parsed.sentences[s].word_count > 0) {
                char *last_word = parsed.sentences[s].words[parsed.sentences[s].word_count - 1];
                int len = strlen(last_word);
                if (len > 0) {
                    char last_char = last_word[len - 1];
                    if (last_char == '.' || last_char == '!' || last_char == '?') {
                        needs_delimiter = 0;
                    }
                }
            }
            if (needs_delimiter && parsed.sentences[s].delimiter) {
                if (content_len + 1 < sizeof(new_content)) {
                    char delim[2] = {parsed.sentences[s].delimiter, '\0'};
                    strcat(new_content, delim);
                    content_len++;
                }
            }
            if (s < parsed.sentence_count - 1) {
                if (content_len + 1 < sizeof(new_content)) {
                    strcat(new_content, " ");
                    content_len++;
                }
            }
        }
        
        strcpy(file->content, new_content);
        free_parsed(&parsed);
        
        char resp[MAX_BUFFER];
        create_response(resp, ERR_SUCCESS, "Word updated");
        send_message(client_socket, resp);
        pthread_mutex_unlock(&file_lock);
    }
    
    // Finalize write
    pthread_mutex_lock(&file_lock);
    strncpy(file->last_modified, get_timestamp(), 64);
    strncpy(file->metadata.last_modified, file->last_modified, 64);
    save_file(filename);

    // Update Name Server with new metadata
    update_nameserver_metadata(filename);

    // Small delay to ensure metadata reaches Name Server before client continues
    usleep(10000); // 10ms delay

    log_message("INFO", "File written: %s", filename);
    log_audit("SYSTEM", "WRITE", filename, "file content updated", 1);

    char resp[MAX_BUFFER];
    create_response(resp, ERR_SUCCESS, "Write successful");
    send_message(client_socket, resp);

    pthread_mutex_unlock(&file->sentence_locks[sentence_num]);
    pthread_mutex_unlock(&file_lock);
}

void handle_delete_file(int client_socket, const char *message) {
    char filename[MAX_FILENAME], username[MAX_USERNAME] = "";
    // Try both formats for compatibility
    if (sscanf(message, "TYPE:DELETE\nUSER:%s\nFILENAME:%s", username, filename) < 2) {
        sscanf(message, "TYPE:DELETE\nFILENAME:%s", filename);
    }
    
    pthread_mutex_lock(&file_lock);
    
    for (int i = 0; i < file_count; i++) {
        if (strcmp(files[i].filename, filename) == 0) {
            if (files[i].undo_content != NULL) {
                free(files[i].undo_content);
            }
            
            // Delete from disk
            char path[512];
            snprintf(path, sizeof(path), "%s/%s", STORAGE_DIR, filename);
            remove(path);
            
            // Remove from array
            for (int j = i; j < file_count - 1; j++) {
                files[j] = files[j + 1];
            }
            file_count--;
            
            log_message("INFO", "File deleted: %s", filename);
            log_audit("SYSTEM", "DELETE", filename, "file deleted from storage", 1);
            
            char response[MAX_BUFFER];
            create_response(response, ERR_SUCCESS, "File deleted");
            send_message(client_socket, response);
            
            pthread_mutex_unlock(&file_lock);
            return;
        }
    }
    
    char response[MAX_BUFFER];
    create_error_response(response, ERR_FILE_NOT_FOUND, "File not found");
    send_message(client_socket, response);
    
    pthread_mutex_unlock(&file_lock);
}

void handle_undo_file(int client_socket, const char *message) {
    char filename[MAX_FILENAME];
    sscanf(message, "TYPE:UNDO\nFILENAME:%s", filename);
    
    pthread_mutex_lock(&file_lock);
    
    for (int i = 0; i < file_count; i++) {
        if (strcmp(files[i].filename, filename) == 0) {
            if (files[i].undo_content == NULL) {
                char response[MAX_BUFFER];
                create_error_response(response, ERR_GENERAL, "No undo history");
                send_message(client_socket, response);
                pthread_mutex_unlock(&file_lock);
                return;
            }
            
            strcpy(files[i].content, files[i].undo_content);
            free(files[i].undo_content);
            files[i].undo_content = NULL;
            
            save_file(filename);
            log_message("INFO", "File undone: %s", filename);
            
            char response[MAX_BUFFER];
            create_response(response, ERR_SUCCESS, "Undo successful");
            send_message(client_socket, response);
            
            pthread_mutex_unlock(&file_lock);
            return;
        }
    }
    
    char response[MAX_BUFFER];
    create_error_response(response, ERR_FILE_NOT_FOUND, "File not found");
    send_message(client_socket, response);
    
    pthread_mutex_unlock(&file_lock);
}

void handle_stream_file(int client_socket, const char *message) {
    char filename[MAX_FILENAME];
    sscanf(message, "TYPE:STREAM\nFILENAME:%s", filename);
    
    pthread_mutex_lock(&file_lock);
    
    for (int i = 0; i < file_count; i++) {
        if (strcmp(files[i].filename, filename) == 0) {
            FileContent parsed;
            parse_content(files[i].content, &parsed);
            
            // Stream word by word
            for (int s = 0; s < parsed.sentence_count; s++) {
                for (int w = 0; w < parsed.sentences[s].word_count; w++) {
                    char response[MAX_BUFFER];
                    snprintf(response, sizeof(response), "TYPE:stream_word\nDATA:%s", 
                        parsed.sentences[s].words[w]);
                    send_message(client_socket, response);
                    usleep(100000); // 0.1 second delay
                }
                if (parsed.sentences[s].delimiter) {
                    char response[MAX_BUFFER];
                    char delim[2] = {parsed.sentences[s].delimiter, '\0'};
                    snprintf(response, sizeof(response), "TYPE:stream_word\nDATA:%s", delim);
                    send_message(client_socket, response);
                    usleep(100000);
                }
            }
            
            // Send end marker
            char end[MAX_BUFFER];
            snprintf(end, sizeof(end), "TYPE:stream_end\nDATA:");
            send_message(client_socket, end);
            
            free_parsed(&parsed);
            log_message("INFO", "File streamed: %s", filename);
            pthread_mutex_unlock(&file_lock);
            return;
        }
    }
    
    char response[MAX_BUFFER];
    create_error_response(response, ERR_FILE_NOT_FOUND, "File not found");
    send_message(client_socket, response);
    
    pthread_mutex_unlock(&file_lock);
}

// ======== FOLDER HANDLERS (BONUS FEATURE) ========

void handle_createfolder(int client_socket, const char *message) {
    char path[MAX_PATH];
    sscanf(message, "TYPE:CREATEFOLDER\nPATH:%s", path);
    
    log_message("INFO", "CREATEFOLDER request received for path: %s", path);
    
    // Create physical directory
    char full_path[MAX_PATH];
    snprintf(full_path, sizeof(full_path), "%s/%s", STORAGE_DIR, path);
    
    // Create directory with parents
    char temp_path[MAX_PATH];
    strncpy(temp_path, full_path, MAX_PATH);
    
    // Create parent directories
    for (char *p = temp_path + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            if (mkdir(temp_path, 0755) != 0 && errno != EEXIST) {
                log_message("ERROR", "Failed to create parent dir %s: %s", temp_path, strerror(errno));
            }
            *p = '/';
        }
    }
    
    // Create final directory
    if (mkdir(temp_path, 0755) != 0 && errno != EEXIST) {
        log_message("ERROR", "Failed to create folder %s: %s", temp_path, strerror(errno));
        char response[MAX_BUFFER];
        create_error_response(response, ERR_GENERAL, "Failed to create physical folder");
        send_message(client_socket, response);
        return;
    }
    
    log_message("INFO", "Folder created: %s (physical: %s)", path, temp_path);
    
    char response[MAX_BUFFER];
    create_response(response, ERR_SUCCESS, "Folder created on storage");
    send_message(client_socket, response);
}

void handle_move_file(int client_socket, const char *message) {
    char filename[MAX_FILENAME] = "", src_folder[MAX_PATH] = "", dest_folder[MAX_PATH] = "";
    
    // Parse message line by line using newline delimiter
    char *msg_copy = strdup(message);
    if (!msg_copy) {
        char response[MAX_BUFFER];
        create_error_response(response, ERR_GENERAL, "Memory allocation failed");
        send_message(client_socket, response);
        return;
    }
    char *line = strtok(msg_copy, "\n");

    while (line != NULL) {
        if (strncmp(line, "FILENAME:", 9) == 0) {
            strncpy(filename, line + 9, MAX_FILENAME - 1);
            filename[MAX_FILENAME - 1] = '\0';
        } else if (strncmp(line, "SRC:", 4) == 0) {
            if (strlen(line) > 4) {  // Has content after SRC:
                strncpy(src_folder, line + 4, MAX_PATH - 1);
                src_folder[MAX_PATH - 1] = '\0';
            }
        } else if (strncmp(line, "DEST:", 5) == 0) {
            if (strlen(line) > 5) {  // Has content after DEST:
                strncpy(dest_folder, line + 5, MAX_PATH - 1);
                dest_folder[MAX_PATH - 1] = '\0';
            }
        }
        line = strtok(NULL, "\n");
    }
    free(msg_copy);
    
    pthread_mutex_lock(&file_lock);
    
    // Build source and destination paths
    char src_path[MAX_PATH], dest_path[MAX_PATH];
    if (strlen(src_folder) > 0) {
        snprintf(src_path, sizeof(src_path), "%s/%s/%s", STORAGE_DIR, src_folder, filename);
    } else {
        snprintf(src_path, sizeof(src_path), "%s/%s", STORAGE_DIR, filename);
    }
    
    if (strlen(dest_folder) > 0) {
        snprintf(dest_path, sizeof(dest_path), "%s/%s/%s", STORAGE_DIR, dest_folder, filename);
        
        // Ensure destination folder exists
        char dest_dir[MAX_PATH];
        snprintf(dest_dir, sizeof(dest_dir), "%s/%s", STORAGE_DIR, dest_folder);
        
        // Create destination directory if it doesn't exist
        char temp_path[MAX_PATH];
        strncpy(temp_path, dest_dir, MAX_PATH);
        for (char *p = temp_path + 1; *p; p++) {
            if (*p == '/') {
                *p = '\0';
                mkdir(temp_path, 0755);
                *p = '/';
            }
        }
        mkdir(temp_path, 0755);
    } else {
        snprintf(dest_path, sizeof(dest_path), "%s/%s", STORAGE_DIR, filename);
    }
    
    // Check if source file exists
    if (access(src_path, F_OK) != 0) {
        char response[MAX_BUFFER];
        snprintf(response, sizeof(response), 
            "TYPE:response\nERROR_CODE:%d\nERROR_MSG:Source file not found at %s\n\n", 
            ERR_FILE_NOT_FOUND, src_path);
        send_message(client_socket, response);
        log_message("ERROR", "Move failed: source not found %s", src_path);
        pthread_mutex_unlock(&file_lock);
        return;
    }
    
    // Move the file
    if (rename(src_path, dest_path) != 0) {
        char response[MAX_BUFFER];
        snprintf(response, sizeof(response),
            "TYPE:response\nERROR_CODE:%d\nERROR_MSG:Failed to move file: %s\n\n",
            ERR_GENERAL, strerror(errno));
        send_message(client_socket, response);
        log_message("ERROR", "rename() failed: %s -> %s: %s", src_path, dest_path, strerror(errno));
        pthread_mutex_unlock(&file_lock);
        return;
    }
    
    log_message("INFO", "File moved: %s from '%s' to '%s' (%s -> %s)", 
        filename, src_folder, dest_folder, src_path, dest_path);
    
    char response[MAX_BUFFER];
    create_response(response, ERR_SUCCESS, "File moved on storage");
    send_message(client_socket, response);
    
    pthread_mutex_unlock(&file_lock);
}

// ======== CHECKPOINT HANDLER ========

void handle_revert(int client_socket, const char *message) {
    char filename[MAX_FILENAME], content[MAX_CHECKPOINT_CONTENT];
    
    // Parse message
    const char *filename_marker = strstr(message, "FILENAME:");
    const char *content_marker = strstr(message, "CONTENT:");
    
    if (!filename_marker || !content_marker) {
        char response[MAX_BUFFER];
        create_error_response(response, ERR_GENERAL, "Invalid revert message format");
        send_message(client_socket, response);
        return;
    }
    
    sscanf(filename_marker, "FILENAME:%s", filename);
    strncpy(content, content_marker + 8, MAX_CHECKPOINT_CONTENT - 1);
    content[MAX_CHECKPOINT_CONTENT - 1] = '\0';
    
    pthread_mutex_lock(&file_lock);
    
    // Find file
    int found = 0;
    for (int i = 0; i < file_count; i++) {
        if (strcmp(files[i].filename, filename) == 0) {
            // Replace content
            strncpy(files[i].content, content, sizeof(files[i].content) - 1);
            files[i].content[sizeof(files[i].content) - 1] = '\0';
            
            // Save to disk
            save_file(filename);
            
            found = 1;
            log_message("INFO", "File reverted: %s", filename);
            break;
        }
    }
    
    pthread_mutex_unlock(&file_lock);
    
    if (!found) {
        char response[MAX_BUFFER];
        create_error_response(response, ERR_FILE_NOT_FOUND, "File not found");
        send_message(client_socket, response);
        return;
    }
    
    char response[MAX_BUFFER];
    create_response(response, ERR_SUCCESS, "File reverted on storage");
    send_message(client_socket, response);
}

// ======== END FOLDER HANDLERS ========

void* client_thread(void *arg) {
    int client_socket = (intptr_t)arg;
    char *message;

    while (1) {
        message = receive_message(client_socket);

        // ---- FIX 1: Handle NULL safely (real disconnect) ----
        if (!message) {
            break;
        }

        // ---- FIX 2: Ignore empty packets instead of closing ----
        if (message[0] == '\0') {
            free(message);
            continue;
        }

        // ---- REQUEST ROUTING ----
        if (strncmp(message, "TYPE:CREATE", 11) == 0) {
            handle_create_file(client_socket, message);

        } else if (strncmp(message, "TYPE:READ", 9) == 0) {
            handle_read_file(client_socket, message);

        } else if (strncmp(message, "TYPE:WRITE", 10) == 0) {
            handle_write_session(client_socket, message);

        } else if (strncmp(message, "TYPE:DELETE", 11) == 0) {
            handle_delete_file(client_socket, message);

        } else if (strncmp(message, "TYPE:UNDO", 9) == 0) {
            handle_undo_file(client_socket, message);

        } else if (strncmp(message, "TYPE:STREAM", 11) == 0) {
            handle_stream_file(client_socket, message);

        } else if (strncmp(message, "TYPE:CREATEFOLDER", 17) == 0) {
            handle_createfolder(client_socket, message);

        } else if (strncmp(message, "TYPE:MOVE", 9) == 0) {
            handle_move_file(client_socket, message);

        } else if (strncmp(message, "TYPE:REVERT", 11) == 0) {
            handle_revert(client_socket, message);
        } else if (strncmp(message, "TYPE:GET_METADATA", 17) == 0) {
            handle_get_metadata(client_socket, message);
        }
    }

    close(client_socket);
    return NULL;
}


int main(int argc, char *argv[]) {
    int server_socket;
    struct sockaddr_in server_addr, nm_addr;
    int opt = 1;
    int ss_nm_port = 8000;
    int ss_client_port = SS_CLIENT_PORT;

    // Ignore SIGPIPE to prevent crashes when sending to closed sockets
    signal(SIGPIPE, SIG_IGN);

    // Prefer environment variables if set
    char *env_client_port = getenv("CLIENT_PORT");
    char *env_nm_port = getenv("NM_PORT");
    char *env_nm_host = getenv("NM_HOST");
    char *env_ss_host = getenv("SS_HOST");
    if (env_client_port) {
        ss_client_port = atoi(env_client_port);
    }
    if (env_nm_port) {
        ss_nm_port = atoi(env_nm_port);
    }
    if (env_nm_host) {
        strncpy(nm_host_global, env_nm_host, sizeof(nm_host_global)-1);
        nm_host_global[sizeof(nm_host_global)-1] = '\0';
    }
    if (env_ss_host) {
        strncpy(ss_advertised_ip, env_ss_host, sizeof(ss_advertised_ip)-1);
        ss_advertised_ip[sizeof(ss_advertised_ip)-1] = '\0';
    }

    // Parse command-line arguments for port/hosts if env not set
    // Usage: storage_server [client_port] [nm_port] [nm_host] [ss_host]
    if (!env_client_port && argc > 1) {
        ss_client_port = atoi(argv[1]);
        if (ss_client_port <= 0 || ss_client_port > 65535) {
            fprintf(stderr, "ERROR: Invalid port number '%s'. Port must be between 1-65535.\n", argv[1]);
            fprintf(stderr, "Usage: %s [client_port] [nm_port] [nm_host] [ss_host]\n", argv[0]);
            fprintf(stderr, "Example: %s 9100 8000 127.0.0.1 127.0.0.1\n", argv[0]);
            exit(1);
        }
    }

    if (!env_nm_port && argc > 2) {
        ss_nm_port = atoi(argv[2]);
        if (ss_nm_port <= 0 || ss_nm_port > 65535) {
            fprintf(stderr, "ERROR: Invalid NM port number '%s'. Port must be between 1-65535.\n", argv[2]);
            exit(1);
        }
    }

    if (argc > 3 && !env_nm_host) {
        strncpy(nm_host_global, argv[3], sizeof(nm_host_global)-1);
        nm_host_global[sizeof(nm_host_global)-1] = '\0';
    }

    if (argc > 4 && !env_ss_host) {
        strncpy(ss_advertised_ip, argv[4], sizeof(ss_advertised_ip)-1);
        ss_advertised_ip[sizeof(ss_advertised_ip)-1] = '\0';
    }
    
    fprintf(stdout, "Starting Storage Server with CLIENT_PORT=%d, NM_PORT=%d, NM_HOST=%s, SS_HOST=%s\n",
        ss_client_port, ss_nm_port, nm_host_global, ss_advertised_ip);
    
    system("mkdir -p storage/files");
    system("mkdir -p logs");
    
    open_log("ss");
    init_audit_log();  // Initialize audit trail (UNIQUE FACTOR)
    log_message("INFO", "Starting Storage Server");
    log_audit("system", "STARTUP", NULL, "Storage Server starting", 1);
    
    // Load existing files
    load_files();
    
    // Set the effective NM port from parsed options and connect to Name Server
    nm_port_global = ss_nm_port;

    // Connect to Name Server
    nm_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (nm_socket < 0) {
        log_message("ERROR", "Cannot create socket");
        exit(1);
    }
    
    nm_addr.sin_family = AF_INET;
    nm_addr.sin_addr.s_addr = inet_addr(nm_host_global);
    nm_addr.sin_port = htons(nm_port_global);

    if (connect(nm_socket, (struct sockaddr *)&nm_addr, sizeof(nm_addr)) < 0) {
        log_message("ERROR", "Cannot connect to Name Server %s:%d : %s", nm_host_global, nm_port_global, strerror(errno));
        fprintf(stderr, "ERROR: Cannot connect to Name Server at %s:%d: %s\n", nm_host_global, nm_port_global, strerror(errno));
        fprintf(stderr, "       Make sure the Name Server is running first.\n");
        close(nm_socket);
        exit(1);
    }
    
    // Register with Name Server
    char reg_msg[MAX_BUFFER];
    snprintf(reg_msg, sizeof(reg_msg), "TYPE:REGISTER_SS\nIP:%s\nNM_PORT:%d\nCLIENT_PORT:%d",
        ss_advertised_ip, ss_nm_port, ss_client_port);
    send_message(nm_socket, reg_msg);
    char *tmp_response = receive_message(nm_socket);
    if (tmp_response) free(tmp_response);
    
    log_message("INFO", "Registered with Name Server");
    
    // Announce existing files to Name Server (for persistence after restart)
    DIR *dir = opendir(STORAGE_DIR);
    if (dir) {
        struct dirent *entry;
        while ((entry = readdir(dir)) != NULL) {
            if (entry->d_type == DT_REG && strstr(entry->d_name, ".txt")) {
                // Read metadata from file to get owner
                char filepath[512];
                snprintf(filepath, sizeof(filepath), "%s/%s", STORAGE_DIR, entry->d_name);
                FILE *f = fopen(filepath, "r");
                if (f) {
                    char line[256];
                    char owner[MAX_USERNAME] = "unknown";
                    
                    // Parse metadata header
                    while (fgets(line, sizeof(line), f)) {
                        if (strncmp(line, "OWNER:", 6) == 0) {
                            sscanf(line, "OWNER:%s", owner);
                        }
                        if (strncmp(line, "CONTENT:", 8) == 0) {
                            break;  // End of metadata
                        }
                    }
                    fclose(f);
                    
                    // Announce file to Name Server
                    char announce_msg[MAX_BUFFER];
                    snprintf(announce_msg, sizeof(announce_msg),
                        "TYPE:REREGISTER_FILE\nFILENAME:%s\nOWNER:%s\nSS_ID:%d",
                        entry->d_name, owner, SERVER_ID);
                    send_message(nm_socket, announce_msg);
                    char *resp = receive_message(nm_socket);
                    if (resp) free(resp);
                    
                    log_message("INFO", "Announced existing file: %s (owner: %s)", entry->d_name, owner);
                }
            }
        }
        closedir(dir);
    }
    // Send metadata updates for all loaded files to Name Server
    for (int i = 0; i < file_count; i++) {
        update_nameserver_metadata(files[i].filename);
        // small sleep to avoid overwhelming NM
        usleep(5000);
    }
    log_message("INFO", "File announcement complete");
    
    // Create client-facing socket
    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket < 0) {
        log_message("ERROR", "Socket creation failed");
        exit(1);
    }
    
    if (setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        log_message("ERROR", "Socket option failed");
        exit(1);
    }
    
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(ss_client_port);
    
    if (bind(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        log_message("ERROR", "Bind failed on port %d: %s", ss_client_port, strerror(errno));
        fprintf(stderr, "ERROR: Cannot bind to port %d: %s\n", ss_client_port, strerror(errno));
        fprintf(stderr, "       Another process may be using this port.\n");
        close(server_socket);
        exit(1);
    }
    
    listen(server_socket, 100);
    log_message("INFO", "Storage Server listening on port %d", ss_client_port);
    
    while (1) {
        struct sockaddr_in client_addr;
        int client_socket;
        socklen_t client_len = sizeof(client_addr);
        
        client_socket = accept(server_socket, (struct sockaddr *)&client_addr, &client_len);
        if (client_socket < 0) {
            log_message("ERROR", "Accept failed");
            continue;
        }
        
        log_message("INFO", "Client connected from %s", inet_ntoa(client_addr.sin_addr));
        
        pthread_t thread;
        pthread_create(&thread, NULL, client_thread, (void *)(intptr_t)client_socket);
        pthread_detach(thread);
    }
    
    close(server_socket);
    close(nm_socket);
    return 0;
}

