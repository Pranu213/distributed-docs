// common.c - UPDATED with parsing and file logging
#include <stdarg.h>  
#include "common.h"
#include <sys/time.h>

static FILE *log_file = NULL;
static char log_filename[256];

//open/create log file for component
void open_log(const char *component) {
    snprintf(log_filename, sizeof(log_filename), "%s/%s.log", LOG_DIR, component);
    system("mkdir -p logs");
    log_file = fopen(log_filename, "a");
    if (!log_file) log_file = stderr;
}

void log_message(const char *level, const char *message, ...) {
    if (!log_file) open_log("common"); // fallback
    time_t now = time(NULL);
    struct tm *timeinfo = localtime(&now);
    char timestamp[64];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", timeinfo);
    // Write log entry in log file  
    fprintf(log_file, "[%s] [%s] ", timestamp, level);
    // Handle variable arguments
    va_list args;
    va_start(args, message);
    vfprintf(log_file, message, args);
    va_end(args);
    fprintf(log_file, "\n");
    fflush(log_file);
}

char* get_timestamp() {
    static char buffer[64];
    time_t now = time(NULL);
    struct tm *timeinfo = localtime(&now);
    strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", timeinfo);
    return buffer;
}

void log_console(const char *tag, const char *message, ...) {
    char timestamp[64];
    time_t now = time(NULL);
    struct tm *timeinfo = localtime(&now);
    strftime(timestamp, sizeof(timestamp), "[%Y-%m-%d %H:%M:%S]", timeinfo);
    
    printf("%s [%s] ", timestamp, tag);
    va_list args;
    va_start(args, message);
    vprintf(message, args);
    va_end(args);
    printf("\n");
    fflush(stdout);
}

void send_message(int socket, const char *message) {
    // Safely send messages of arbitrary length by appending the delimiter
    // into a dynamically allocated buffer and sending in a loop until all
    // bytes are transmitted.
    size_t msg_len = strlen(message);
    size_t delim_len = strlen(DELIMITER);
    size_t total_len = msg_len + delim_len;
    char *out = malloc(total_len + 1);
    if (!out) {
        // Fallback: try to send a truncated message
        char buffer[MAX_BUFFER];
        snprintf(buffer, sizeof(buffer), "%s%s", message, DELIMITER);
#ifdef MSG_NOSIGNAL
    send(socket, buffer, strlen(buffer), MSG_NOSIGNAL);
#else
    send(socket, buffer, strlen(buffer), 0);
#endif
        return;
    }
    memcpy(out, message, msg_len);
    memcpy(out + msg_len, DELIMITER, delim_len);
    out[total_len] = '\0';

    size_t sent = 0;
    while (sent < total_len) {
    ssize_t n;
#ifdef MSG_NOSIGNAL
    n = send(socket, out + sent, total_len - sent, MSG_NOSIGNAL);
#else
    n = send(socket, out + sent, total_len - sent, 0);
#endif
    if (n <= 0) break; // socket error or closed
        sent += n;
    }

    free(out);
}

char* receive_message(int socket) {
    // 1. DYNAMIC ALLOCATION (CRITICAL FIX): Allocate buffer on the heap 
    // to ensure each concurrent call gets its own memory space.
    char *buffer = (char*)malloc(MAX_BUFFER * 2);
    if (!buffer) {
        // Use log_message if available, or print to stderr
        // log_message("FATAL", "Memory allocation failed for network buffer.");
        return NULL;
    }
    memset(buffer, 0, MAX_BUFFER * 2);

    // Using a dynamic size variable for clarity
    const int buffer_size = MAX_BUFFER * 2;
    char line[1024];
    int total = 0;

    // Do NOT set a receive timeout here — keep sockets blocking so idle
    // clients are not disconnected due to a receive timeout. This ensures
    // servers stay connected until the peer actually closes the socket or
    // an explicit shutdown is requested.

    // Read loop
    while (1) {
        int i = 0;
        char c;

        // Read one line (byte by byte)
        while (i < sizeof(line) - 1) {
            int r = recv(socket, &c, 1, 0);

            if (r <= 0) {
                // Timeout (r<0 with EAGAIN/EWOULDBLOCK), orderly close (r==0), or other error (r<0)
                buffer[total] = '\0';

                // No data received at all
                if (total == 0) {
                    if (r == 0) {
                        // Remote closed connection
                        free(buffer);
                        return NULL;
                    }

                    // If interrupted by signal, retry
                    if (errno == EINTR) {
                        continue;
                    }

                    // Non-recoverable error: treat as disconnect
                    free(buffer);
                    return NULL;
                }

                // If we received partial data before timeout/disconnect, return the partial buffer
                return buffer;
            }

            line[i++] = c;
            if (c == '\n')
                break;
        }

        line[i] = '\0';

        // Append to main buffer (with safety check)
        if (total + i < buffer_size) {
            memcpy(buffer + total, line, i);
            total += i;
            buffer[total] = '\0';
        } else {
            // BUFFER OVERFLOW CHECK: Message is too large for the allocated buffer
            // log_message("WARNING", "Incoming message exceeded MAX_BUFFER size. Dropping connection.");
            free(buffer);
            return NULL;
        }

        // Check delimiter "\n\n"
        if (strstr(buffer, "\n\n")) {
            // Cut message at delimiter (ensures the response format is clean)
            char *pos = strstr(buffer, "\n\n");
            *pos = '\0';
            
            // NOTE: The caller MUST free(buffer) after using the message.
            return buffer;
        }
        
        // Safety check to prevent extremely large but non-delimited messages from filling up memory
        if (total > buffer_size - 1024) { // Check when getting close to limit
             // log_message("WARNING", "Message approaching buffer limit without delimiter.");
        }
    }
}



void create_response(char *buffer, int error_code, const char *data) {
    if (data) {
        snprintf(buffer, MAX_BUFFER, "TYPE:response\nERROR_CODE:%d\nDATA:%s", error_code, data);
    } else {
        snprintf(buffer, MAX_BUFFER, "TYPE:response\nERROR_CODE:%d", error_code);
    }
}

void create_error_response(char *buffer, int error_code, const char *error_msg) {
    snprintf(buffer, MAX_BUFFER, "TYPE:error\nERROR_CODE:%d\nERROR_MSG:%s", error_code, error_msg);
}

// Simple parser: split by space for words, .!? for sentences (edge cases: skip if followed by lowercase letter)
void parse_content(const char *content, FileContent *parsed) {
    parsed->sentence_count = 0;
    parsed->sentences = malloc(MAX_SENTENCES * sizeof(Sentence));
    char temp[MAX_BUFFER * 10];
    strcpy(temp, content);
    char *sent_start = temp;
    char *ptr = temp;
    
    while (*ptr) {
        if (*ptr == '.' || *ptr == '!' || *ptr == '?') {
            char next = *(ptr + 1);
            // Always treat .!? as sentence delimiters
            // End sentence
            char sent[MAX_BUFFER];
            strncpy(sent, sent_start, ptr - sent_start + 1);
            sent[ptr - sent_start + 1] = '\0';
            
            // Parse words in sentence
            Sentence *s = &parsed->sentences[parsed->sentence_count];
            s->word_count = 0;
            s->words = malloc(MAX_WORDS * sizeof(char*));
            char *word_start = sent;
            char *wptr = sent;
            
            while (*wptr) {
                if (*wptr == ' ' || *wptr == '\n' || *wptr == '\t') {
                    if (wptr > word_start) {
                        char word[MAX_BUFFER];
                        strncpy(word, word_start, wptr - word_start);
                        word[wptr - word_start] = '\0';
                        s->words[s->word_count] = strdup(word);
                        s->word_count++;
                    }
                    word_start = wptr + 1;
                }
                wptr++;
            }
            if (wptr > word_start) {
                char word[MAX_BUFFER];
                strncpy(word, word_start, wptr - word_start);
                word[wptr - word_start] = '\0';
                s->words[s->word_count] = strdup(word);
                s->word_count++;
            }
            
            s->delimiter = *ptr;
            parsed->sentence_count++;
            sent_start = ptr + 1;
            
            // Skip whitespace after delimiter
            while (*(ptr + 1) == ' ' || *(ptr + 1) == '\n' || *(ptr + 1) == '\t') {
                ptr++;
            }
        }
        ptr++;
    }
    
    // Last sentence if no delimiter
    if (sent_start < ptr && strlen(sent_start) > 0) {
        // Trim whitespace
        while (*sent_start == ' ' || *sent_start == '\n' || *sent_start == '\t') sent_start++;
        if (strlen(sent_start) > 0) {
            Sentence *s = &parsed->sentences[parsed->sentence_count];
            s->word_count = 0;
            s->words = malloc(MAX_WORDS * sizeof(char*));
            char *word_start = sent_start;
            char *wptr = sent_start;
            
            while (*wptr) {
                if (*wptr == ' ' || *wptr == '\n' || *wptr == '\t') {
                    if (wptr > word_start) {
                        char word[MAX_BUFFER];
                        strncpy(word, word_start, wptr - word_start);
                        word[wptr - word_start] = '\0';
                        s->words[s->word_count] = strdup(word);
                        s->word_count++;
                    }
                    word_start = wptr + 1;
                }
                wptr++;
            }
            if (wptr > word_start) {
                char word[MAX_BUFFER];
                strncpy(word, word_start, wptr - word_start);
                word[wptr - word_start] = '\0';
                s->words[s->word_count] = strdup(word);
                s->word_count++;
            }
            
            s->delimiter = '\0';
            parsed->sentence_count++;
        }
    }
}

void free_parsed(FileContent *parsed) {
    for (int i = 0; i < parsed->sentence_count; i++) {
        for (int j = 0; j < parsed->sentences[i].word_count; j++) {
            free(parsed->sentences[i].words[j]);
        }
        free(parsed->sentences[i].words);
    }
    free(parsed->sentences);
}

void calculate_metadata(const char *content, FileMetadata *meta) {
    meta->char_count = strlen(content);
    meta->size_bytes = meta->char_count;
    meta->word_count = 0;
    meta->sentence_count = 0;
    FileContent parsed;
    parse_content(content, &parsed);
    meta->word_count = 0;
    for (int i = 0; i < parsed.sentence_count; i++) {
        meta->word_count += parsed.sentences[i].word_count;
        meta->sentence_count = parsed.sentence_count;
    }
    free_parsed(&parsed);
    strcpy(meta->last_accessed, get_timestamp());
    strcpy(meta->last_accessed_by, "system"); // update with user
}

void init_sentence_locks(pthread_mutex_t *locks, int count) {
    for (int i = 0; i < count; i++) {
        pthread_mutex_init(&locks[i], NULL);
    }
}

// ==================== COMPRESSION FUNCTIONS (UNIQUE FACTOR) ====================

int compress_data(const char *input, size_t input_len, char *output, size_t *output_len) {
    z_stream stream;
    stream.zalloc = Z_NULL;
    stream.zfree = Z_NULL;
    stream.opaque = Z_NULL;
    
    if (deflateInit(&stream, Z_BEST_COMPRESSION) != Z_OK) {
        return -1;
    }
    
    stream.avail_in = input_len;
    stream.next_in = (Bytef *)input;
    stream.avail_out = *output_len;
    stream.next_out = (Bytef *)output;
    
    int ret = deflate(&stream, Z_FINISH);
    if (ret != Z_STREAM_END) {
        deflateEnd(&stream);
        return -1;
    }
    
    *output_len = stream.total_out;
    deflateEnd(&stream);
    return 0;
}

int decompress_data(const char *input, size_t input_len, char *output, size_t *output_len) {
    z_stream stream;
    stream.zalloc = Z_NULL;
    stream.zfree = Z_NULL;
    stream.opaque = Z_NULL;
    
    if (inflateInit(&stream) != Z_OK) {
        return -1;
    }
    
    stream.avail_in = input_len;
    stream.next_in = (Bytef *)input;
    stream.avail_out = *output_len;
    stream.next_out = (Bytef *)output;
    
    int ret = inflate(&stream, Z_FINISH);
    if (ret != Z_STREAM_END) {
        inflateEnd(&stream);
        return -1;
    }
    
    *output_len = stream.total_out;
    inflateEnd(&stream);
    return 0;
}

// ==================== AUDIT TRAIL FUNCTIONS (UNIQUE FACTOR) ====================

static FILE *audit_file = NULL;
static pthread_mutex_t audit_lock = PTHREAD_MUTEX_INITIALIZER;

void init_audit_log() {
    system("mkdir -p logs");
    audit_file = fopen(AUDIT_LOG, "a");
    if (!audit_file) {
        audit_file = stderr;
    }
    
    // Write header if file is empty
    fseek(audit_file, 0, SEEK_END);
    if (ftell(audit_file) == 0) {
        fprintf(audit_file, "# LangOS Audit Trail Log\n");
        fprintf(audit_file, "# Format: [Timestamp] [User] [Operation] [File] [Details] [Status]\n");
        fprintf(audit_file, "# ======================================================================\n");
        fflush(audit_file);
    }
}

void log_audit(const char *username, const char *operation, const char *filename,
               const char *details, int success) {
    pthread_mutex_lock(&audit_lock);
    
    if (!audit_file) {
        init_audit_log();
    }
    
    char timestamp[64];
    time_t now = time(NULL);
    struct tm *timeinfo = localtime(&now);
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", timeinfo);
    
    fprintf(audit_file, "[%s] [%-15s] [%-12s] [%-30s] [%-40s] [%s]\n",
            timestamp,
            username ? username : "system",
            operation,
            filename ? filename : "-",
            details ? details : "-",
            success ? "SUCCESS" : "FAILURE");
    fflush(audit_file);
    
    pthread_mutex_unlock(&audit_lock);
}

