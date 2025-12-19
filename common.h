
#ifndef COMMON_H
#define COMMON_H

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <time.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <dirent.h>
#include <ctype.h>
#include <stdint.h>
#include <errno.h>
#include <zlib.h>

#define MAX_BUFFER 8192
#define MAX_FILENAME 256
#define MAX_USERNAME 128
#define MAX_USERS 1000
#define MAX_FILES 10000
#define MAX_SENTENCES 5000
#define MAX_WORDS 50000
#define MAX_PATH 2048
#define MAX_FOLDERS 1000
#define MAX_REQUESTS 1000
#define MAX_REPLICAS 3           // Maximum replicas per file (for fault tolerance)
#define DELIMITER "\n\n"
#define MSG_END "||END||"
#define LOG_DIR "logs"
#define STORAGE_DIR "storage/files"

// Error Codes (same)
#define ERR_SUCCESS 0
#define ERR_FILE_NOT_FOUND 1
#define ERR_ACCESS_DENIED 2
#define ERR_FILE_LOCKED 3
#define ERR_INVALID_INDEX 4
#define ERR_USER_NOT_FOUND 5
#define ERR_FILE_EXISTS 6
#define ERR_UNAUTHORIZED 7
#define ERR_SERVER_UNAVAILABLE 8
#define ERR_GENERAL 9

// Message Types (added)
#define MSG_REGISTER_CLIENT "TYPE:REGISTER_CLIENT"
#define MSG_REGISTER_SS "TYPE:REGISTER_SS"
#define MSG_CREATE "TYPE:CREATE"
#define MSG_DELETE "TYPE:DELETE"
#define MSG_READ "TYPE:READ"
#define MSG_WRITE "TYPE:WRITE"
#define MSG_WRITE_END "TYPE:ETIRW"
#define MSG_VIEW "TYPE:VIEW"
#define MSG_LIST "TYPE:LIST"
#define MSG_INFO "TYPE:INFO"
#define MSG_UNDO "TYPE:UNDO"
#define MSG_STREAM "TYPE:STREAM"
#define MSG_EXEC "TYPE:EXEC"
#define MSG_ADDACCESS "TYPE:ADDACCESS"
#define MSG_REMACCESS "TYPE:REMACCESS"
#define MSG_REQUESTACCESS "TYPE:REQUESTACCESS"
#define MSG_VIEWREQUESTS "TYPE:VIEWREQUESTS"
#define MSG_APPROVEREQUEST "TYPE:APPROVEREQUEST"
#define MSG_DENYREQUEST "TYPE:DENYREQUEST"
#define MSG_CREATEFOLDER "TYPE:CREATEFOLDER"
#define MSG_MOVE "TYPE:MOVE"
#define MSG_VIEWFOLDER "TYPE:VIEWFOLDER"
#define MSG_CHECKPOINT "TYPE:CHECKPOINT"
#define MSG_LISTCHECKPOINTS "TYPE:LISTCHECKPOINTS"
#define MSG_VIEWCHECKPOINT "TYPE:VIEWCHECKPOINT"
#define MSG_REVERT "TYPE:REVERT"
#define MSG_RESPONSE "TYPE:response"
#define MSG_ERROR "TYPE:error"
#define MSG_HEARTBEAT "TYPE:HEARTBEAT"
#define MSG_REPLICATE "TYPE:REPLICATE"
#define MSG_SYNC "TYPE:SYNC"

// File Structure (same)
typedef struct {
    char filename[MAX_FILENAME];
    char owner[MAX_USERNAME];
    char created[64];
    char last_modified[64];
    char last_accessed[64];
    char last_accessed_by[MAX_USERNAME];
    int word_count;
    int char_count;
    int sentence_count;
    int size_bytes;
} FileMetadata;

// Access Control (same)
typedef struct {
    char username[MAX_USERNAME];
    char access_type[3]; // "R" or "RW"
} AccessControl;

// Sentence Structure (same)
typedef struct {
    char **words;
    int word_count;
    char delimiter;
} Sentence;

typedef struct {
    Sentence *sentences;
    int sentence_count;
} FileContent;


// StoredFile structure for Storage Server
typedef struct {
    char filename[MAX_FILENAME];
    char owner[MAX_USERNAME];
    char created[64];
    char last_modified[64];
    FileMetadata metadata;  // Persist metadata in-memory for SS (for Storage Server)

    char content[MAX_BUFFER * 10];  

    int compressed;
    size_t original_size;
    size_t compressed_size;

    int locked;                     // global lock
    char *undo_content;             // undo buffer

    pthread_mutex_t sentence_locks[MAX_SENTENCES];
} StoredFile;


// FileEntry (for NM registry) - enhanced for replication
typedef struct {
    char filename[MAX_FILENAME];
    char folder_path[MAX_PATH];  // Path to containing folder (e.g., "folder1/folder2")
    int storage_server_id;
    FileMetadata metadata;
    AccessControl acl[MAX_USERS];
    int acl_count;
    int replica_ids[MAX_REPLICAS];  // Storage server IDs holding replicas
    int replica_count;               // Number of active replicas
} FileEntry;

// ConnectedClient (for NM)
typedef struct {
    char username[MAX_USERNAME];
    char ip[16];
    int port;
    time_t connection_time;
} ConnectedClient;


// Storage Server Info (enhanced for fault tolerance + persistent connections)
typedef struct {
    char ip[16];
    int nm_port;
    int client_port;

    // Identification & health
    int server_id;
    int active;
    time_t last_heartbeat;      

    // Replication fields
    int replica_count;
    int replica_ids[10];
    int is_replica_of;

    // === PERSISTENT CONNECTION FIELDS ===
    int persistent_sock;         
    int connected;               
    pthread_mutex_t ss_lock;     
} StorageServerInfo;



// Access Request (for bonus feature)
typedef struct {
    char filename[MAX_FILENAME];
    char requester[MAX_USERNAME];
    int permission; // 0=read, 1=write
    char timestamp[64];
    int status; // 0=pending, 1=approved, 2=denied
} AccessRequest;

#define REQUEST_PENDING 0
#define REQUEST_APPROVED 1
#define REQUEST_DENIED 2
#define PERM_READ 0
#define PERM_WRITE 1

// Folder Structure (for bonus feature)
typedef struct {
    char path[MAX_PATH];        // Full path like "folder1/folder2"
    char owner[MAX_USERNAME];
    char created[64];
    int file_count;
    int subfolder_count;
} FolderInfo;

// Checkpoint Structure (for version control bonus feature)
#define MAX_CHECKPOINTS 100
#define MAX_TAG_LENGTH 64
#define MAX_CHECKPOINT_CONTENT 81920
#define HEARTBEAT_INTERVAL 5     // Heartbeat every 5 seconds
#define HEARTBEAT_TIMEOUT 15     // Mark failed after 15 seconds
#define AUDIT_LOG "logs/audit.log"  // Audit trail log file
#define MAX_COMPRESSED_SIZE (MAX_BUFFER * 10 * 2)  // Max size for compressed data

typedef struct {
    int version_id;                      // Sequential version number
    char filename[MAX_FILENAME];         // Associated file
    char tag[MAX_TAG_LENGTH];            // Optional user tag (e.g., "before-refactor")
    char creator[MAX_USERNAME];          // Who created the checkpoint
    char timestamp[64];                  // When it was created
    char content[MAX_CHECKPOINT_CONTENT]; // Full file content snapshot
    int word_count;                      // Metadata at checkpoint time
    int char_count;
} CheckpointEntry;

// Audit Trail Entry (for unique factor)
typedef struct {
    char timestamp[64];
    char username[MAX_USERNAME];
    char operation[32];      // CREATE, READ, WRITE, DELETE, etc.
    char filename[MAX_FILENAME];
    char details[256];       // Additional details (e.g., "compressed 1024 -> 512 bytes")
    int success;             // 1 = success, 0 = failure
} AuditEntry;

// Function Declarations (added parse funcs)
void open_log(const char *component);
void log_message(const char *level, const char *message, ...);
void log_console(const char *tag, const char *message, ...);
char* get_timestamp();
void send_message(int socket, const char *message);
char* receive_message(int socket);
void parse_message(const char *message, char *key, char *value);
void create_response(char *buffer, int error_code, const char *data);
void create_error_response(char *buffer, int error_code, const char *error_msg);
void parse_content(const char *content, FileContent *parsed);
void free_parsed(FileContent *parsed);
void calculate_metadata(const char *content, FileMetadata *meta);
void init_sentence_locks(pthread_mutex_t *locks, int count);

// Compression functions (unique factor)
int compress_data(const char *input, size_t input_len, char *output, size_t *output_len);
int decompress_data(const char *input, size_t input_len, char *output, size_t *output_len);

// Audit trail functions (unique factor)
void log_audit(const char *username, const char *operation, const char *filename, 
               const char *details, int success);
void init_audit_log();

#endif
