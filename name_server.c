#include "common.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "common.h"
#include <pthread.h>
#include <errno.h>
#define NM_PORT 8000
#define MAX_STORAGE_SERVERS 100
#define MAX_CLIENTS 1000
#define HASH_SIZE 1024

// ...existing code...
#include <sys/time.h>
typedef struct FileNode {
    FileEntry entry;
    struct FileNode *next;
} FileNode;

FileNode *hash_table[HASH_SIZE];
StorageServerInfo storage_servers[MAX_STORAGE_SERVERS];
int ss_count = 0;
ConnectedClient connected_clients[MAX_CLIENTS];
int client_count = 0;
int file_count = 0;

// Access Request System
AccessRequest access_requests[MAX_REQUESTS];
int request_count = 0;
pthread_mutex_t request_lock = PTHREAD_MUTEX_INITIALIZER;

// Folder System
FolderInfo folders[MAX_FOLDERS];
int folder_count = 0;
pthread_mutex_t folder_lock = PTHREAD_MUTEX_INITIALIZER;

// Checkpoint System
CheckpointEntry checkpoints[MAX_FILES * 10]; // Support up to 10 checkpoints per file
int checkpoint_count = 0;
pthread_mutex_t checkpoint_lock = PTHREAD_MUTEX_INITIALIZER;

pthread_mutex_t registry_lock = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t ss_lock = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t client_lock = PTHREAD_MUTEX_INITIALIZER;

// ======== TRIE IMPLEMENTATION FOR EFFICIENT SEARCH ========
typedef struct TrieNode {
    struct TrieNode *children[256];  // Support all ASCII characters
    FileEntry *file_entry;            // Pointer to file entry if this is end of filename
    int is_end_of_word;               // Flag to mark end of filename
} TrieNode;

TrieNode *trie_root = NULL;
pthread_mutex_t trie_lock = PTHREAD_MUTEX_INITIALIZER;

void trie_init(void) {
    if (!trie_root) {
        trie_root = calloc(1, sizeof(TrieNode));
    }
}

void trie_insert(const char *filename, FileEntry *entry) {
    if (!trie_root) trie_init();
    
    pthread_mutex_lock(&trie_lock);
    TrieNode *node = trie_root;
    
    for (int i = 0; filename[i]; i++) {
        int idx = (unsigned char)filename[i];
        if (!node->children[idx]) {
            node->children[idx] = calloc(1, sizeof(TrieNode));
        }
        node = node->children[idx];
    }
    
    node->is_end_of_word = 1;
    node->file_entry = entry;
    pthread_mutex_unlock(&trie_lock);
}

FileEntry* trie_search(const char *filename) {
    if (!trie_root) return NULL;
    
    pthread_mutex_lock(&trie_lock);
    TrieNode *node = trie_root;
    
    for (int i = 0; filename[i]; i++) {
        int idx = (unsigned char)filename[i];
        if (!node->children[idx]) {
            pthread_mutex_unlock(&trie_lock);
            return NULL;
        }
        node = node->children[idx];
    }
    
    FileEntry *result = node->is_end_of_word ? node->file_entry : NULL;
    pthread_mutex_unlock(&trie_lock);
    return result;
}

void trie_delete_helper(TrieNode *node) {
    if (!node) return;
    for (int i = 0; i < 256; i++) {
        if (node->children[i]) {
            trie_delete_helper(node->children[i]);
        }
    }
    free(node);
}

void trie_remove(const char *filename) {
    // Simple approach: just mark as not end of word
    if (!trie_root) return;
    
    pthread_mutex_lock(&trie_lock);
    TrieNode *node = trie_root;
    
    for (int i = 0; filename[i]; i++) {
        int idx = (unsigned char)filename[i];
        if (!node->children[idx]) {
            pthread_mutex_unlock(&trie_lock);
            return;
        }
        node = node->children[idx];
    }
    
    node->is_end_of_word = 0;
    node->file_entry = NULL;
    pthread_mutex_unlock(&trie_lock);
}

// ======== SEARCH CACHE FOR RECENT LOOKUPS ========
#define CACHE_SIZE 100
#define CACHE_TTL 300  // 5 minutes

typedef struct {
    char filename[MAX_FILENAME];
    FileEntry *entry;
    time_t timestamp;
    int valid;
} CacheEntry;

CacheEntry file_cache[CACHE_SIZE];
int cache_index = 0;
pthread_mutex_t cache_lock = PTHREAD_MUTEX_INITIALIZER;

// Forward declaration
FileEntry *find_in_hash(const char *filename);

void cache_invalidate(const char *filename) {
    pthread_mutex_lock(&cache_lock);
    for (int i = 0; i < CACHE_SIZE; i++) {
        if (file_cache[i].valid && strcmp(file_cache[i].filename, filename) == 0) {
            file_cache[i].valid = 0;
        }
    }
    pthread_mutex_unlock(&cache_lock);
}

// Forward declaration for metadata updater
void send_and_receive_metadata(const char *filename, FileMetadata *meta);

FileEntry* find_file_optimized(const char *filename) {
    // Step 1: Check cache first (fastest)
    pthread_mutex_lock(&cache_lock);
    for (int i = 0; i < CACHE_SIZE; i++) {
        if (file_cache[i].valid && 
            strcmp(file_cache[i].filename, filename) == 0) {
            
            time_t now = time(NULL);
            if (now - file_cache[i].timestamp < CACHE_TTL) {
                // Cache hit!
                FileEntry *entry = file_cache[i].entry;
                pthread_mutex_unlock(&cache_lock);
                //log_message("DEBUG", "Cache HIT for file: %s", filename);
                return entry;
            } else {
                // Cache expired
                file_cache[i].valid = 0;
            }
        }
    }
    pthread_mutex_unlock(&cache_lock);
    
    // Step 2: Cache miss - search Trie (O(k) where k is filename length)
    FileEntry *entry = trie_search(filename);
    
    if (!entry) {
        // Step 3: Fallback to hash table if Trie search fails
        entry = find_in_hash(filename);
    }
    
    // Step 4: Add to cache if found
    if (entry) {
        pthread_mutex_lock(&cache_lock);
        int idx = cache_index++ % CACHE_SIZE;
        strncpy(file_cache[idx].filename, filename, MAX_FILENAME);
        file_cache[idx].entry = entry;
        file_cache[idx].timestamp = time(NULL);
        file_cache[idx].valid = 1;
        pthread_mutex_unlock(&cache_lock);
        //log_message("DEBUG", "Cache MISS for file: %s - Added to cache", filename);
    }
    
    return entry;
}
// Implementation: perform a GET_METADATA call to the SS
void send_and_receive_metadata(const char *filename, FileMetadata *meta) {
    FileEntry *entry = find_file_optimized(filename);
    if (!entry) return;

    int ss_id = entry->storage_server_id;
    if (ss_id < 0 || ss_id >= MAX_STORAGE_SERVERS) return;

    StorageServerInfo *ss = &storage_servers[ss_id];
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return;

    struct timeval timeout;
    timeout.tv_sec = 2; // 2 seconds timeout
    timeout.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout, sizeof(timeout));

    struct sockaddr_in ss_addr;
    ss_addr.sin_family = AF_INET;
    ss_addr.sin_port = htons(ss->client_port);
    ss_addr.sin_addr.s_addr = inet_addr(ss->ip);

    if (connect(sock, (struct sockaddr *)&ss_addr, sizeof(ss_addr)) < 0) {
        close(sock);
        return;
    }

    char req[MAX_BUFFER];
    snprintf(req, sizeof(req), "TYPE:GET_METADATA\nFILENAME:%s", filename);
    send_message(sock, req);

    char *resp = receive_message(sock);
    if (resp && strstr(resp, "TYPE:METADATA")) {
        int w, c, s, sz;
        char last_accessed[64] = "";
        char last_accessed_by[MAX_USERNAME] = "";
        sscanf(resp, "TYPE:METADATA\nFILENAME:%*s\nWORD_COUNT:%d\nCHAR_COUNT:%d\nSENTENCE_COUNT:%d\nSIZE:%d\nLAST_ACCESSED:%63[^\n]\nLAST_ACCESSED_BY:%127[^\n]",
               &w, &c, &s, &sz, last_accessed, last_accessed_by);
        meta->word_count = w;
        meta->char_count = c;
        meta->sentence_count = s;
        meta->size_bytes = sz;
        if (strlen(last_accessed) > 0)
            strncpy(meta->last_accessed, last_accessed, 64);
        if (strlen(last_accessed_by) > 0)
            strncpy(meta->last_accessed_by, last_accessed_by, MAX_USERNAME);
    }
    if (resp) free(resp);
    close(sock);
}
// ======== END TRIE AND CACHE ========

unsigned int hash_filename(const char *str) {
    unsigned int hash = 0;
    while (*str) {
        hash = hash * 31 + *str++;
    }
    return hash % HASH_SIZE;
}

void add_to_hash(FileEntry *entry) {
    unsigned int h = hash_filename(entry->filename);
    FileNode *node = malloc(sizeof(FileNode));
    node->entry = *entry;
    node->next = hash_table[h];
    hash_table[h] = node;
    file_count++;
    
    trie_insert(entry->filename, &node->entry);
}

FileEntry *find_in_hash(const char *filename) {
    unsigned int h = hash_filename(filename);
    FileNode *node = hash_table[h];
    while (node) {
        if (strcmp(node->entry.filename, filename) == 0) return &node->entry;
        node = node->next;
    }
    return NULL;
}

void remove_from_hash(const char *filename) {
    unsigned int h = hash_filename(filename);
    FileNode *node = hash_table[h];
    FileNode *prev = NULL;
    
    while (node) {
        if (strcmp(node->entry.filename, filename) == 0) {
            if (prev) {
                prev->next = node->next;
            } else {
                hash_table[h] = node->next;
            }
            free(node);
            file_count--;
            
            // Also remove from Trie and invalidate cache
            trie_remove(filename);
            cache_invalidate(filename);
            return;
        }
        prev = node;
        node = node->next;
    }
}

// ======== FOLDER HELPER FUNCTIONS ========

FolderInfo* find_folder(const char *path) {
    for (int i = 0; i < folder_count; i++) {
        if (strcmp(folders[i].path, path) == 0) {
            return &folders[i];
        }
    }
    return NULL;
}

int create_folder_entry(const char *path, const char *owner) {
    if (folder_count >= MAX_FOLDERS) {
        return -1;
    }
    
    FolderInfo *folder = &folders[folder_count++];
    strncpy(folder->path, path, MAX_PATH);
    strncpy(folder->owner, owner, MAX_USERNAME);
    strncpy(folder->created, get_timestamp(), 64);
    folder->file_count = 0;
    folder->subfolder_count = 0;
    
    return 0;
}

void normalize_path(char *path) {
    // Remove trailing slashes
    int len = strlen(path);
    while (len > 0 && path[len-1] == '/') {
        path[--len] = '\0';
    }
    // Remove leading slashes
    if (path[0] == '/') {
        memmove(path, path + 1, strlen(path));
    }
}

void get_full_path(const char *folder, const char *filename, char *full_path) {
    if (folder && strlen(folder) > 0) {
        snprintf(full_path, MAX_PATH, "%s/%s", folder, filename);
    } else {
        strncpy(full_path, filename, MAX_PATH);
    }
}

// ======== END FOLDER HELPERS ========

static int rr_ss_index = 0;
int get_available_ss(void) {
    int start = rr_ss_index;
    for (int tries = 0; tries < ss_count; tries++) {
        int idx = (start + tries) % ss_count;
        if (storage_servers[idx].active) {
            rr_ss_index = (idx + 1) % ss_count;
            return idx;
        }
    }
    return -1;
}


int forward_to_ss(int ss_id, const char *message, char *response) {
    StorageServerInfo *ss = &storage_servers[ss_id];

    pthread_mutex_lock(&ss->ss_lock);

    // If no active connection, reconnect
    if (!ss->connected) {
        ss->persistent_sock = socket(AF_INET, SOCK_STREAM, 0);
        if (ss->persistent_sock < 0) {
            ss->connected = 0;
            pthread_mutex_unlock(&ss->ss_lock);
            return -1;
        }

        struct sockaddr_in ss_addr;
        ss_addr.sin_family = AF_INET;
        ss_addr.sin_addr.s_addr = inet_addr(ss->ip);
        ss_addr.sin_port = htons(ss->client_port);

        if (connect(ss->persistent_sock, (struct sockaddr*)&ss_addr, sizeof(ss_addr)) < 0) {
            close(ss->persistent_sock);
            ss->connected = 0;
            pthread_mutex_unlock(&ss->ss_lock);
            return -1;
        }

        ss->connected = 1;
    }

    // Send the request
    send_message(ss->persistent_sock, message);

    // Receive response
    char *resp = receive_message(ss->persistent_sock);

    // Handle failed read (socket died)
    if (!resp) {
        ss->connected = 0; // force reconnect later
        pthread_mutex_unlock(&ss->ss_lock);
        return -1;
    }

    strcpy(response, resp);
    pthread_mutex_unlock(&ss->ss_lock);
    return 0;
}


void register_storage_server(int client_socket, const char *message) {
    char ip[16], nm_port_str[10], client_port_str[10];
    sscanf(message, "TYPE:REGISTER_SS\nIP:%s\nNM_PORT:%s\nCLIENT_PORT:%s", 
        ip, nm_port_str, client_port_str);
    
    pthread_mutex_lock(&ss_lock);
    if (ss_count < MAX_STORAGE_SERVERS) {
        StorageServerInfo *ss = &storage_servers[ss_count];
        strcpy(ss->ip, ip);
        ss->nm_port = atoi(nm_port_str);
        ss->client_port = atoi(client_port_str);
        ss->server_id = ss_count;
        ss->active = 1;
        ss->last_heartbeat = time(NULL);  // Initialize heartbeat
        ss->replica_count = 0;             // No replicas initially
        ss->is_replica_of = -1;            // This is a primary SS

        // Initialize replica_ids array
        for (int i = 0; i < 10; i++) {
            ss->replica_ids[i] = -1;
        }

        // ====================================
        // INITIALIZE NEW PERSISTENT SOCKET FIELDS
        // ====================================
        ss->persistent_sock = -1;
        ss->connected = 0;
        pthread_mutex_init(&ss->ss_lock, NULL);
        // ====================================

        ss_count++;
        
        log_message("INFO", "Storage Server registered: ID=%d IP=%s NM_PORT=%d CLIENT_PORT=%d", 
            ss->server_id, ss->ip, ss->nm_port, ss->client_port);
        log_console("NM", "Storage Server %d registered (%s:%d)", ss->server_id, ss->ip, ss->client_port);
        
        char response[MAX_BUFFER];
        create_response(response, ERR_SUCCESS, NULL);
        send_message(client_socket, response);
    } else {
        char response[MAX_BUFFER];
        create_error_response(response, ERR_GENERAL, "Too many storage servers");
        send_message(client_socket, response);
    }
    pthread_mutex_unlock(&ss_lock);
}


void register_client(int client_socket, const char *message) {
    char username[MAX_USERNAME], ip[16], port_str[10];
    sscanf(message, "TYPE:REGISTER_CLIENT\nUSER:%s\nIP:%s\nPORT:%s", username, ip, port_str);
    
    pthread_mutex_lock(&client_lock);
    if (client_count < MAX_CLIENTS) {
        ConnectedClient *client = &connected_clients[client_count];
        strcpy(client->username, username);
        strcpy(client->ip, ip);
        client->port = atoi(port_str);
        client->connection_time = time(NULL);
        client_count++;
        
        log_message("INFO", "Client registered: USER=%s IP=%s PORT=%s", username, ip, port_str);
        log_console("NM", "Client '%s' connected\n", username);
        
        char response[MAX_BUFFER];
        create_response(response, ERR_SUCCESS, NULL);
        send_message(client_socket, response);
    } else {
        char response[MAX_BUFFER];
        create_error_response(response, ERR_GENERAL, "Too many clients");
        send_message(client_socket, response);
    }
    pthread_mutex_unlock(&client_lock);
}

void handle_update_metadata(const char *message) {
    char filename[MAX_FILENAME];
    int word_count, char_count, sentence_count, size_bytes;
    char last_accessed[64] = "";
    char last_accessed_by[MAX_USERNAME] = "";
    // Parse the UPDATE_METADATA message (with optional last_accessed/by)
    sscanf(message, "TYPE:UPDATE_METADATA\nFILENAME:%s\nWORD_COUNT:%d\nCHAR_COUNT:%d\nSENTENCE_COUNT:%d\nSIZE:%d\nLAST_ACCESSED:%63[^\n]\nLAST_ACCESSED_BY:%127[^\n]",
        filename, &word_count, &char_count, &sentence_count, &size_bytes, last_accessed, last_accessed_by);
    
    pthread_mutex_lock(&registry_lock);
    
    // Find the file entry
    FileEntry *entry = find_file_optimized(filename);
    if (entry != NULL) {
        // Update metadata
        entry->metadata.word_count = word_count;
        entry->metadata.char_count = char_count;
        entry->metadata.sentence_count = sentence_count;
        entry->metadata.size_bytes = size_bytes;
        if (strlen(last_accessed) > 0)
            strncpy(entry->metadata.last_accessed, last_accessed, 64);
        if (strlen(last_accessed_by) > 0)
            strncpy(entry->metadata.last_accessed_by, last_accessed_by, MAX_USERNAME);
        strcpy(entry->metadata.last_modified, get_timestamp());
        log_message("INFO", "Updated metadata for %s: words=%d, chars=%d, last_accessed=%s, last_accessed_by=%s", 
                   filename, word_count, char_count, last_accessed, last_accessed_by);
    } else {
        log_message("WARNING", "UPDATE_METADATA: File '%s' not found", filename);
    }
    
    pthread_mutex_unlock(&registry_lock);
}

void handle_create_file(int client_socket, const char *message) {
    char username[MAX_USERNAME], filename[MAX_FILENAME];
    sscanf(message, "TYPE:CREATE\nUSER:%s\nFILENAME:%s", username, filename);
    
    pthread_mutex_lock(&registry_lock);
    
    // Validate filename is not empty
    if (strlen(filename) == 0) {
        char response[MAX_BUFFER];
        create_error_response(response, ERR_GENERAL, "Filename cannot be empty");
        send_message(client_socket, response);
        log_console("NM", "CREATE failed: Empty filename\n");
        log_audit(username, "CREATE", "", "empty filename", 0);
        pthread_mutex_unlock(&registry_lock);
        return;
    }
    
    if (find_file_optimized(filename) != NULL) {
        char response[MAX_BUFFER];
        create_error_response(response, ERR_FILE_EXISTS, "File already exists");
        send_message(client_socket, response);
        log_console("NM", "CREATE failed: File '%s' already exists\n", filename);
        log_audit(username, "CREATE", filename, "file already exists", 0);
        pthread_mutex_unlock(&registry_lock);
        return;
    }
    
    int ss_id = get_available_ss();
    if (ss_id == -1) {
        char response[MAX_BUFFER];
        create_error_response(response, ERR_SERVER_UNAVAILABLE, "No storage servers available");
        send_message(client_socket, response);
        log_console("NM", "CREATE failed: No storage servers available");
        log_audit(username, "CREATE", filename, "no storage servers available", 0);
        pthread_mutex_unlock(&registry_lock);
        return;
    }
    
    FileEntry entry;
    strcpy(entry.filename, filename);
    strcpy(entry.folder_path, "");  // Initialize to root folder
    entry.storage_server_id = ss_id;
    strcpy(entry.metadata.filename, filename);
    strcpy(entry.metadata.owner, username);
    strcpy(entry.metadata.created, get_timestamp());
    strcpy(entry.metadata.last_modified, get_timestamp());
    strcpy(entry.metadata.last_accessed, get_timestamp());
    strcpy(entry.metadata.last_accessed_by, username);
    entry.metadata.word_count = 0;
    entry.metadata.char_count = 0;
    entry.metadata.sentence_count = 0;
    entry.metadata.size_bytes = 0;

    strcpy(entry.acl[0].username, username);
    strcpy(entry.acl[0].access_type, "RW");
    entry.acl_count = 1;

    // Keep the registry locked while we attempt to forward the CREATE to the
    // selected Storage Server to avoid races (this is simple and safe; if
    // forwarding blocks for long periods we can improve by introducing a
    // lightweight reservation state later).

    // Forward to SS
    char ss_response[MAX_BUFFER];
    if (forward_to_ss(ss_id, message, ss_response) < 0) {
        // Failed to reach SS: do NOT register the file in the Name Server
        create_error_response(ss_response, ERR_SERVER_UNAVAILABLE, "Storage server unavailable");
        log_audit(username, "CREATE", filename, "storage server unavailable", 0);
        send_message(client_socket, ss_response);
        pthread_mutex_unlock(&registry_lock);
        return;
    }

    // If SS returned an error, forward it to client and do not register
    if (!strstr(ss_response, "ERROR_CODE:0")) {
        send_message(client_socket, ss_response);
        pthread_mutex_unlock(&registry_lock);
        return;
    }

    // Storage Server successfully created the file; now register it in NM
    add_to_hash(&entry);

    log_message("INFO", "File registered: %s -> SS %d by %s", filename, ss_id, username);
    log_audit(username, "CREATE", filename, "file created and registered", 1);
    log_console("NM", "File '%s' registered on SS %d\n", filename, ss_id);

    pthread_mutex_unlock(&registry_lock);

    // Forward SS success response to client
    send_message(client_socket, ss_response);
}

void handle_read_file(int client_socket, const char *message) {
    char username[MAX_USERNAME], filename[MAX_FILENAME];
    sscanf(message, "TYPE:READ\nUSER:%s\nFILENAME:%s", username, filename);
    
    pthread_mutex_lock(&registry_lock);
    
    FileEntry *entry = find_file_optimized(filename);
    if (!entry) {
        char resp[MAX_BUFFER];
        create_error_response(resp, ERR_FILE_NOT_FOUND, "File not found");
        send_message(client_socket, resp);
        log_console("NM", "READ failed: File '%s' not found\n", filename);
        pthread_mutex_unlock(&registry_lock);
        return;
    }
    
    // ACL check
    int has_access = (strcmp(entry->metadata.owner, username) == 0);
    for (int j = 0; j < entry->acl_count; j++) {
        if (strcmp(entry->acl[j].username, username) == 0 && 
            strchr(entry->acl[j].access_type, 'R')) {
            has_access = 1;
            break;
        }
    }
    
    if (!has_access) {
        char resp[MAX_BUFFER];
        create_error_response(resp, ERR_ACCESS_DENIED, "No read access");
        send_message(client_socket, resp);
        log_console("NM", "READ failed: User '%s' has no access to '%s'\n", username, filename);
        pthread_mutex_unlock(&registry_lock);
        return;
    }
    
    int ss_id = entry->storage_server_id;
    StorageServerInfo *ss = &storage_servers[ss_id];

    // Update last accessed metadata in registry
    strncpy(entry->metadata.last_accessed, get_timestamp(), 64);
    strncpy(entry->metadata.last_accessed_by, username, MAX_USERNAME);

    char resp[MAX_BUFFER];
    snprintf(resp, sizeof(resp), "TYPE:response\nERROR_CODE:0\nIP:%s\nPORT:%d", 
        ss->ip, ss->client_port);
    send_message(client_socket, resp);

    log_message("INFO", "READ request: %s by %s -> SS %d", filename, username, ss_id);
    log_console("NM", "READ: '%s' by '%s' -> SS %d (%s:%d)\n", filename, username, ss_id, ss->ip, ss->client_port);

    pthread_mutex_unlock(&registry_lock);
}

void handle_write_file(int client_socket, const char *message) {
    char username[MAX_USERNAME], filename[MAX_FILENAME];
    sscanf(message, "TYPE:WRITE\nUSER:%s\nFILENAME:%s", username, filename);
    
    pthread_mutex_lock(&registry_lock);
    
    FileEntry *entry = find_file_optimized(filename);
    if (!entry) {
        char resp[MAX_BUFFER];
        create_error_response(resp, ERR_FILE_NOT_FOUND, "File not found");
        send_message(client_socket, resp);
        log_console("NM", "WRITE failed: File '%s' not found\n", filename);
        log_audit(username, "WRITE", filename, "file not found", 0);
        pthread_mutex_unlock(&registry_lock);
        return;
    }
    
    // ACL check
    int has_access = (strcmp(entry->metadata.owner, username) == 0);
    for (int j = 0; j < entry->acl_count; j++) {
        if (strcmp(entry->acl[j].username, username) == 0 && 
            strchr(entry->acl[j].access_type, 'W')) {
            has_access = 1;
            break;
        }
    }
    
    if (!has_access) {
        char resp[MAX_BUFFER];
        create_error_response(resp, ERR_ACCESS_DENIED, "No write access");
        send_message(client_socket, resp);
        log_console("NM", "WRITE failed: User '%s' has no write access to '%s'\n", username, filename);
        log_audit(username, "WRITE", filename, "access denied - no write permission", 0);
        pthread_mutex_unlock(&registry_lock);
        return;
    }
    
    int ss_id = entry->storage_server_id;
    StorageServerInfo *ss = &storage_servers[ss_id];
    
    char resp[MAX_BUFFER];
    snprintf(resp, sizeof(resp), "TYPE:response\nERROR_CODE:0\nIP:%s\nPORT:%d", 
        ss->ip, ss->client_port);
    send_message(client_socket, resp);
    
    log_message("INFO", "WRITE request: %s by %s -> SS %d", filename, username, ss_id);
    log_audit(username, "WRITE", filename, "write access granted", 1);
    log_console("NM", "WRITE: '%s' by '%s' -> SS %d (%s:%d)\n", filename, username, ss_id, ss->ip, ss->client_port);
    
    pthread_mutex_unlock(&registry_lock);
}

void handle_delete_file(int client_socket, const char *message) {
    char username[MAX_USERNAME], filename[MAX_FILENAME];
    sscanf(message, "TYPE:DELETE\nUSER:%s\nFILENAME:%s", username, filename);
    
    pthread_mutex_lock(&registry_lock);
    
    FileEntry *entry = find_file_optimized(filename);
    if (!entry) {
        char resp[MAX_BUFFER];
        create_error_response(resp, ERR_FILE_NOT_FOUND, "File not found");
        send_message(client_socket, resp);
        log_console("NM", "DELETE failed: File '%s' not found\n", filename);
        log_audit(username, "DELETE", filename, "file not found", 0);
        pthread_mutex_unlock(&registry_lock);
        return;
    }
    
    // Only owner can delete
    if (strcmp(entry->metadata.owner, username) != 0) {
        char resp[MAX_BUFFER];
        create_error_response(resp, ERR_ACCESS_DENIED, "Only owner can delete");
        send_message(client_socket, resp);
        log_console("NM", "DELETE failed: User '%s' is not owner of '%s'\n", username, filename);
        log_audit(username, "DELETE", filename, "access denied - not owner", 0);
        pthread_mutex_unlock(&registry_lock);
        return;
    }
    
    int ss_id = entry->storage_server_id;
    
    remove_from_hash(filename);
    
    log_message("INFO", "File deleted: %s by %s", filename, username);
    log_audit(username, "DELETE", filename, "file deleted successfully", 1);
    log_console("NM", "File '%s' deleted by '%s'\n", filename, username);
    
    pthread_mutex_unlock(&registry_lock);
    
    // Forward to SS
    char ss_response[MAX_BUFFER];
    if (forward_to_ss(ss_id, message, ss_response) < 0) {
        create_error_response(ss_response, ERR_SERVER_UNAVAILABLE, "Storage server unavailable");
        log_audit(username, "DELETE", filename, "storage server unavailable", 0);
    }
    
    send_message(client_socket, ss_response);
}

void handle_view_files(int client_socket, const char *msg) {
    char username[MAX_USERNAME] = "";
    char flags[32] = "";
    char filename[MAX_FILENAME] = "";

    // Local buffer to avoid modifying original
    char buf[MAX_BUFFER];
    strncpy(buf, msg, sizeof(buf));

    // Split into lines
    char *line = strtok(buf, "\n");

    while (line) {
        if (strncmp(line, "USER:", 5) == 0) {
            strcpy(username, line + 5);
        }
        else if (strncmp(line, "FLAGS:", 6) == 0) {
            strcpy(flags, line + 6);
        }
        else if (strncmp(line, "FILENAME:", 9) == 0) {
            strcpy(filename, line + 9);
        }
        line = strtok(NULL, "\n");
    }

    // Trim spaces
    for (int i = strlen(flags) - 1; i >= 0 && isspace(flags[i]); i--)
        flags[i] = 0;

    int show_all = strchr(flags, 'a') != NULL;
    int show_long = strchr(flags, 'l') != NULL;

    pthread_mutex_lock(&registry_lock);

    char response[MAX_BUFFER * 5];
    size_t resp_len = 0;
    if (show_long) {
        resp_len = snprintf(response, sizeof(response),
            "TYPE:response\nERROR_CODE:0\nDATA:\n"
            "---------------------------------------------------------\n"
            "|  Filename  | Words | Chars | Last Access Time | Owner |\n"
            "|------------|-------|-------|------------------|-------|\n"
        );
    } else {
        resp_len = snprintf(response, sizeof(response), "TYPE:response\nERROR_CODE:0\nDATA:");
    }

    // If a specific filename was requested, only show that file
    if (filename[0] != '\0') {
        FileEntry *entry = find_file_optimized(filename);
        if (entry) {
            int has_access = (strcmp(entry->metadata.owner, username) == 0);
            for (int j = 0; j < entry->acl_count && !has_access; j++) {
                if (strcmp(entry->acl[j].username, username) == 0)
                    has_access = 1;
            }

            if (has_access || show_all) {
                // Refresh metadata
                send_and_receive_metadata(entry->filename, &entry->metadata);
                if (show_long) {
                    char linebuf[256];
                    int line_len = snprintf(linebuf, sizeof(linebuf),
                        "| %-10s | %5d | %5d | %16s | %-5s |\n",
                        entry->filename, entry->metadata.word_count,
                        entry->metadata.char_count, entry->metadata.last_accessed,
                        entry->metadata.owner
                    );
                    if (resp_len + line_len < sizeof(response)) {
                        strncat(response, linebuf, sizeof(response) - resp_len - 1);
                        resp_len += line_len;
                    }
                } else {
                    const char *arrow = "\n--> ";
                    size_t arrow_len = strlen(arrow);
                    size_t fname_len = strlen(entry->filename);
                    if (resp_len + arrow_len + fname_len < sizeof(response)) {
                        strncat(response, arrow, sizeof(response) - resp_len - 1);
                        resp_len += arrow_len;
                        strncat(response, entry->filename, sizeof(response) - resp_len - 1);
                        resp_len += fname_len;
                    }
                }
            }
        }
    } else {
        // Iterate files
        for (int h = 0; h < HASH_SIZE; h++) {
            FileNode *node = hash_table[h];
            int max_iters = 10000; // Prevent infinite loop if corrupted
            while (node && max_iters-- > 0) {
                FileEntry *entry = &node->entry;
                if (!entry) {
                    log_message("ERROR", "Null entry detected in hash table at bucket %d", h);
                    break;
                }
                int has_access = (strcmp(entry->metadata.owner, username) == 0);
                for (int j = 0; j < entry->acl_count && !has_access; j++) {
                    if (strcmp(entry->acl[j].username, username) == 0)
                        has_access = 1;
                }
                if (has_access || show_all) {
                    // Request latest metadata from storage server before showing details
                    send_and_receive_metadata(entry->filename, &entry->metadata);
                    if (show_long) {
                        char linebuf[256];
                        int line_len = snprintf(linebuf, sizeof(linebuf),
                            "| %-10s | %5d | %5d | %16s | %-5s |\n",
                            entry->filename, entry->metadata.word_count,
                            entry->metadata.char_count, entry->metadata.last_accessed,
                            entry->metadata.owner
                        );
                        if (resp_len + line_len < sizeof(response)) {
                            strncat(response, linebuf, sizeof(response) - resp_len - 1);
                            resp_len += line_len;
                        }
                    } else {
                        const char *arrow = "\n--> ";
                        size_t arrow_len = strlen(arrow);
                        size_t fname_len = strlen(entry->filename);
                        if (resp_len + arrow_len + fname_len < sizeof(response)) {
                            strncat(response, arrow, sizeof(response) - resp_len - 1);
                            resp_len += arrow_len;
                            strncat(response, entry->filename, sizeof(response) - resp_len - 1);
                            resp_len += fname_len;
                        }
                    }
                }
                node = node->next;
            }
            if (max_iters <= 0) {
                log_message("ERROR", "Cycle detected in hash table bucket %d, breaking loop", h);
            }
        }
    }

    if (show_long)
        strncat(response, "---------------------------------------------------------\n", sizeof(response) - resp_len - 1);
    else
        strncat(response, "\n", sizeof(response) - resp_len - 1);

    send_message(client_socket, response);

    log_message("INFO", "VIEW by %s (flags: %s, file: %s)",
                username, flags, filename);

    pthread_mutex_unlock(&registry_lock);
}



void handle_info(int client_socket, const char *message) {
    char username[MAX_USERNAME], filename[MAX_FILENAME];
    sscanf(message, "TYPE:INFO\nUSER:%s\nFILENAME:%s", username, filename);
    
    pthread_mutex_lock(&registry_lock);
    
    FileEntry *entry = find_file_optimized(filename);
    if (!entry) {
        char response[MAX_BUFFER];
        create_error_response(response, ERR_FILE_NOT_FOUND, "File not found");
        send_message(client_socket, response);
        pthread_mutex_unlock(&registry_lock);
        return;
    }

    // Always fetch latest metadata from Storage Server
    send_and_receive_metadata(filename, &entry->metadata);

    char response[MAX_BUFFER * 2];
    snprintf(response, sizeof(response),
        "TYPE:response\nERROR_CODE:0\nDATA:\n"
        "--> File: %s\n"
        "--> Owner: %s\n"
        "--> Created: %s\n"
        "--> Last Modified: %s\n"
        "--> Size: %d bytes\n"
        "--> Last Accessed: %s by %s\n"
        "--> Access:",
        entry->filename, entry->metadata.owner, entry->metadata.created,
        entry->metadata.last_modified, entry->metadata.size_bytes,
        entry->metadata.last_accessed, entry->metadata.last_accessed_by);

    size_t resp_len = strlen(response);
    for (int i = 0; i < entry->acl_count; i++) {
        const char *space = " ";
        const char *open = " (";
        const char *close = ")";
        const char *comma = ",";
        size_t uname_len = strlen(entry->acl[i].username);
        size_t atype_len = strlen(entry->acl[i].access_type);
        if (resp_len + 1 + uname_len + 2 + atype_len + 1 < sizeof(response)) {
            strncat(response, space, sizeof(response) - resp_len - 1);
            resp_len += 1;
            strncat(response, entry->acl[i].username, sizeof(response) - resp_len - 1);
            resp_len += uname_len;
            strncat(response, open, sizeof(response) - resp_len - 1);
            resp_len += 2;
            strncat(response, entry->acl[i].access_type, sizeof(response) - resp_len - 1);
            resp_len += atype_len;
            strncat(response, close, sizeof(response) - resp_len - 1);
            resp_len += 1;
            if (i < entry->acl_count - 1) {
                strncat(response, comma, sizeof(response) - resp_len - 1);
                resp_len += 1;
            }
        }
    }
    strncat(response, "\n", sizeof(response) - resp_len - 1);

    send_message(client_socket, response);
    log_message("INFO", "INFO: %s by %s", filename, username);

    pthread_mutex_unlock(&registry_lock);
}

void handle_list_users(int client_socket) {
    pthread_mutex_lock(&client_lock);
    
    char response[MAX_BUFFER * 2] = "TYPE:response\nERROR_CODE:0\nDATA:";
    
    // Use a simple array to track unique usernames
    char unique_users[MAX_CLIENTS][MAX_USERNAME];
    int unique_count = 0;
    
    for (int i = 0; i < client_count; i++) {
        // Check if this username is already in our unique list
        int found = 0;
        for (int j = 0; j < unique_count; j++) {
            if (strcmp(unique_users[j], connected_clients[i].username) == 0) {
                found = 1;
                break;
            }
        }
        
        // If not found, add it to unique list
        if (!found && unique_count < MAX_CLIENTS) {
            strcpy(unique_users[unique_count], connected_clients[i].username);
            unique_count++;
        }
    }
    
    // Build response with unique usernames only
    for (int i = 0; i < unique_count; i++) {
        strcat(response, "\n--> ");
        strcat(response, unique_users[i]);
    }
    strcat(response, "\n");
    
    send_message(client_socket, response);
    log_message("INFO", "LIST users");
    
    pthread_mutex_unlock(&client_lock);
}

void handle_addaccess(int client_socket, const char *message) {
    char username[MAX_USERNAME], filename[MAX_FILENAME], target_user[MAX_USERNAME], access_type[10];
    sscanf(message, "TYPE:ADDACCESS\nUSER:%s\nFILENAME:%s\nTARGET:%s\nACCESS:%s", 
        username, filename, target_user, access_type);
    
    // Validate target username (no special characters that could break protocol)
    for (int i = 0; target_user[i]; i++) {
        if (target_user[i] == '\n' || target_user[i] == ':' || target_user[i] == '\\') {
            char response[MAX_BUFFER];
            create_error_response(response, ERR_GENERAL, "Username contains invalid characters");
            send_message(client_socket, response);
            log_message("ERROR", "ADDACCESS: Invalid username '%s' (contains special chars)", target_user);
            return;
        }
    }
    
    pthread_mutex_lock(&registry_lock);
    
    FileEntry *entry = find_file_optimized(filename);
    if (!entry) {
        char resp[MAX_BUFFER];
        create_error_response(resp, ERR_FILE_NOT_FOUND, "File not found");
        send_message(client_socket, resp);
        pthread_mutex_unlock(&registry_lock);
        return;
    }
    
    // Only owner can grant access
    if (strcmp(entry->metadata.owner, username) != 0) {
        char resp[MAX_BUFFER];
        create_error_response(resp, ERR_ACCESS_DENIED, "Only owner can grant access");
        send_message(client_socket, resp);
        log_console("NM", "ADDACCESS failed: User '%s' is not owner of '%s'\n", username, filename);
        pthread_mutex_unlock(&registry_lock);
        return;
    }
    
    // Validate target user exists (check connected clients)
    pthread_mutex_lock(&client_lock);
    int user_exists = 0;
    for (int i = 0; i < client_count; i++) {
        if (strcmp(connected_clients[i].username, target_user) == 0) {
            user_exists = 1;
            break;
        }
    }
    pthread_mutex_unlock(&client_lock);
    
    // Allow granting access even if user not currently connected (for future access)
    // But log a warning
    if (!user_exists) {
        log_message("INFO", "ADDACCESS: Granting access to user '%s' who is not currently connected", target_user);
    }
    
    // Check if user already has access
    int found = 0;
    for (int i = 0; i < entry->acl_count; i++) {
        if (strcmp(entry->acl[i].username, target_user) == 0) {
            strcpy(entry->acl[i].access_type, access_type);
            found = 1;
            break;
        }
    }
    
    if (!found && entry->acl_count < MAX_USERS) {
        strcpy(entry->acl[entry->acl_count].username, target_user);
        strcpy(entry->acl[entry->acl_count].access_type, access_type);
        entry->acl_count++;
    }
    
    char resp[MAX_BUFFER];
    create_response(resp, ERR_SUCCESS, "Access granted successfully");
    send_message(client_socket, resp);
    
    log_message("INFO", "ADDACCESS: %s granted %s access to %s on %s", 
        username, access_type, target_user, filename);
    log_console("NM", "Access granted: '%s' -> '%s' (%s) on '%s'\n", 
        username, target_user, access_type, filename);
    
    pthread_mutex_unlock(&registry_lock);
}

void handle_remaccess(int client_socket, const char *message) {
    char username[MAX_USERNAME], filename[MAX_FILENAME], target_user[MAX_USERNAME];
    sscanf(message, "TYPE:REMACCESS\nUSER:%s\nFILENAME:%s\nTARGET:%s", 
        username, filename, target_user);
    
    pthread_mutex_lock(&registry_lock);
    
    FileEntry *entry = find_file_optimized(filename);
    if (!entry) {
        char resp[MAX_BUFFER];
        create_error_response(resp, ERR_FILE_NOT_FOUND, "File not found");
        send_message(client_socket, resp);
        pthread_mutex_unlock(&registry_lock);
        return;
    }
    
    // Only owner can remove access
    if (strcmp(entry->metadata.owner, username) != 0) {
        char resp[MAX_BUFFER];
        create_error_response(resp, ERR_ACCESS_DENIED, "Only owner can remove access");
        send_message(client_socket, resp);
        pthread_mutex_unlock(&registry_lock);
        return;
    }
    
    // Owner cannot remove themselves
    if (strcmp(entry->metadata.owner, target_user) == 0) {
        char resp[MAX_BUFFER];
        create_error_response(resp, ERR_GENERAL, "Owner cannot remove self access");
        send_message(client_socket, resp);
        pthread_mutex_unlock(&registry_lock);
        return;
    }
    
    // Remove from ACL
    for (int i = 0; i < entry->acl_count; i++) {
        if (strcmp(entry->acl[i].username, target_user) == 0) {
            // Shift remaining entries
            for (int j = i; j < entry->acl_count - 1; j++) {
                entry->acl[j] = entry->acl[j + 1];
            }
            entry->acl_count--;
            break;
        }
    }
    
    char resp[MAX_BUFFER];
    create_response(resp, ERR_SUCCESS, "Access removed successfully");
    send_message(client_socket, resp);
    
    log_message("INFO", "REMACCESS: %s removed %s from %s", username, target_user, filename);
    log_console("NM", "Access removed: '%s' removed '%s' from '%s'\n", username, target_user, filename);
    
    pthread_mutex_unlock(&registry_lock);
}

// ======== ACCESS REQUEST HANDLERS (BONUS FEATURE) ========

void handle_requestaccess(int client_socket, const char *message) {
    char username[MAX_USERNAME], filename[MAX_FILENAME], perm_str[8];
    sscanf(message, "TYPE:REQUESTACCESS\nUSER:%s\nFILENAME:%s\nPERMISSION:%s", 
        username, filename, perm_str);
    
    pthread_mutex_lock(&registry_lock);
    
    FileEntry *entry = find_file_optimized(filename);
    if (!entry) {
        char resp[MAX_BUFFER];
        create_error_response(resp, ERR_FILE_NOT_FOUND, "File not found");
        send_message(client_socket, resp);
        pthread_mutex_unlock(&registry_lock);
        return;
    }
    
    // Can't request access to your own file
    if (strcmp(entry->metadata.owner, username) == 0) {
        char resp[MAX_BUFFER];
        create_error_response(resp, ERR_GENERAL, "You already own this file");
        send_message(client_socket, resp);
        pthread_mutex_unlock(&registry_lock);
        return;
    }
    
    pthread_mutex_unlock(&registry_lock);
    
    // Add to request queue
    pthread_mutex_lock(&request_lock);
    
    // Check if request already exists
    for (int i = 0; i < request_count; i++) {
        if (strcmp(access_requests[i].filename, filename) == 0 &&
            strcmp(access_requests[i].requester, username) == 0 &&
            access_requests[i].status == REQUEST_PENDING) {
            char resp[MAX_BUFFER];
            create_error_response(resp, ERR_GENERAL, "Request already pending");
            send_message(client_socket, resp);
            pthread_mutex_unlock(&request_lock);
            return;
        }
    }
    
    if (request_count >= MAX_REQUESTS) {
        char resp[MAX_BUFFER];
        create_error_response(resp, ERR_GENERAL, "Too many pending requests");
        send_message(client_socket, resp);
        pthread_mutex_unlock(&request_lock);
        return;
    }
    
    // Create new request
    AccessRequest *req = &access_requests[request_count++];
    strncpy(req->filename, filename, MAX_FILENAME);
    strncpy(req->requester, username, MAX_USERNAME);
    req->permission = (strcmp(perm_str, "W") == 0) ? PERM_WRITE : PERM_READ;
    strncpy(req->timestamp, get_timestamp(), 64);
    req->status = REQUEST_PENDING;
    
    char resp[MAX_BUFFER];
    snprintf(resp, MAX_BUFFER, 
        "TYPE:response\nERROR_CODE:0\nDATA:Access request sent to owner\n");
    send_message(client_socket, resp);
    
    log_message("INFO", "REQUESTACCESS: %s requested %s access to %s", 
        username, perm_str, filename);
    log_console("NM", "Access requested: '%s' for %s on '%s'\n", username, perm_str, filename);
    
    pthread_mutex_unlock(&request_lock);
}

void handle_viewrequests(int client_socket, const char *message) {
    char username[MAX_USERNAME], filename[MAX_FILENAME] = "";
    
    // Parse username (required)
    if (sscanf(message, "TYPE:VIEWREQUESTS\nUSER:%s", username) < 1) {
        char resp[MAX_BUFFER];
        create_error_response(resp, ERR_GENERAL, "Invalid request format");
        send_message(client_socket, resp);
        return;
    }
    
    // Try to parse filename (optional)
    char *filename_ptr = strstr(message, "FILENAME:");
    if (filename_ptr) {
        sscanf(filename_ptr, "FILENAME:%s", filename);
    }
    
    pthread_mutex_lock(&registry_lock);
    pthread_mutex_lock(&request_lock);
    
    char resp[MAX_BUFFER * 2];
    int offset = sprintf(resp, "TYPE:response\nERROR_CODE:0\nDATA:");
    
    int found = 0;
    for (int i = 0; i < request_count; i++) {
        AccessRequest *req = &access_requests[i];
        
        // Skip if not pending
        if (req->status != REQUEST_PENDING) continue;
        
        // Check if this file belongs to the user
        FileEntry *entry = find_file_optimized(req->filename);
        if (!entry || strcmp(entry->metadata.owner, username) != 0) continue;
        
        // If filename specified, filter by it
        if (strlen(filename) > 0 && strcmp(req->filename, filename) != 0) continue;
        
        offset += snprintf(resp + offset, MAX_BUFFER * 2 - offset,
            "\n--> Request #%d: %s wants %s access to %s (at %s)",
            i, req->requester, 
            (req->permission == PERM_WRITE) ? "WRITE" : "READ",
            req->filename, req->timestamp);
        found++;
    }
    
    if (!found) {
        offset += snprintf(resp + offset, MAX_BUFFER * 2 - offset,
            "\nNo pending requests");
    }
    
    strcat(resp, "\n");
    send_message(client_socket, resp);
    
    pthread_mutex_unlock(&request_lock);
    pthread_mutex_unlock(&registry_lock);
}

void handle_approverequest(int client_socket, const char *message) {
    char username[MAX_USERNAME], filename[MAX_FILENAME], requester[MAX_USERNAME];
    sscanf(message, "TYPE:APPROVEREQUEST\nUSER:%s\nFILENAME:%s\nREQUESTER:%s", 
        username, filename, requester);
    
    pthread_mutex_lock(&registry_lock);
    
    FileEntry *entry = find_file_optimized(filename);
    if (!entry) {
        char resp[MAX_BUFFER];
        create_error_response(resp, ERR_FILE_NOT_FOUND, "File not found");
        send_message(client_socket, resp);
        pthread_mutex_unlock(&registry_lock);
        return;
    }
    
    // Only owner can approve
    if (strcmp(entry->metadata.owner, username) != 0) {
        char resp[MAX_BUFFER];
        create_error_response(resp, ERR_ACCESS_DENIED, "Only owner can approve requests");
        send_message(client_socket, resp);
        pthread_mutex_unlock(&registry_lock);
        return;
    }
    
    pthread_mutex_lock(&request_lock);
    
    // Find the request
    AccessRequest *req = NULL;
    int req_idx = -1;
    for (int i = 0; i < request_count; i++) {
        if (strcmp(access_requests[i].filename, filename) == 0 &&
            strcmp(access_requests[i].requester, requester) == 0 &&
            access_requests[i].status == REQUEST_PENDING) {
            req = &access_requests[i];
            req_idx = i;
            break;
        }
    }
    
    if (!req) {
        char resp[MAX_BUFFER];
        create_error_response(resp, ERR_GENERAL, "No pending request found");
        send_message(client_socket, resp);
        pthread_mutex_unlock(&request_lock);
        pthread_mutex_unlock(&registry_lock);
        return;
    }
    
    // Grant access via ACL
    if (entry->acl_count < MAX_USERS) {
        strncpy(entry->acl[entry->acl_count].username, requester, MAX_USERNAME);
        if (req->permission == PERM_WRITE) {
            strcpy(entry->acl[entry->acl_count].access_type, "RW");
        } else {
            strcpy(entry->acl[entry->acl_count].access_type, "R");
        }
        entry->acl_count++;
    }
    
    // Mark request as approved
    req->status = REQUEST_APPROVED;
    
    char resp[MAX_BUFFER];
    snprintf(resp, MAX_BUFFER, 
        "TYPE:response\nERROR_CODE:0\nDATA:Request approved, access granted to %s\n\n",
        requester);
    send_message(client_socket, resp);
    
    log_message("INFO", "APPROVEREQUEST: %s approved %s for %s on %s", 
        username, requester, 
        (req->permission == PERM_WRITE) ? "RW" : "R", filename);
    log_console("NM", "Request approved: %s granted access to '%s' on '%s'\n", 
        username, requester, filename);
    
    pthread_mutex_unlock(&request_lock);
    pthread_mutex_unlock(&registry_lock);
}

void handle_denyrequest(int client_socket, const char *message) {
    char username[MAX_USERNAME], filename[MAX_FILENAME], requester[MAX_USERNAME];
    sscanf(message, "TYPE:DENYREQUEST\nUSER:%s\nFILENAME:%s\nREQUESTER:%s", 
        username, filename, requester);
    
    pthread_mutex_lock(&registry_lock);
    
    FileEntry *entry = find_file_optimized(filename);
    if (!entry) {
        char resp[MAX_BUFFER];
        create_error_response(resp, ERR_FILE_NOT_FOUND, "File not found");
        send_message(client_socket, resp);
        pthread_mutex_unlock(&registry_lock);
        return;
    }
    
    // Only owner can deny
    if (strcmp(entry->metadata.owner, username) != 0) {
        char resp[MAX_BUFFER];
        create_error_response(resp, ERR_ACCESS_DENIED, "Only owner can deny requests");
        send_message(client_socket, resp);
        pthread_mutex_unlock(&registry_lock);
        return;
    }
    
    pthread_mutex_lock(&request_lock);
    
    // Find the request
    AccessRequest *req = NULL;
    for (int i = 0; i < request_count; i++) {
        if (strcmp(access_requests[i].filename, filename) == 0 &&
            strcmp(access_requests[i].requester, requester) == 0 &&
            access_requests[i].status == REQUEST_PENDING) {
            req = &access_requests[i];
            break;
        }
    }
    
    if (!req) {
        char resp[MAX_BUFFER];
        create_error_response(resp, ERR_GENERAL, "No pending request found");
        send_message(client_socket, resp);
        pthread_mutex_unlock(&request_lock);
        pthread_mutex_unlock(&registry_lock);
        return;
    }
    
    // Mark request as denied
    req->status = REQUEST_DENIED;
    
    char resp[MAX_BUFFER];
    snprintf(resp, MAX_BUFFER, 
        "TYPE:response\nERROR_CODE:0\nDATA:Request denied for %s\n\n", requester);
    send_message(client_socket, resp);
    
    log_message("INFO", "DENYREQUEST: %s denied %s on %s", username, requester, filename);
    log_console("NM", "Request denied: %s denied '%s' access to '%s'\n", 
        username, requester, filename);
    
    pthread_mutex_unlock(&request_lock);
    pthread_mutex_unlock(&registry_lock);
}

// ======== END ACCESS REQUEST HANDLERS ========

// ======== FOLDER HANDLERS (BONUS FEATURE) ========

void handle_createfolder(int client_socket, const char *message) {
    char username[MAX_USERNAME], folder_path[MAX_PATH];
    sscanf(message, "TYPE:CREATEFOLDER\nUSER:%s\nPATH:%s", username, folder_path);
    
    normalize_path(folder_path);
    
    pthread_mutex_lock(&folder_lock);
    
    // Check if folder already exists
    if (find_folder(folder_path)) {
        char resp[MAX_BUFFER];
        create_error_response(resp, ERR_FILE_EXISTS, "Folder already exists");
        send_message(client_socket, resp);
        pthread_mutex_unlock(&folder_lock);
        return;
    }
    
    // Create folder entry
    if (create_folder_entry(folder_path, username) < 0) {
        char resp[MAX_BUFFER];
        create_error_response(resp, ERR_GENERAL, "Too many folders");
        send_message(client_socket, resp);
        pthread_mutex_unlock(&folder_lock);
        return;
    }
    
    pthread_mutex_unlock(&folder_lock);
    
    // Forward to storage server to create physical directory
    int ss_id = get_available_ss();
    if (ss_id < 0) {
        char resp[MAX_BUFFER];
        create_error_response(resp, ERR_SERVER_UNAVAILABLE, "No storage server available");
        send_message(client_socket, resp);
        return;
    }
    
    char ss_msg[MAX_BUFFER];
    snprintf(ss_msg, sizeof(ss_msg), "TYPE:CREATEFOLDER\nPATH:%s", folder_path);
    
    char ss_response[MAX_BUFFER];
    if (forward_to_ss(ss_id, ss_msg, ss_response) < 0) {
        char resp[MAX_BUFFER];
        create_error_response(resp, ERR_SERVER_UNAVAILABLE, "Failed to create folder on storage");
        send_message(client_socket, resp);
        return;
    }
    
    char resp[MAX_BUFFER];
    create_response(resp, ERR_SUCCESS, "Folder created successfully");
    send_message(client_socket, resp);
    
    log_message("INFO", "CREATEFOLDER: %s created '%s'", username, folder_path);
    log_console("NM", "Folder created: '%s' by %s\n", folder_path, username);
}

void handle_move(int client_socket, const char *message) {
    char username[MAX_USERNAME], filename[MAX_FILENAME], dest_folder[MAX_PATH];
    sscanf(message, "TYPE:MOVE\nUSER:%s\nFILENAME:%s\nDEST:%s", 
        username, filename, dest_folder);
    
    normalize_path(dest_folder);
    
    pthread_mutex_lock(&registry_lock);
    pthread_mutex_lock(&folder_lock);
    
    FileEntry *entry = find_file_optimized(filename);
    if (!entry) {
        char resp[MAX_BUFFER];
        create_error_response(resp, ERR_FILE_NOT_FOUND, "File not found");
        send_message(client_socket, resp);
        pthread_mutex_unlock(&folder_lock);
        pthread_mutex_unlock(&registry_lock);
        return;
    }
    
    // Check if user is owner
    if (strcmp(entry->metadata.owner, username) != 0) {
        char resp[MAX_BUFFER];
        create_error_response(resp, ERR_ACCESS_DENIED, "Only owner can move file");
        send_message(client_socket, resp);
        pthread_mutex_unlock(&folder_lock);
        pthread_mutex_unlock(&registry_lock);
        return;
    }
    
    // Check if destination folder exists
    if (strlen(dest_folder) > 0 && !find_folder(dest_folder)) {
        char resp[MAX_BUFFER];
        create_error_response(resp, ERR_FILE_NOT_FOUND, "Destination folder does not exist");
        send_message(client_socket, resp);
        pthread_mutex_unlock(&folder_lock);
        pthread_mutex_unlock(&registry_lock);
        return;
    }
    
    // Forward to storage server
    int ss_id = entry->storage_server_id;
    char ss_msg[MAX_BUFFER];
    snprintf(ss_msg, sizeof(ss_msg), "TYPE:MOVE\nFILENAME:%s\nSRC:%s\nDEST:%s", 
        filename, entry->folder_path, dest_folder);
    
    char ss_response[MAX_BUFFER];
    if (forward_to_ss(ss_id, ss_msg, ss_response) < 0) {
        char resp[MAX_BUFFER];
        create_error_response(resp, ERR_SERVER_UNAVAILABLE, "Failed to move file on storage");
        send_message(client_socket, resp);
        pthread_mutex_unlock(&folder_lock);
        pthread_mutex_unlock(&registry_lock);
        return;
    }
    
    // Update folder path in registry
    strncpy(entry->folder_path, dest_folder, MAX_PATH);
    
    char resp[MAX_BUFFER];
    create_response(resp, ERR_SUCCESS, "File moved successfully");
    send_message(client_socket, resp);
    
    log_message("INFO", "MOVE: %s moved '%s' to '%s'", username, filename, dest_folder);
    log_console("NM", "File moved: '%s' to '%s' by %s\n", filename, dest_folder, username);
    
    pthread_mutex_unlock(&folder_lock);
    pthread_mutex_unlock(&registry_lock);
}

void handle_viewfolder(int client_socket, const char *message) {
    char username[MAX_USERNAME], folder_path[MAX_PATH] = "";
    
    // Parse - folder path is optional (empty = root)
    if (sscanf(message, "TYPE:VIEWFOLDER\nUSER:%s\nPATH:%s", username, folder_path) < 1) {
        sscanf(message, "TYPE:VIEWFOLDER\nUSER:%s", username);
    }
    
    normalize_path(folder_path);
    
    pthread_mutex_lock(&registry_lock);
    pthread_mutex_lock(&folder_lock);
    
    char resp[MAX_BUFFER * 2];
    int offset = sprintf(resp, "TYPE:response\nERROR_CODE:0\nDATA:");
    
    // List folders in this path
    int found_folders = 0;
    for (int i = 0; i < folder_count; i++) {
        // Check if this folder is in the requested path
        if (strlen(folder_path) == 0) {
            // Root - show top-level folders (no slashes in path)
            if (strchr(folders[i].path, '/') == NULL) {
                offset += snprintf(resp + offset, MAX_BUFFER * 2 - offset,
                    "\n[DIR]  %s/ (owner: %s)", folders[i].path, folders[i].owner);
                found_folders++;
            }
        } else {
            // Show subfolders of this folder
            int path_len = strlen(folder_path);
            if (strncmp(folders[i].path, folder_path, path_len) == 0 &&
                folders[i].path[path_len] == '/') {
                // Check if it's a direct child (no more slashes after)
                char *remaining = folders[i].path + path_len + 1;
                if (strchr(remaining, '/') == NULL) {
                    offset += snprintf(resp + offset, MAX_BUFFER * 2 - offset,
                        "\n[DIR]  %s/ (owner: %s)", folders[i].path, folders[i].owner);
                    found_folders++;
                }
            }
        }
    }
    
    // List files in this folder
    int found_files = 0;
    for (int i = 0; i < HASH_SIZE; i++) {
        FileNode *node = hash_table[i];
        while (node) {
            FileEntry *entry = &node->entry;
            
            // Check if file is in this folder
            if (strcmp(entry->folder_path, folder_path) == 0) {
                // Check if user has access
                int has_access = (strcmp(entry->metadata.owner, username) == 0);
                for (int j = 0; j < entry->acl_count; j++) {
                    if (strcmp(entry->acl[j].username, username) == 0) {
                        has_access = 1;
                        break;
                    }
                }
                
                if (has_access) {
                    offset += snprintf(resp + offset, MAX_BUFFER * 2 - offset,
                        "\n[FILE] %s (owner: %s, %d words)", 
                        entry->filename, entry->metadata.owner, entry->metadata.word_count);
                    found_files++;
                }
            }
            
            node = node->next;
        }
    }
    
    if (found_folders == 0 && found_files == 0) {
        offset += snprintf(resp + offset, MAX_BUFFER * 2 - offset,
            "\nEmpty folder");
    }
    
    strcat(resp, "\n");
    send_message(client_socket, resp);
    
    pthread_mutex_unlock(&folder_lock);
    pthread_mutex_unlock(&registry_lock);
}

// ======== END FOLDER HANDLERS ========

void handle_exec(int client_socket, const char *message) {
    char username[MAX_USERNAME], filename[MAX_FILENAME];
    sscanf(message, "TYPE:EXEC\nUSER:%s\nFILENAME:%s", username, filename);
    
    pthread_mutex_lock(&registry_lock);
    
    FileEntry *entry = find_file_optimized(filename);
    if (!entry) {
        char resp[MAX_BUFFER];
        create_error_response(resp, ERR_FILE_NOT_FOUND, "File not found");
        send_message(client_socket, resp);
        log_console("NM", "EXEC failed: File '%s' not found\n", filename);
        pthread_mutex_unlock(&registry_lock);
        return;
    }
    
    // ACL check - need read access
    int has_access = (strcmp(entry->metadata.owner, username) == 0);
    for (int j = 0; j < entry->acl_count; j++) {
        if (strcmp(entry->acl[j].username, username) == 0 && 
            strchr(entry->acl[j].access_type, 'R')) {
            has_access = 1;
            break;
        }
    }
    
    if (!has_access) {
        char resp[MAX_BUFFER];
        create_error_response(resp, ERR_ACCESS_DENIED, "No read access");
        send_message(client_socket, resp);
        log_console("NM", "EXEC failed: User '%s' has no access to '%s'\n", username, filename);
        pthread_mutex_unlock(&registry_lock);
        return;
    }
    
    int ss_id = entry->storage_server_id;
    
    pthread_mutex_unlock(&registry_lock);
    
    // Get file content from SS (include USER field for compatibility)
    char read_msg[MAX_BUFFER];
    snprintf(read_msg, sizeof(read_msg), "TYPE:READ\nUSER:%s\nFILENAME:%s", username, filename);
    char ss_response[MAX_BUFFER * 10];
    
    if (forward_to_ss(ss_id, read_msg, ss_response) < 0) {
        char resp[MAX_BUFFER];
        create_error_response(resp, ERR_SERVER_UNAVAILABLE, "Storage server unavailable");
        send_message(client_socket, resp);
        return;
    }
    
    // Extract content
    char *data_start = strstr(ss_response, "DATA:");
    if (!data_start) {
        char resp[MAX_BUFFER];
        create_error_response(resp, ERR_GENERAL, "Failed to read file");
        send_message(client_socket, resp);
        return;
    }
    data_start += 5; // Skip "DATA:"
    
    // Execute commands
    FILE *fp = popen(data_start, "r");
    if (fp == NULL) {
        char resp[MAX_BUFFER];
        create_error_response(resp, ERR_GENERAL, "Failed to execute commands");
        send_message(client_socket, resp);
        return;
    }
    
    char output[MAX_BUFFER * 5] = "TYPE:response\nERROR_CODE:0\nDATA:\n";
    char line[1024];
    while (fgets(line, sizeof(line), fp) != NULL) {
        strcat(output, line);
    }
    pclose(fp);
    
    send_message(client_socket, output);
    log_message("INFO", "EXEC: %s by %s", filename, username);
    log_console("NM", "EXEC: '%s' executed by '%s'\n", filename, username);
}

// ==================== CHECKPOINT SYSTEM ====================

void handle_checkpoint(int client_socket, const char *message) {
    char username[MAX_USERNAME], filename[MAX_FILENAME], tag[MAX_TAG_LENGTH] = "";
    sscanf(message, "TYPE:CHECKPOINT\nUSER:%s\nFILENAME:%s\nTAG:%[^\n]", 
        username, filename, tag);
    
    pthread_mutex_lock(&registry_lock);
    
    FileEntry *entry = find_file_optimized(filename);
    if (!entry) {
        char resp[MAX_BUFFER];
        create_error_response(resp, ERR_FILE_NOT_FOUND, "File not found");
        send_message(client_socket, resp);
        log_audit(username, "CHECKPOINT", filename, "file not found", 0);
        pthread_mutex_unlock(&registry_lock);
        return;
    }
    
    // Only owner can create checkpoints
    if (strcmp(entry->metadata.owner, username) != 0) {
        char resp[MAX_BUFFER];
        create_error_response(resp, ERR_ACCESS_DENIED, "Only owner can create checkpoints");
        send_message(client_socket, resp);
        log_audit(username, "CHECKPOINT", filename, "access denied - not owner", 0);
        pthread_mutex_unlock(&registry_lock);
        return;
    }
    
    int ss_id = entry->storage_server_id;
    pthread_mutex_unlock(&registry_lock);
    
    // Read current file content from storage server
    char read_msg[MAX_BUFFER];
    snprintf(read_msg, sizeof(read_msg), "TYPE:READ\nFILENAME:%s", filename);
    char ss_response[MAX_BUFFER * 10];
    
    if (forward_to_ss(ss_id, read_msg, ss_response) < 0) {
        char resp[MAX_BUFFER];
        create_error_response(resp, ERR_SERVER_UNAVAILABLE, "Storage server unavailable");
        send_message(client_socket, resp);
        return;
    }
    
    // Extract content
    char *data_start = strstr(ss_response, "DATA:");
    if (!data_start) {
        char resp[MAX_BUFFER];
        create_error_response(resp, ERR_GENERAL, "Failed to read file content");
        send_message(client_socket, resp);
        return;
    }
    data_start += 5; // Skip "DATA:"
    
    // Create checkpoint entry
    pthread_mutex_lock(&checkpoint_lock);
    
    if (checkpoint_count >= MAX_FILES * 10) {
        char resp[MAX_BUFFER];
        create_error_response(resp, ERR_GENERAL, "Checkpoint storage full");
        send_message(client_socket, resp);
        pthread_mutex_unlock(&checkpoint_lock);
        return;
    }
    
    // Find next version ID for this file
    int next_version = 1;
    for (int i = 0; i < checkpoint_count; i++) {
        if (strcmp(checkpoints[i].filename, filename) == 0) {
            if (checkpoints[i].version_id >= next_version) {
                next_version = checkpoints[i].version_id + 1;
            }
        }
    }
    
    CheckpointEntry *ckpt = &checkpoints[checkpoint_count++];
    ckpt->version_id = next_version;
    strncpy(ckpt->filename, filename, MAX_FILENAME);
    strncpy(ckpt->tag, tag, MAX_TAG_LENGTH);
    strncpy(ckpt->creator, username, MAX_USERNAME);
    strncpy(ckpt->timestamp, get_timestamp(), 64);
    strncpy(ckpt->content, data_start, MAX_CHECKPOINT_CONTENT - 1);
    ckpt->content[MAX_CHECKPOINT_CONTENT - 1] = '\0';
    
    pthread_mutex_lock(&registry_lock);
    ckpt->word_count = entry->metadata.word_count;
    ckpt->char_count = entry->metadata.char_count;
    pthread_mutex_unlock(&registry_lock);
    
    pthread_mutex_unlock(&checkpoint_lock);
    
    char resp[MAX_BUFFER];
    snprintf(resp, sizeof(resp), 
        "TYPE:response\nERROR_CODE:0\nDATA:Checkpoint v%d created%s%s\n\n",
        next_version, strlen(tag) > 0 ? " with tag: " : "", strlen(tag) > 0 ? tag : "");
    send_message(client_socket, resp);
    
    char details[256];
    snprintf(details, sizeof(details), "checkpoint v%d created%s%s", 
        next_version, strlen(tag) > 0 ? " with tag: " : "", strlen(tag) > 0 ? tag : "");
    log_audit(username, "CHECKPOINT", filename, details, 1);
    
    log_message("INFO", "CHECKPOINT: %s created v%d for '%s'%s%s", 
        username, next_version, filename, strlen(tag) > 0 ? " tag=" : "", tag);
    log_console("NM", "Checkpoint v%d created for '%s' by %s\n", next_version, filename, username);
}

void handle_listcheckpoints(int client_socket, const char *message) {
    char username[MAX_USERNAME], filename[MAX_FILENAME];
    sscanf(message, "TYPE:LISTCHECKPOINTS\nUSER:%s\nFILENAME:%s", username, filename);
    
    pthread_mutex_lock(&registry_lock);
    
    FileEntry *entry = find_file_optimized(filename);
    if (!entry) {
        char resp[MAX_BUFFER];
        create_error_response(resp, ERR_FILE_NOT_FOUND, "File not found");
        send_message(client_socket, resp);
        pthread_mutex_unlock(&registry_lock);
        return;
    }
    
    pthread_mutex_unlock(&registry_lock);
    
    pthread_mutex_lock(&checkpoint_lock);
    
    char resp[MAX_BUFFER * 4];
    int offset = sprintf(resp, "TYPE:response\nERROR_CODE:0\nDATA:");
    offset += sprintf(resp + offset, "Checkpoints for '%s':\n", filename);
    offset += sprintf(resp + offset, "%-8s %-20s %-20s %-30s\n", 
        "Version", "Created", "By", "Tag");
    offset += sprintf(resp + offset, "%s\n", "----------------------------------------------------------------------\n");
    
    int found = 0;
    for (int i = 0; i < checkpoint_count; i++) {
        if (strcmp(checkpoints[i].filename, filename) == 0) {
            offset += snprintf(resp + offset, MAX_BUFFER * 4 - offset,
                "v%-7d %-20s %-20s %s\n",
                checkpoints[i].version_id,
                checkpoints[i].timestamp,
                checkpoints[i].creator,
                strlen(checkpoints[i].tag) > 0 ? checkpoints[i].tag : "(no tag)");
            found++;
        }
    }
    
    if (found == 0) {
        offset += sprintf(resp + offset, "No checkpoints found.");
    } else {
        offset += sprintf(resp + offset, "\nTotal: %d checkpoint(s)\n", found);
    }
    
    strcat(resp, "\n");
    pthread_mutex_unlock(&checkpoint_lock);
    
    send_message(client_socket, resp);
    log_message("INFO", "LISTCHECKPOINTS: %s viewed checkpoints for '%s'", username, filename);
}

void handle_viewcheckpoint(int client_socket, const char *message) {
    char username[MAX_USERNAME], filename[MAX_FILENAME];
    char tag[MAX_TAG_LENGTH];
    sscanf(message, "TYPE:VIEWCHECKPOINT\nUSER:%s\nFILENAME:%s\nTAG:%s", 
        username, filename, tag);
    
    pthread_mutex_lock(&registry_lock);
    
    FileEntry *entry = find_file_optimized(filename);
    if (!entry) {
        char resp[MAX_BUFFER];
        create_error_response(resp, ERR_FILE_NOT_FOUND, "File not found");
        send_message(client_socket, resp);
        pthread_mutex_unlock(&registry_lock);
        return;
    }
    
    pthread_mutex_unlock(&registry_lock);
    
    pthread_mutex_lock(&checkpoint_lock);
    
    CheckpointEntry *ckpt = NULL;
    for (int i = 0; i < checkpoint_count; i++) {
        if (strcmp(checkpoints[i].filename, filename) == 0 && 
            strcmp(checkpoints[i].tag, tag) == 0) {
            ckpt = &checkpoints[i];
            break;
        }
    }
    
    if (!ckpt) {
        char resp[MAX_BUFFER];
        create_error_response(resp, ERR_FILE_NOT_FOUND, "Checkpoint not found");
        send_message(client_socket, resp);
        pthread_mutex_unlock(&checkpoint_lock);
        return;
    }
    
    char resp[MAX_BUFFER * 4];
    // Show content preview (first 1000 chars) to avoid buffer overflow
    char content_preview[1024];
    strncpy(content_preview, ckpt->content, 1000);
    content_preview[1000] = '\0';
    if (strlen(ckpt->content) > 1000) {
        strcat(content_preview, "\n...(content truncated)...");
    }
    
    snprintf(resp, sizeof(resp),
        "TYPE:response\nERROR_CODE:0\nDATA:\n"
        "=== Checkpoint v%d for '%s' ===\n"
        "Created: %s by %s\n"
        "Tag: %s\n"
        "Words: %d, Chars: %d\n"
        "--- Content ---\n%s\n\n",
        ckpt->version_id,
        ckpt->filename,
        ckpt->timestamp,
        ckpt->creator,
        strlen(ckpt->tag) > 0 ? ckpt->tag : "(no tag)",
        ckpt->word_count,
        ckpt->char_count,
        content_preview);
    
    pthread_mutex_unlock(&checkpoint_lock);
    
    send_message(client_socket, resp);
    log_message("INFO", "VIEWCHECKPOINT: %s viewed tag '%s' of '%s'", username, tag, filename);
}

void handle_revert(int client_socket, const char *message) {
    char username[MAX_USERNAME], filename[MAX_FILENAME];
    char tag[MAX_TAG_LENGTH];
    sscanf(message, "TYPE:REVERT\nUSER:%s\nFILENAME:%s\nTAG:%s", 
        username, filename, tag);
    
    pthread_mutex_lock(&registry_lock);
    
    FileEntry *entry = find_file_optimized(filename);
    if (!entry) {
        char resp[MAX_BUFFER];
        create_error_response(resp, ERR_FILE_NOT_FOUND, "File not found");
        send_message(client_socket, resp);
        log_audit(username, "REVERT", filename, "file not found", 0);
        pthread_mutex_unlock(&registry_lock);
        return;
    }
    
    // Only owner can revert
    if (strcmp(entry->metadata.owner, username) != 0) {
        char resp[MAX_BUFFER];
        create_error_response(resp, ERR_ACCESS_DENIED, "Only owner can revert file");
        send_message(client_socket, resp);
        log_audit(username, "REVERT", filename, "access denied - not owner", 0);
        pthread_mutex_unlock(&registry_lock);
        return;
    }
    
    int ss_id = entry->storage_server_id;
    pthread_mutex_unlock(&registry_lock);
    
    pthread_mutex_lock(&checkpoint_lock);
    
    CheckpointEntry *ckpt = NULL;
    for (int i = 0; i < checkpoint_count; i++) {
        if (strcmp(checkpoints[i].filename, filename) == 0 && 
            strcmp(checkpoints[i].tag, tag) == 0) {
            ckpt = &checkpoints[i];
            break;
        }
    }
    
    if (!ckpt) {
        char resp[MAX_BUFFER];
        create_error_response(resp, ERR_FILE_NOT_FOUND, "Checkpoint not found");
        send_message(client_socket, resp);
        char details[256];
        snprintf(details, sizeof(details), "checkpoint '%s' not found", tag);
        log_audit(username, "REVERT", filename, details, 0);
        pthread_mutex_unlock(&checkpoint_lock);
        return;
    }
    
    // Send revert command to storage server with checkpoint content
    // Dynamically allocate message to handle large checkpoint content safely
    size_t msg_size = strlen(filename) + strlen(ckpt->content) + 100;
    char *ss_msg = malloc(msg_size);
    if (!ss_msg) {
        char resp[MAX_BUFFER];
        create_error_response(resp, ERR_GENERAL, "Memory allocation failed");
        send_message(client_socket, resp);
        pthread_mutex_unlock(&checkpoint_lock);
        return;
    }
    snprintf(ss_msg, msg_size, 
        "TYPE:REVERT\nFILENAME:%s\nCONTENT:%s", filename, ckpt->content);
    
    pthread_mutex_unlock(&checkpoint_lock);
    
    char ss_response[MAX_BUFFER];
    if (forward_to_ss(ss_id, ss_msg, ss_response) < 0) {
        char resp[MAX_BUFFER];
        create_error_response(resp, ERR_SERVER_UNAVAILABLE, "Storage server unavailable");
        send_message(client_socket, resp);
        free(ss_msg);
        return;
    }
    free(ss_msg);
    
    // Update metadata
    pthread_mutex_lock(&registry_lock);
    entry->metadata.word_count = ckpt->word_count;
    entry->metadata.char_count = ckpt->char_count;
    strncpy(entry->metadata.last_modified, get_timestamp(), 64);
    pthread_mutex_unlock(&registry_lock);
    
    char resp[MAX_BUFFER];
    snprintf(resp, sizeof(resp),
        "TYPE:response\nERROR_CODE:0\nDATA:File reverted to checkpoint '%s'\n\n",
        tag);
    send_message(client_socket, resp);
    
    char details[256];
    snprintf(details, sizeof(details), "reverted to checkpoint '%s'", tag);
    log_audit(username, "REVERT", filename, details, 1);
    
    log_message("INFO", "REVERT: %s reverted '%s' to '%s'", username, filename, tag);
    log_console("NM", "File '%s' reverted to '%s' by %s\n", filename, tag, username);
}

// ==================== END CHECKPOINT SYSTEM ====================

void* client_thread(void *arg) {
    int client_socket = (intptr_t)arg;
    char *message;
    
    //log_message("DEBUG", "Client thread started for socket %d", client_socket);
    
    while (1) {
       // log_message("DEBUG", "Waiting for message on socket %d", client_socket);
	
    message = receive_message(client_socket);

    if (!message) break; // connection closed

    if (strlen(message) == 0) continue;

    // MUST ensure message has TYPE: before handling
    if (!strstr(message, "TYPE:")) {
        continue;
    }

       // log_message("DEBUG", "Received message on socket %d: %.50s...", client_socket, message);
        
        if (strncmp(message, "TYPE:REGISTER_CLIENT", 20) == 0) {
            register_client(client_socket, message);
        } else if (strncmp(message, "TYPE:REGISTER_SS", 16) == 0) {
            register_storage_server(client_socket, message);
        } else if (strncmp(message, "TYPE:REREGISTER_FILE", 20) == 0) {
            // Handle file re-registration after restart (for persistence)
            char filename[MAX_FILENAME], owner[MAX_USERNAME];
            int ss_id;
            sscanf(message, "TYPE:REREGISTER_FILE\nFILENAME:%s\nOWNER:%s\nSS_ID:%d", filename, owner, &ss_id);
            
            pthread_mutex_lock(&registry_lock);
            
            // Check if file already registered (avoid duplicates)
            FileEntry *existing = find_file_optimized(filename);
            if (!existing) {
                FileEntry entry;
                strcpy(entry.filename, filename);
                strcpy(entry.folder_path, "");
                entry.storage_server_id = ss_id;
                strcpy(entry.metadata.filename, filename);
                strcpy(entry.metadata.owner, owner);
                strcpy(entry.metadata.created, get_timestamp());
                strcpy(entry.metadata.last_modified, get_timestamp());
                strcpy(entry.metadata.last_accessed, get_timestamp());
                strcpy(entry.metadata.last_accessed_by, owner);
                entry.metadata.word_count = 0;
                entry.metadata.char_count = 0;
                entry.metadata.sentence_count = 0;
                entry.metadata.size_bytes = 0;
                
                strcpy(entry.acl[0].username, owner);
                strcpy(entry.acl[0].access_type, "RW");
                entry.acl_count = 1;
                
                add_to_hash(&entry);
                
                log_message("INFO", "Re-registered file: %s (owner: %s, SS: %d)", filename, owner, ss_id);
            }
            
           
             
            pthread_mutex_unlock(&registry_lock);
            
            // Send acknowledgment
            char resp[MAX_BUFFER];
            snprintf(resp, sizeof(resp), "TYPE:response\nERROR_CODE:0\nDATA:OK");
            send_message(client_socket, resp);
        } else if (strncmp(message, "TYPE:CREATEFOLDER", 17) == 0) {
            handle_createfolder(client_socket, message);
        } else if (strncmp(message, "TYPE:CREATE", 11) == 0) {
            handle_create_file(client_socket, message);
        } else if (strncmp(message, "TYPE:READ", 9) == 0) {
            handle_read_file(client_socket, message);
        } else if (strncmp(message, "TYPE:WRITE", 10) == 0) {
            handle_write_file(client_socket, message);
        } else if (strncmp(message, "TYPE:UPDATE_METADATA", 20) == 0) {
            log_message("INFO", "Received UPDATE_METADATA message");
            handle_update_metadata(message);
        } else if (strncmp(message, "TYPE:DELETE", 11) == 0) {
            handle_delete_file(client_socket, message);
        } else if (strncmp(message, "TYPE:VIEWREQUESTS", 17) == 0) {
            handle_viewrequests(client_socket, message);
        } else if (strncmp(message, "TYPE:VIEWCHECKPOINT", 19) == 0) {
            handle_viewcheckpoint(client_socket, message);
        } else if (strncmp(message, "TYPE:VIEWFOLDER", 15) == 0) {
            handle_viewfolder(client_socket, message);
        } else if (strncmp(message, "TYPE:VIEW", 9) == 0) {
            handle_view_files(client_socket, message);
        } else if (strncmp(message, "TYPE:INFO", 9) == 0) {
            handle_info(client_socket, message);
        } else if (strncmp(message, "TYPE:LISTCHECKPOINTS", 20) == 0) {
            handle_listcheckpoints(client_socket, message);
        } else if (strncmp(message, "TYPE:LIST", 9) == 0) {
            handle_list_users(client_socket);
        } else if (strncmp(message, "TYPE:ADDACCESS", 14) == 0) {
            handle_addaccess(client_socket, message);
        } else if (strncmp(message, "TYPE:REMACCESS", 14) == 0) {
            handle_remaccess(client_socket, message);
        } else if (strncmp(message, "TYPE:REQUESTACCESS", 18) == 0) {
            handle_requestaccess(client_socket, message);
        } else if (strncmp(message, "TYPE:APPROVEREQUEST", 19) == 0) {
            handle_approverequest(client_socket, message);
        } else if (strncmp(message, "TYPE:DENYREQUEST", 16) == 0) {
            handle_denyrequest(client_socket, message);
        } else if (strncmp(message, "TYPE:CHECKPOINT", 15) == 0) {
            handle_checkpoint(client_socket, message);
        } else if (strncmp(message, "TYPE:VIEWCHECKPOINT", 19) == 0) {
            handle_viewcheckpoint(client_socket, message);
        } else if (strncmp(message, "TYPE:REVERT", 11) == 0) {
            handle_revert(client_socket, message);
        } else if (strncmp(message, "TYPE:MOVE", 9) == 0) {
            handle_move(client_socket, message);
        } else if (strncmp(message, "TYPE:EXEC", 9) == 0) {
            handle_exec(client_socket, message);
        }
    }
    
    close(client_socket);
    return NULL;
}

// ==================== PERSISTENCE HANDLERS ====================
void save_nm_state() {
    FILE *f = fopen("nm_state.txt", "w");
    if (!f) return;

    pthread_mutex_lock(&registry_lock);
    
    // Save File Registry and ACLs
    for (int i = 0; i < HASH_SIZE; i++) {
        FileNode *node = hash_table[i];
        while (node) {
            FileEntry *e = &node->entry;
            fprintf(f, "FILE|%s|%s|%d|%s|%d\n", 
                e->filename, e->folder_path, e->storage_server_id, 
                e->metadata.owner, e->acl_count);
            
            // Save ACLs for this file
            for(int j=0; j<e->acl_count; j++) {
                fprintf(f, "ACL|%s|%s|%s\n", 
                    e->filename, e->acl[j].username, e->acl[j].access_type);
            }
            node = node->next;
        }
    }
    
    pthread_mutex_unlock(&registry_lock);
    fclose(f);
}

void load_nm_state() {
    FILE *f = fopen("nm_state.txt", "r");
    if (!f) return;

    char line[MAX_BUFFER];
    while (fgets(line, sizeof(line), f)) {
        line[strcspn(line, "\n")] = 0;
        
        char type[10];
        char p1[MAX_FILENAME], p2[MAX_PATH], p3[MAX_USERNAME], p4[10];
        int id, count;

        if (strncmp(line, "FILE|", 5) == 0) {
            sscanf(line, "FILE|%[^|]|%[^|]|%d|%[^|]|%d", p1, p2, &id, p3, &count);
            
            FileEntry entry;
            strcpy(entry.filename, p1);
            strcpy(entry.folder_path, p2);
            entry.storage_server_id = id;
            strcpy(entry.metadata.owner, p3);
            strcpy(entry.metadata.filename, p1);
            // Set defaults for others
            strcpy(entry.metadata.created, get_timestamp());
            strcpy(entry.metadata.last_modified, get_timestamp());
            strcpy(entry.metadata.last_accessed, get_timestamp());
            entry.acl_count = 0; 
            
            add_to_hash(&entry); // Add to memory
        } 
        else if (strncmp(line, "ACL|", 4) == 0) {
            sscanf(line, "ACL|%[^|]|%[^|]|%s", p1, p3, p4); // Filename, User, Access
            FileEntry *e = find_file_optimized(p1);
            if (e && e->acl_count < MAX_USERS) {
                strcpy(e->acl[e->acl_count].username, p3);
                strcpy(e->acl[e->acl_count].access_type, p4);
                e->acl_count++;
            }
        }
    }
    fclose(f);
    log_message("INFO", "NM State loaded from disk.");
}



int main(void) {
    int server_socket;
    struct sockaddr_in server_addr;
    int opt = 1;
    
    system("mkdir -p logs");
    open_log("nm");
    init_audit_log();  // Initialize audit trail (UNIQUE FACTOR)
    load_nm_state();
    log_message("INFO", "Starting Name Server on port %d", NM_PORT);
    log_audit("system", "STARTUP", NULL, "Name Server starting", 1);
    log_console("NM", "Name Server starting on port %d", NM_PORT);
    
    // Initialize hash table
    for (int i = 0; i < HASH_SIZE; i++) {
        hash_table[i] = NULL;
    }
    
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
    server_addr.sin_port = htons(NM_PORT);
    
    if (bind(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        log_message("ERROR", "Bind failed on port %d: %s", NM_PORT, strerror(errno));
        log_console("NM", "ERROR: Bind failed on port %d: %s\n", NM_PORT, strerror(errno));
        fprintf(stderr, "ERROR: Cannot bind to port %d: %s\n", NM_PORT, strerror(errno));
        fprintf(stderr, "       Another process may be using this port. Kill old processes with:\n");
        fprintf(stderr, "       killall -9 name_server storage_server client\n");
        close(server_socket);
        exit(1);
    }
    
    listen(server_socket, MAX_CLIENTS + MAX_STORAGE_SERVERS);
    log_message("INFO", "Name Server listening");
    log_console("NM", "Listening for connections...");
    
    while (1) {
        struct sockaddr_in client_addr;
        int client_socket;
        socklen_t client_len = sizeof(client_addr);
        
        client_socket = accept(server_socket, (struct sockaddr *)&client_addr, &client_len);
        if (client_socket < 0) {
            log_message("ERROR", "Accept failed");
            continue;
        }
        
        log_message("INFO", "Connection from %s", inet_ntoa(client_addr.sin_addr));
        
        pthread_t thread;
        pthread_create(&thread, NULL, client_thread, (void *)(intptr_t)client_socket);
        pthread_detach(thread);
    }
    
    close(server_socket);
    return 0;
}

