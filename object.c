#include "pes.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <openssl/evp.h>

// ─── PROVIDED ────────────────────────────────────────────────────────────────

void hash_to_hex(const ObjectID *id, char *hex_out) {
    for (int i = 0; i < HASH_SIZE; i++) {
        sprintf(hex_out + i * 2, "%02x", id->hash[i]);
    }
    hex_out[HASH_HEX_SIZE] = '\0';
}

int hex_to_hash(const char *hex, ObjectID *id_out) {
    if (strlen(hex) < HASH_HEX_SIZE) return -1;
    for (int i = 0; i < HASH_SIZE; i++) {
        unsigned int byte;
        if (sscanf(hex + i * 2, "%2x", &byte) != 1) return -1;
        id_out->hash[i] = (uint8_t)byte;
    }
    return 0;
}

void compute_hash(const void *data, size_t len, ObjectID *id_out) {
    unsigned int hash_len;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, data, len);
    EVP_DigestFinal_ex(ctx, id_out->hash, &hash_len);
    EVP_MD_CTX_free(ctx);
}

void object_path(const ObjectID *id, char *path_out, size_t path_size) {
    char hex[HASH_HEX_SIZE + 1];
    hash_to_hex(id, hex);
    snprintf(path_out, path_size, "%s/%.2s/%s", OBJECTS_DIR, hex, hex + 2);
}

int object_exists(const ObjectID *id) {
    char path[512];
    object_path(id, path, sizeof(path));
    return access(path, F_OK) == 0;
}

// ─── IMPLEMENTED ──────────────────────────────────────────────────

int object_write(ObjectType type, const void *data, size_t len, ObjectID *id_out) {
    const char *type_str = (type == OBJ_BLOB) ? "blob" : ((type == OBJ_TREE) ? "tree" : "commit");
    
    // 1. Build the full object: header ("type size\0") + data
    char header[64];
    int header_len = snprintf(header, sizeof(header), "%s %zu", type_str, len) + 1; // +1 includes the \0
    
    size_t full_len = header_len + len;
    uint8_t *full_data = malloc(full_len);
    if (!full_data) return -1;
    
    memcpy(full_data, header, header_len);
    if (len > 0) memcpy(full_data + header_len, data, len);
    
    // 2. Compute SHA-256 hash of the FULL object
    compute_hash(full_data, full_len, id_out);
    
    // 3. Check for deduplication
    if (object_exists(id_out)) {
        free(full_data);
        return 0; // Already exists, return success
    }
    
    // 4. Create shard directory
    char final_path[512];
    object_path(id_out, final_path, sizeof(final_path));
    
    char dir_path[512];
    strncpy(dir_path, final_path, sizeof(dir_path));
    char *last_slash = strrchr(dir_path, '/');
    if (last_slash) {
        *last_slash = '\0';
        mkdir(dir_path, 0755); // Create .pes/objects/XX
    }
    
    // 5. Write to a temporary file
    char tmp_path[512];
    snprintf(tmp_path, sizeof(tmp_path), "%s.tmp_XXXXXX", final_path);
    
    int fd = open(tmp_path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd < 0) {
        free(full_data);
        return -1;
    }
    
    if (write(fd, full_data, full_len) != (ssize_t)full_len) {
        close(fd);
        free(full_data);
        return -1;
    }
    
    // 6. fsync temporary file
    fsync(fd);
    close(fd);
    free(full_data);
    
    // 7. Atomic rename to final path
    if (rename(tmp_path, final_path) != 0) {
        return -1;
    }
    
    return 0;
}

int object_read(const ObjectID *id, ObjectType *type_out, void **data_out, size_t *len_out) {
    char path[512];
    object_path(id, path, sizeof(path));
    
    // 1 & 2. Open and read the entire file
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    
    fseek(f, 0, SEEK_END);
    long file_size = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    uint8_t *full_data = malloc(file_size);
    if (!full_data) {
        fclose(f);
        return -1;
    }
    
    if (fread(full_data, 1, file_size, f) != (size_t)file_size) {
        free(full_data);
        fclose(f);
        return -1;
    }
    fclose(f);
    
    // 4. Verify integrity
    ObjectID check_id;
    compute_hash(full_data, file_size, &check_id);
    if (memcmp(id->hash, check_id.hash, HASH_SIZE) != 0) {
        free(full_data); // Corrupt file
        return -1;
    }
    
    // 3. Parse header
    uint8_t *null_byte = memchr(full_data, '\0', file_size);
    if (!null_byte) {
        free(full_data);
        return -1;
    }
    
    char type_str[16];
    size_t parsed_size;
    if (sscanf((char *)full_data, "%15s %zu", type_str, &parsed_size) != 2) {
        free(full_data);
        return -1;
    }
    
    // 5. Set ObjectType
    if (strcmp(type_str, "blob") == 0) *type_out = OBJ_BLOB;
    else if (strcmp(type_str, "tree") == 0) *type_out = OBJ_TREE;
    else if (strcmp(type_str, "commit") == 0) *type_out = OBJ_COMMIT;
    else { free(full_data); return -1; }
    
    // 6. Extract data portion
    *len_out = parsed_size;
    *data_out = malloc(parsed_size);
    if (!*data_out) {
        free(full_data);
        return -1;
    }
    
    memcpy(*data_out, null_byte + 1, parsed_size);
    free(full_data);
    
    return 0;
}
