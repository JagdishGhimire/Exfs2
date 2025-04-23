#include "exfs2.h"
#include <search.h> // Required for qsort

// --- Global Variables ---
// These track the highest index segment files that *might* exist.
// They should be updated when new segments are created.
// A more robust approach might scan for existing segments on startup.
int next_inode_segment_idx = 0;
int next_data_segment_idx = 0;

// --- Helper Functions ---

// Generate segment filename
void get_segment_filename(const char* prefix, int index, char* buffer, size_t buffer_size) {
    snprintf(buffer, buffer_size, "%s%d%s", prefix, index, SEGMENT_SUFFIX);
}

// Open/Create a segment file
FILE* open_segment(const char* prefix, int index, const char* mode) {
    char filename[100];
    get_segment_filename(prefix, index, filename, sizeof(filename));
    FILE *fp = fopen(filename, mode);
    if (!fp && (mode[0] == 'r' && mode[1] == 'b' && mode[2] == '+')) { // If fopen with "rb+" fails, try creating it
         fp = fopen(filename, "wb+"); // Try creating
         if (fp) {
            // Initialize if newly created (specific initialization in create_*)
            if (ftruncate(fileno(fp), SEGMENT_SIZE) != 0) {
                 perror("Failed to set segment size");
                 fclose(fp);
                 return NULL;
            }
            rewind(fp);
         }
    }
     if (!fp) {
         // Don't print error here if it's just a check (like in init_exfs2)
         // fprintf(stderr, "Error opening/creating segment %s: %s\n", filename, strerror(errno));
     }
    return fp;
}

// Create and initialize a new inode segment
int create_inode_segment(int index) {
    FILE *fp = open_segment(INODE_SEGMENT_PREFIX, index, "wb+"); // Create or overwrite
    if (!fp) {
        fprintf(stderr, "Error creating inode segment %d: %s\n", index, strerror(errno));
        return -1;
    }

    // Write initial empty bitmap (all zeros = free)
    uint8_t bitmap[INODE_BITMAP_SIZE] = {0};
    if (fwrite(bitmap, 1, INODE_BITMAP_SIZE, fp) != INODE_BITMAP_SIZE) {
        perror("Failed to write inode bitmap");
        fclose(fp);
        return -1;
    }

    // The rest of the file is implicitly zeroed by ftruncate in open_segment

    printf("Created inode segment %d\n", index);
    fclose(fp);
    if (index >= next_inode_segment_idx) {
        next_inode_segment_idx = index + 1;
    }
    return 0;
}

// Create and initialize a new data segment
int create_data_segment(int index) {
    FILE *fp = open_segment(DATA_SEGMENT_PREFIX, index, "wb+"); // Create or overwrite
    if (!fp) {
        fprintf(stderr, "Error creating data segment %d: %s\n", index, strerror(errno));
        return -1;
    }

    // Write initial empty bitmap (all zeros = free)
    uint8_t bitmap[DATA_BITMAP_SIZE] = {0};
    if (fwrite(bitmap, 1, DATA_BITMAP_SIZE, fp) != DATA_BITMAP_SIZE) {
        perror("Failed to write data bitmap");
        fclose(fp);
        return -1;
    }

    // The rest implicitly zeroed
    printf("Created data segment %d\n", index);
    fclose(fp);
     if (index >= next_data_segment_idx) {
        next_data_segment_idx = index + 1;
    }
    return 0;
}

// --- Bitmap Operations ---
int get_bit(const uint8_t *bitmap, uint32_t index) {
    return (bitmap[index / 8] >> (index % 8)) & 1;
}

void set_bit(uint8_t *bitmap, uint32_t index) {
    bitmap[index / 8] |= (1 << (index % 8));
}

void clear_bit(uint8_t *bitmap, uint32_t index) {
    bitmap[index / 8] &= ~(1 << (index % 8));
}


// --- Inode Operations ---

uint32_t find_free_inode() {
    for (int seg_idx = 0; seg_idx < next_inode_segment_idx; ++seg_idx) {
        FILE *fp = open_segment(INODE_SEGMENT_PREFIX, seg_idx, "rb+");
        if (!fp) continue; // Try next segment

        uint8_t bitmap[INODE_BITMAP_SIZE];
        if (fread(bitmap, 1, INODE_BITMAP_SIZE, fp) != INODE_BITMAP_SIZE) {
            perror("Failed to read inode bitmap");
            fclose(fp);
            continue;
        }

        for (uint32_t local_idx = 0; local_idx < MAX_INODES_PER_SEGMENT; ++local_idx) {
            // Inode 0 is special (root), ensure it's handled correctly during init
            // Skip checking inode 0 here if it's always reserved after init?
            // Or rely on init setting its bit. Assuming init handles it.
            if (!get_bit(bitmap, local_idx)) {
                set_bit(bitmap, local_idx);
                // Write bitmap back
                rewind(fp);
                if (fwrite(bitmap, 1, INODE_BITMAP_SIZE, fp) != INODE_BITMAP_SIZE) {
                    perror("Failed to write updated inode bitmap");
                    // Rollback? Error out? For now, just report error
                    clear_bit(bitmap, local_idx); // Attempt rollback of in-memory bitmap
                    fclose(fp);
                    return UINT32_MAX; // Indicate error
                }
                fclose(fp);
                return (uint32_t)seg_idx * MAX_INODES_PER_SEGMENT + local_idx;
            }
        }
        fclose(fp);
    }

    // No free inode found in existing segments, create a new one
    int new_seg_idx = next_inode_segment_idx;
    if (create_inode_segment(new_seg_idx) == 0) {
        // The first inode (index 0) in the new segment is free
         FILE *fp = open_segment(INODE_SEGMENT_PREFIX, new_seg_idx , "rb+"); // Open the newly created one
         if (!fp) return UINT32_MAX;

         uint8_t bitmap[INODE_BITMAP_SIZE];
         fread(bitmap, 1, INODE_BITMAP_SIZE, fp); // Read the bitmap (should be zeroed)
         set_bit(bitmap, 0); // Set first bit
         rewind(fp);
         fwrite(bitmap, 1, INODE_BITMAP_SIZE, fp); // Write back
         fclose(fp);

         return (uint32_t)new_seg_idx * MAX_INODES_PER_SEGMENT + 0;

    } else {
        fprintf(stderr, "Failed to create new inode segment.\n");
        return UINT32_MAX; // Indicate error
    }
}


int read_inode(uint32_t inode_num, Inode *inode_buffer) {
    uint32_t seg_idx = inode_num / MAX_INODES_PER_SEGMENT;
    uint32_t local_idx = inode_num % MAX_INODES_PER_SEGMENT;
    long offset = (long)INODE_BITMAP_SIZE + (long)local_idx * INODE_SIZE;

    FILE *fp = open_segment(INODE_SEGMENT_PREFIX, seg_idx, "rb");
    if (!fp) {
        // fprintf(stderr, "read_inode: Could not open inode segment %u for inode %u\n", seg_idx, inode_num);
        return -1;
    }

    if (fseek(fp, offset, SEEK_SET) != 0) {
        perror("Failed to seek to inode");
        fclose(fp);
        return -1;
    }

    if (fread(inode_buffer, sizeof(Inode), 1, fp) != 1) {
        // Check for EOF specifically, might just be an uninitialized part
        if(feof(fp)) {
             // This is common if reading an inode that was allocated but never fully written (e.g., during add failure)
             // Or reading beyond the last written inode in a segment. Treat as zeroed/invalid.
             // fprintf(stderr, "Warning: Read inode %u reached EOF (possibly uninitialized).\n", inode_num);
             memset(inode_buffer, 0, sizeof(Inode)); // Return zeroed inode
             // Indicate potential issue? Or let caller decide based on zeroed struct? Returning 0 for now.
        } else {
            perror("Failed to read inode");
            fclose(fp);
            return -1;
        }
    }

    fclose(fp);
    return 0;
}

int write_inode(uint32_t inode_num, const Inode *inode_buffer) {
    uint32_t seg_idx = inode_num / MAX_INODES_PER_SEGMENT;
    uint32_t local_idx = inode_num % MAX_INODES_PER_SEGMENT;
    long offset = (long)INODE_BITMAP_SIZE + (long)local_idx * INODE_SIZE;

    FILE *fp = open_segment(INODE_SEGMENT_PREFIX, seg_idx, "rb+"); // Need write access
    if (!fp) {
         fprintf(stderr, "write_inode: Could not open inode segment %u for writing inode %u\n", seg_idx, inode_num);
        return -1;
    }

    if (fseek(fp, offset, SEEK_SET) != 0) {
        perror("Failed to seek to inode location for writing");
        fclose(fp);
        return -1;
    }

    if (fwrite(inode_buffer, sizeof(Inode), 1, fp) != 1) {
        perror("Failed to write inode");
        fclose(fp);
        return -1;
    }

    // Ensure data is written to disk (optional, performance impact)
    // fflush(fp);
    // fsync(fileno(fp));

    fclose(fp);
    return 0;
}

void free_inode(uint32_t inode_num) {
    // Add check: Do not free inode 0 (root)
    if (inode_num == 0) {
        fprintf(stderr, "Warning: Attempted to free root inode (0). Operation aborted.\n");
        return;
    }

    uint32_t seg_idx = inode_num / MAX_INODES_PER_SEGMENT;
    uint32_t local_idx = inode_num % MAX_INODES_PER_SEGMENT;

    FILE *fp = open_segment(INODE_SEGMENT_PREFIX, seg_idx, "rb+");
    if (!fp) {
        fprintf(stderr, "Error opening inode segment %d to free inode %u\n", seg_idx, inode_num);
        return;
    }

    uint8_t bitmap[INODE_BITMAP_SIZE];
     if (fread(bitmap, 1, INODE_BITMAP_SIZE, fp) != INODE_BITMAP_SIZE) {
        perror("Failed to read inode bitmap for freeing");
        fclose(fp);
        return;
     }

     if (get_bit(bitmap, local_idx)) {
        clear_bit(bitmap, local_idx);
        rewind(fp);
        if (fwrite(bitmap, 1, INODE_BITMAP_SIZE, fp) != INODE_BITMAP_SIZE) {
            perror("Failed to write updated inode bitmap after freeing");
            // Decide how to handle this error - the inode might be logically free
            // but the bitmap update failed.
        } else {
            // printf("Freed inode %u\n", inode_num); // Optional debug
        }
     } else {
         fprintf(stderr, "Warning: Attempted to free already free inode %u\n", inode_num);
     }

    fclose(fp);
    // Note: This function only frees the inode number. The caller is responsible
    // for freeing the data blocks associated with the inode *before* calling this.
}


// --- Data Block Operations ---

uint32_t find_free_data_block() {
    for (int seg_idx = 0; seg_idx < next_data_segment_idx; ++seg_idx) {
        FILE *fp = open_segment(DATA_SEGMENT_PREFIX, seg_idx, "rb+");
        if (!fp) continue;

        uint8_t bitmap[DATA_BITMAP_SIZE];
        if (fread(bitmap, 1, DATA_BITMAP_SIZE, fp) != DATA_BITMAP_SIZE) {
             perror("Failed to read data bitmap");
             fclose(fp);
             continue;
        }

        for (uint32_t local_idx = 0; local_idx < MAX_BLOCKS_PER_DATA_SEGMENT; ++local_idx) {
             // Block 0 might be special (e.g., root dir block).
             // Rely on init setting its bit.
            if (!get_bit(bitmap, local_idx)) {
                set_bit(bitmap, local_idx);
                rewind(fp);
                if (fwrite(bitmap, 1, DATA_BITMAP_SIZE, fp) != DATA_BITMAP_SIZE) {
                    perror("Failed to write updated data bitmap");
                    clear_bit(bitmap, local_idx); // Rollback in-memory
                    fclose(fp);
                    return UINT32_MAX; // Error
                }
                fclose(fp);
                return (uint32_t)seg_idx * MAX_BLOCKS_PER_DATA_SEGMENT + local_idx;
            }
        }
        fclose(fp);
    }

    // No free block found, create a new data segment
    int new_seg_idx = next_data_segment_idx;
    if (create_data_segment(new_seg_idx) == 0) {
         FILE *fp = open_segment(DATA_SEGMENT_PREFIX, new_seg_idx, "rb+");
         if (!fp) return UINT32_MAX;

         uint8_t bitmap[DATA_BITMAP_SIZE];
         fread(bitmap, 1, DATA_BITMAP_SIZE, fp);
         set_bit(bitmap, 0); // Allocate first block (index 0) in the new segment
         rewind(fp);
         fwrite(bitmap, 1, DATA_BITMAP_SIZE, fp);
         fclose(fp);

         return (uint32_t)new_seg_idx * MAX_BLOCKS_PER_DATA_SEGMENT + 0;

    } else {
        fprintf(stderr, "Failed to create new data segment.\n");
        return UINT32_MAX; // Error
    }
}

int read_data_block(uint32_t block_num, char *buffer) {
    uint32_t seg_idx = block_num / MAX_BLOCKS_PER_DATA_SEGMENT;
    uint32_t local_idx = block_num % MAX_BLOCKS_PER_DATA_SEGMENT;
    long offset = (long)DATA_AREA_OFFSET + (long)local_idx * BLOCK_SIZE;

    FILE *fp = open_segment(DATA_SEGMENT_PREFIX, seg_idx, "rb");
    if (!fp) {
        // fprintf(stderr, "read_data_block: Could not open data segment %u for block %u\n", seg_idx, block_num);
        return -1;
    }

     if (fseek(fp, offset, SEEK_SET) != 0) {
        perror("Failed to seek to data block");
        fclose(fp);
        return -1;
    }

    size_t bytes_read = fread(buffer, 1, BLOCK_SIZE, fp);
    if (bytes_read < BLOCK_SIZE) {
         if(feof(fp)) {
            // This might happen if reading past the allocated part of the last segment
            // Or reading an uninitialized block. Treat as zeros for safety.
            // fprintf(stderr, "Warning: Read data block %u reached EOF or short read (%zu bytes).\n", block_num, bytes_read);
            memset(buffer + bytes_read, 0, BLOCK_SIZE - bytes_read); // Zero out the rest
         } else {
            perror("Failed to read data block");
            fclose(fp);
            return -1;
         }
    }

    fclose(fp);
    return 0;
}

int write_data_block(uint32_t block_num, const char *buffer) {
    uint32_t seg_idx = block_num / MAX_BLOCKS_PER_DATA_SEGMENT;
    uint32_t local_idx = block_num % MAX_BLOCKS_PER_DATA_SEGMENT;
    long offset = (long)DATA_AREA_OFFSET + (long)local_idx * BLOCK_SIZE;

    FILE *fp = open_segment(DATA_SEGMENT_PREFIX, seg_idx, "rb+");
    if (!fp) {
        fprintf(stderr, "write_data_block: Could not open data segment %u for writing block %u\n", seg_idx, block_num);
        return -1;
    }

    if (fseek(fp, offset, SEEK_SET) != 0) {
        perror("Failed to seek to data block location for writing");
        fclose(fp);
        return -1;
    }

    if (fwrite(buffer, 1, BLOCK_SIZE, fp) != BLOCK_SIZE) {
        perror("Failed to write data block");
        fclose(fp);
        return -1;
    }

    // Ensure data is written to disk (optional, performance impact)
    // fflush(fp);
    // fsync(fileno(fp));

    fclose(fp);
    return 0;
}

void free_data_block(uint32_t block_num) {
     // Allow freeing block 0, as it might be used for non-root dirs/files
     if (block_num == UINT32_MAX) { // Check for the error indicator
         fprintf(stderr, "Warning: Attempt to free invalid block number UINT32_MAX\n");
         return;
     }

    uint32_t seg_idx = block_num / MAX_BLOCKS_PER_DATA_SEGMENT;
    uint32_t local_idx = block_num % MAX_BLOCKS_PER_DATA_SEGMENT;

    FILE *fp = open_segment(DATA_SEGMENT_PREFIX, seg_idx, "rb+");
    if (!fp) {
         fprintf(stderr, "Error opening data segment %d to free block %u\n", seg_idx, block_num);
         return;
     }

    uint8_t bitmap[DATA_BITMAP_SIZE];
     if (fread(bitmap, 1, DATA_BITMAP_SIZE, fp) != DATA_BITMAP_SIZE) {
         perror("Failed to read data bitmap for freeing");
         fclose(fp);
         return;
     }

     if (get_bit(bitmap, local_idx)) {
         clear_bit(bitmap, local_idx);
         rewind(fp);
         if (fwrite(bitmap, 1, DATA_BITMAP_SIZE, fp) != DATA_BITMAP_SIZE) {
             perror("Failed to write updated data bitmap after freeing block");
             // Handle error - block might be logically free but bitmap update failed
         } else {
              // Optional: Can add debug printf("Freed data block %u\n", block_num);
         }
     } else {
         fprintf(stderr, "Warning: Attempted to free already free data block %u\n", block_num);
     }

    fclose(fp);
}

// Recursive helper to free indirect blocks
void free_indirect_blocks(uint32_t block_num, int level) {
    if (block_num == 0 || block_num == UINT32_MAX || level < 0) {
        return; // Nothing to free or invalid block/level
    }

    uint32_t pointers[POINTERS_PER_BLOCK];
    char block_buffer[BLOCK_SIZE];

    if (read_data_block(block_num, block_buffer) != 0) {
        fprintf(stderr, "Error reading indirect block %u (level %d) for freeing\n", block_num, level);
        // Mark block as free anyway? Or leave potentially orphaned blocks?
        // For safety, we'll try to free the current block number even if reading failed.
        free_data_block(block_num);
        return;
    }
    memcpy(pointers, block_buffer, BLOCK_SIZE); // Copy buffer content to pointer array

    for (int i = 0; i < POINTERS_PER_BLOCK; ++i) {
        if (pointers[i] != 0 && pointers[i] != UINT32_MAX) {
            if (level == 0) { // These are direct data blocks pointed to by the indirect block
                free_data_block(pointers[i]);
            } else { // These are further indirect blocks
                free_indirect_blocks(pointers[i], level - 1);
            }
        }
    }
    // After freeing all pointed-to blocks, free this indirect block itself
    free_data_block(block_num);
}


// --- Path and Directory Operations ---

// Parses path like "/a/b/c", finds inode for 'c', returns parent ('b') inode_num.
// Sets *target_inode_num to the inode of the final component if found (UINT32_MAX otherwise).
// Sets *target_name to the final component name (e.g., "c").
// Returns 0 on success (path parsed, existence indicated by target_inode_num), -1 on error (invalid path structure or component not found when expected).
int parse_path(const char *path, uint32_t *parent_inode_num, uint32_t *target_inode_num, char *target_name) {
    if (path == NULL || path[0] != '/') {
        fprintf(stderr, "Invalid path format. Must start with '/'.\n");
        return -1;
    }

    uint32_t current_inode_num = 0; // Start at root (inode 0)
    *parent_inode_num = 0; // Default parent is root
    *target_inode_num = UINT32_MAX; // Not found yet
    target_name[0] = '\0'; // Initialize target name

    char path_copy[PATH_MAX]; // Use PATH_MAX or similar limit
    strncpy(path_copy, path, PATH_MAX - 1);
    path_copy[PATH_MAX - 1] = '\0';

    char *token;
    char *rest = path_copy;
    char *last_token = NULL;

    // Skip leading '/'
    if (rest[0] == '/') rest++;

    // Handle root path "/"
    if (strlen(rest) == 0) {
        *target_inode_num = 0; // Root inode is 0
        strncpy(target_name, "/", MAX_FILENAME_LEN); // Special name for root
        target_name[MAX_FILENAME_LEN] = '\0';
        *parent_inode_num = 0; // Root's parent is itself conceptually
        return 0;
    }

    // Iterate through path components
    while ((token = strtok_r(rest, "/", &rest))) {
        if (last_token) { // If this is not the first component
             uint32_t found_inode;
             // Find the inode for the previous component (last_token) within the current directory (current_inode_num)
             if (find_entry_in_dir(current_inode_num, last_token, &found_inode) != 0) {
                 fprintf(stderr, "Path component '%s' not found in directory inode %u\n", last_token, current_inode_num);
                 return -1; // Component not found
             }

             // Check if the found inode is actually a directory
             Inode temp_inode;
             if (read_inode(found_inode, &temp_inode) != 0) {
                 fprintf(stderr, "Failed to read inode %u for path component '%s'\n", found_inode, last_token);
                 return -1;
             }
             if (!temp_inode.is_directory) {
                 fprintf(stderr, "Path component '%s' is not a directory.\n", last_token);
                 return -1;
             }

             // Update parent and move into the found directory
             *parent_inode_num = current_inode_num;
             current_inode_num = found_inode;
        }
         last_token = token; // The current token becomes the last_token for the next iteration or the final target
    }


    // Process the last component (last_token)
    if (last_token) {
        strncpy(target_name, last_token, MAX_FILENAME_LEN);
        target_name[MAX_FILENAME_LEN] = '\0'; // Ensure null termination

        // Check if the final component exists in the final directory (current_inode_num)
        uint32_t final_inode;
        if (find_entry_in_dir(current_inode_num, target_name, &final_inode) == 0) {
            *target_inode_num = final_inode; // Found it
        } else {
            *target_inode_num = UINT32_MAX; // Not found
             // It's okay if it's not found during 'add' operation, but indicates error for 'remove', 'list', 'extract'
        }
        *parent_inode_num = current_inode_num; // The directory where target_name should reside (or does reside)
        return 0; // Success in parsing, target_inode_num indicates if it exists
    } else {
        // This case should technically be handled by the "/" check earlier, but as a fallback:
        fprintf(stderr, "Error parsing path - no components found after '/'.\n");
        return -1;
    }
}


// Searches directory data blocks for an entry. Returns 0 and sets entry_inode_num if found.
int find_entry_in_dir(uint32_t dir_inode_num, const char *name, uint32_t *entry_inode_num) {
    Inode dir_inode;
    if (read_inode(dir_inode_num, &dir_inode) != 0 || !dir_inode.is_directory) {
        // Don't print error here, as it might be called speculatively
        // fprintf(stderr, "Cannot search: Inode %u is not a valid directory.\n", dir_inode_num);
        return -1;
    }

    char block_buffer[BLOCK_SIZE];
    DirectoryEntry *entries = (DirectoryEntry *)block_buffer;
    size_t entries_searched = 0;
    size_t total_entries_in_inode = dir_inode.size; // Number of valid entries according to inode

    // TODO: Iterate through direct, single, double, triple blocks of the directory inode
    // This simplified version only checks direct blocks for brevity.
    // A full implementation needs get_block_for_offset logic here, adapted for directories.

    for (int i = 0; i < MAX_DIRECT_POINTERS && entries_searched < total_entries_in_inode; ++i) {
        uint32_t block_num = dir_inode.direct_blocks[i];
        if (block_num == 0 || block_num == UINT32_MAX) continue; // Skip unused or invalid pointers

        if (read_data_block(block_num, block_buffer) != 0) {
            fprintf(stderr, "Error reading directory data block %u while searching for '%s'\n", block_num, name);
            continue; // Skip this block
        }

        for (int j = 0; j < DIRENTRIES_PER_BLOCK; ++j) {
             if (entries[j].inode_num != 0 && entries[j].inode_num != UINT32_MAX) { // Check if entry is valid (inode is not 0 or error marker)
                 // Only increment entries_searched if we find a valid, non-empty slot
                 entries_searched++;

                 if (strncmp(entries[j].name, name, MAX_FILENAME_LEN) == 0)
                 {
                     *entry_inode_num = entries[j].inode_num;
                     return 0; // Found
                 }
                 // Optimization: If we've already found the number of entries listed in the inode, we can stop.
                 if (entries_searched >= total_entries_in_inode) {
                     goto search_end; // Exit outer loop too
                 }
             }
             // If inode_num is 0, it's an empty slot, continue searching in this block.
        }
    }
    // If not found in direct blocks, continue search into single, double, triple indirect blocks...
    // ... (Implementation needed) ...

search_end:
    return -1; // Not found
}

// Adds a directory entry. May need to allocate new data block for the directory.
int add_entry_to_dir(uint32_t dir_inode_num, const char *name, uint32_t entry_inode_num) {
    Inode dir_inode;
    if (read_inode(dir_inode_num, &dir_inode) != 0 || !dir_inode.is_directory) {
        fprintf(stderr, "Cannot add entry: Inode %u is not a valid directory.\n", dir_inode_num);
        return -1;
    }

     if (strlen(name) > MAX_FILENAME_LEN) {
         fprintf(stderr, "Error: Filename '%s' is too long (max %d chars).\n", name, MAX_FILENAME_LEN);
         return -1;
     }

    char block_buffer[BLOCK_SIZE];
    DirectoryEntry *entries = (DirectoryEntry *)block_buffer;
    size_t entries_scanned = 0; // Track total slots scanned
    size_t total_valid_entries = dir_inode.size; // Valid entries according to inode
    int found_slot = 0;
    uint32_t target_block_num = UINT32_MAX;
    int target_entry_index = -1;
    uint32_t first_free_block_ptr_index = UINT32_MAX; // Index within inode's block pointers

    // --- Phase 1: Find an empty slot (inode_num == 0) in existing blocks ---
    // TODO: Iterate through direct, single, double, triple blocks
    // Simplified: check direct blocks only
    for (int i = 0; i < MAX_DIRECT_POINTERS; ++i) {
        uint32_t block_num = dir_inode.direct_blocks[i];

        if (block_num == 0 || block_num == UINT32_MAX) { // Found an unused block pointer in the inode
             if (first_free_block_ptr_index == UINT32_MAX) {
                 first_free_block_ptr_index = i; // Remember the first available slot for a new block
             }
             continue; // Skip to next pointer
        }

        // Read the existing data block
        if (read_data_block(block_num, block_buffer) != 0) {
             fprintf(stderr, "Warning: Error reading dir block %u while searching for empty slot.\n", block_num);
             continue; // Skip this block
        }

        for (int j = 0; j < DIRENTRIES_PER_BLOCK; ++j) {
             if (entries[j].inode_num == 0) { // Found an empty slot within the block
                 target_block_num = block_num;
                 target_entry_index = j;
                 found_slot = 1;
                 goto slot_found; // Exit loops
             }
             // Count valid entries encountered to potentially stop early, though not strictly necessary here
             // if (entries[j].inode_num != 0 && entries[j].inode_num != UINT32_MAX) entries_scanned++;
        }
    }
     // ... Add logic for indirect blocks search here ...


slot_found:
    // --- Phase 2: Handle slot finding result ---
    if (found_slot) {
        // Read the target block again (it might not be the last one read if indirect was used)
        if (read_data_block(target_block_num, block_buffer) != 0) {
            fprintf(stderr, "Error re-reading block %u to add entry.\n", target_block_num);
            return -1;
        }
        // Write the new entry
        strncpy(entries[target_entry_index].name, name, MAX_FILENAME_LEN);
        entries[target_entry_index].name[MAX_FILENAME_LEN] = '\0';
        entries[target_entry_index].inode_num = entry_inode_num;

        if (write_data_block(target_block_num, block_buffer) != 0) {
            fprintf(stderr, "Error writing updated directory block %u.\n", target_block_num);
            // Attempt to revert entry? Complicated. Mark as error.
            entries[target_entry_index].inode_num = 0; // Try to revert in memory at least
            return -1;
        }

        // Increment inode size only if this new entry increases the count
        // This happens if we reused a slot that was previously considered empty *beyond* the old size.
        // A simpler, safe approach is to always increment size when adding,
        // assuming remove doesn't decrement size (which it currently doesn't).
        dir_inode.size++;
        if (write_inode(dir_inode_num, &dir_inode) != 0) {
             fprintf(stderr, "Error updating directory inode %u size after adding entry.\n", dir_inode_num);
             // Inconsistency! Entry added to block, but inode size not updated.
             // Should try to revert the block write? Very complex. Mark error.
             return -1;
        }
        // printf("Added entry '%s' -> %u in dir inode %u (used existing slot in block %u)\n", name, entry_inode_num, dir_inode_num, target_block_num);
        return 0; // Success

    } else {
        // --- Phase 3: Allocate a new block if no empty slot found ---
        // printf("No free slot found in directory %u, allocating new block.\n", dir_inode_num);
        uint32_t new_block = find_free_data_block();
        if (new_block == UINT32_MAX) {
            fprintf(stderr, "Failed to allocate new data block for directory %u.\n", dir_inode_num);
            return -1;
        }

        // Find where to store the pointer to the new block in the inode
        // TODO: Check direct pointers first (using first_free_block_ptr_index), then single indirect, etc.
        // Simplified: Check direct pointers only
        int pointer_stored = 0;
        if (first_free_block_ptr_index != UINT32_MAX && first_free_block_ptr_index < MAX_DIRECT_POINTERS) {
             dir_inode.direct_blocks[first_free_block_ptr_index] = new_block;
             pointer_stored = 1;
        }
        // ... Add logic to store in indirect blocks if direct are full ...

        if (!pointer_stored) {
            fprintf(stderr, "Directory inode %u is full (no place to store new block pointer).\n", dir_inode_num);
            free_data_block(new_block); // Free the allocated block
            return -1;
        }

        // Initialize the new block (all entries except the first are empty)
        memset(block_buffer, 0, BLOCK_SIZE);
        strncpy(entries[0].name, name, MAX_FILENAME_LEN);
        entries[0].name[MAX_FILENAME_LEN] = '\0';
        entries[0].inode_num = entry_inode_num;

        if (write_data_block(new_block, block_buffer) != 0) {
            fprintf(stderr, "Error writing newly allocated directory block %u.\n", new_block);
            // Revert inode pointer? Free block?
             dir_inode.direct_blocks[first_free_block_ptr_index] = 0; // Clear pointer in inode
             write_inode(dir_inode_num, &dir_inode); // Attempt to write back inode change
             free_data_block(new_block); // Free the block
            return -1;
        }

        // Update directory inode size and write it back
        dir_inode.size++;
        if (write_inode(dir_inode_num, &dir_inode) != 0) {
            fprintf(stderr, "Error updating directory inode %u after allocating new block.\n", dir_inode_num);
            // Inconsistency! New block written, pointer stored, but size wrong.
            // Should try to revert? Very complex. Mark error.
            return -1;
        }

        // printf("Added entry '%s' -> %u in dir inode %u (allocated new block %u)\n", name, entry_inode_num, dir_inode_num, new_block);
        return 0; // Success
    }
}


// Removes entry by setting its inode number to 0. Does not compact directory file.
// Does NOT currently decrement inode size.
int remove_entry_from_dir(uint32_t dir_inode_num, const char *name) {
    Inode dir_inode;
    if (read_inode(dir_inode_num, &dir_inode) != 0 || !dir_inode.is_directory) {
        fprintf(stderr, "Cannot remove entry: Inode %u is not a valid directory.\n", dir_inode_num);
        return -1;
    }

    char block_buffer[BLOCK_SIZE];
    DirectoryEntry *entries = (DirectoryEntry *)block_buffer;
    size_t entries_searched = 0; // Count valid entries scanned
    size_t total_entries_in_inode = dir_inode.size;
    int found = 0;

    // TODO: Iterate through direct, single, double, triple blocks
    // Simplified: Check direct blocks only
    for (int i = 0; i < MAX_DIRECT_POINTERS && entries_searched < total_entries_in_inode; ++i) {
        uint32_t block_num = dir_inode.direct_blocks[i];
        if (block_num == 0 || block_num == UINT32_MAX) continue;

        if (read_data_block(block_num, block_buffer) != 0) {
             fprintf(stderr, "Warning: Error reading dir block %u while removing '%s'.\n", block_num, name);
             continue; // Skip block
        }

        for (int j = 0; j < DIRENTRIES_PER_BLOCK; ++j) {
            if (entries[j].inode_num != 0 && entries[j].inode_num != UINT32_MAX) { // If valid entry
                entries_searched++; // Count valid entry

                if (strncmp(entries[j].name, name, MAX_FILENAME_LEN) == 0) {
                    // Found the entry, mark as invalid
                    uint32_t inode_to_remove = entries[j].inode_num; // Keep track for potential later use
                    entries[j].inode_num = 0; // Mark as free/invalid
                    memset(entries[j].name, 0, MAX_FILENAME_LEN + 1); // Clear name

                    if (write_data_block(block_num, block_buffer) != 0) {
                        fprintf(stderr, "Error writing directory block %u after removing entry '%s'.\n", block_num, name);
                        // Entry might still appear if read before this failed write is fixed.
                        // Try to revert in-memory change?
                        entries[j].inode_num = inode_to_remove;
                        strncpy(entries[j].name, name, MAX_FILENAME_LEN);
                        return -1; // Indicate error
                    }

                    // Optional: Decrement dir_inode.size. This makes adding logic more complex
                    // as it needs to handle finding slots vs. appending correctly.
                    // For simplicity, size is NOT decremented here. The block slot is just marked free.
                    // dir_inode.size--;
                    // write_inode(dir_inode_num, &dir_inode); // Write updated inode if size changes

                    // printf("Removed entry '%s' from directory inode %u (marked slot as free in block %u).\n", name, dir_inode_num, block_num);
                    found = 1;
                    goto entry_removed; // Exit loops
                }
                // Optimization: Stop searching if we've examined all entries expected by inode size
                if (entries_searched >= total_entries_in_inode) {
                     goto entry_removed;
                 }
            }
        }
    }
    // ... Add logic for indirect blocks search here ...

entry_removed:
    if (!found) {
        fprintf(stderr, "Entry '%s' not found in directory inode %u.\n", name, dir_inode_num);
        return -1; // Not found
    }

    // Optional: Check if the directory block is now empty and potentially free it
    // Requires reading the block again and checking all entries.
    // Also requires removing the block pointer from the inode (direct or indirect)
    // This adds significant complexity.

    return 0; // Success
}


// Creates a new directory with "." and ".." entries
uint32_t create_directory(uint32_t parent_inode_num, const char *name) {
     // 1. Allocate inode for the new directory
     uint32_t new_dir_inode_num = find_free_inode();
     if (new_dir_inode_num == UINT32_MAX) {
         fprintf(stderr, "Failed to allocate inode for new directory '%s'\n", name);
         return UINT32_MAX;
     }

     // 2. Allocate a data block for the new directory's entries (".", "..")
     uint32_t new_dir_data_block = find_free_data_block();
     if (new_dir_data_block == UINT32_MAX) {
         fprintf(stderr, "Failed to allocate data block for new directory '%s'\n", name);
         free_inode(new_dir_inode_num); // Rollback inode allocation
         return UINT32_MAX;
     }

     // 3. Initialize the new directory's inode
     Inode new_dir_inode;
     memset(&new_dir_inode, 0, sizeof(Inode));
     new_dir_inode.is_directory = 1;
     new_dir_inode.mode = S_IFDIR | 0755; // Standard directory permissions
     new_dir_inode.size = 2; // Starts with "." and ".." entries
     new_dir_inode.direct_blocks[0] = new_dir_data_block;
     // Initialize other block pointers to 0 or UINT32_MAX if preferred marker

     // 4. Initialize the new directory's data block with "." and ".."
     char block_buffer[BLOCK_SIZE];
     DirectoryEntry *entries = (DirectoryEntry *)block_buffer;
     memset(block_buffer, 0, BLOCK_SIZE);

     // Entry for "."
     strncpy(entries[0].name, ".", MAX_FILENAME_LEN);
     entries[0].inode_num = new_dir_inode_num; // Points to itself

     // Entry for ".."
     strncpy(entries[1].name, "..", MAX_FILENAME_LEN);
     entries[1].inode_num = parent_inode_num; // Points to parent

     // 5. Write the new inode and data block
     if (write_inode(new_dir_inode_num, &new_dir_inode) != 0) {
         fprintf(stderr, "Failed to write inode for new directory '%s'\n", name);
         free_data_block(new_dir_data_block);
         free_inode(new_dir_inode_num);
         return UINT32_MAX;
     }
     if (write_data_block(new_dir_data_block, block_buffer) != 0) {
         fprintf(stderr, "Failed to write data block for new directory '%s'\n", name);
         // Partially created state. Attempt cleanup.
         free_inode(new_dir_inode_num); // Free inode (block is already potentially corrupt/written)
         // Data block bitmap might be set, but inode is free. Inconsistency possible.
         return UINT32_MAX;
     }

     // 6. Add the entry for the new directory to its parent directory
     if (add_entry_to_dir(parent_inode_num, name, new_dir_inode_num) != 0) {
         fprintf(stderr, "Failed to add entry for new directory '%s' to parent inode %u\n", name, parent_inode_num);
         // Rollback: Remove the created directory (inode and data block)
         // This requires recursive freeing logic if the directory had contents (though it shouldn't yet)
         // Simplification: Just free the direct block and the inode
         free_data_block(new_dir_data_block); // Free data block
         free_inode(new_dir_inode_num);       // Free inode
         return UINT32_MAX;
     }

     // printf("Created directory '%s' (inode %u, data block %u)\n", name, new_dir_inode_num, new_dir_data_block);
     return new_dir_inode_num; // Success
}


// Helper to get the actual data block number for a given file offset
// Handles direct, single, double, triple indirect blocks.
// If allocate=1, allocates necessary blocks if they don't exist.
// Returns block number or UINT32_MAX on error/if block not allocated and allocate=0.
// IMPORTANT: This function modifies the inode if allocate=1.
uint32_t get_block_for_offset(uint32_t inode_num, size_t offset, int allocate) {
    Inode inode;
    if (read_inode(inode_num, &inode) != 0) {
        fprintf(stderr, "get_block_for_offset: Failed to read inode %u\n", inode_num);
        return UINT32_MAX;
    }

    uint32_t block_index = offset / BLOCK_SIZE; // Which block in the file sequence (0, 1, 2...)
    uint32_t current_block_num = UINT32_MAX;
    int inode_dirty = 0; // Flag to track if inode needs writing back

    // --- 1. Direct Blocks ---
    if (block_index < MAX_DIRECT_POINTERS) {
        current_block_num = inode.direct_blocks[block_index];
        if (current_block_num == 0 || current_block_num == UINT32_MAX) { // Check if block pointer is unused
            if (allocate) {
                uint32_t new_block = find_free_data_block();
                if (new_block == UINT32_MAX) return UINT32_MAX; // Allocation failed
                inode.direct_blocks[block_index] = new_block;
                inode_dirty = 1; // Mark inode as modified
                current_block_num = new_block;
                // Zero out the newly allocated block (optional but good practice)
                // char zero_buffer[BLOCK_SIZE] = {0};
                // write_data_block(new_block, zero_buffer);
            } else {
                return UINT32_MAX; // Not allocated and not requesting allocation
            }
        }
        goto end_get_block; // Found/allocated direct block
    }

    // --- Calculate indices for indirect blocks ---
    block_index -= MAX_DIRECT_POINTERS; // Adjust index relative to start of indirect blocks

    // --- 2. Single Indirect ---
    uint32_t single_indirect_limit = POINTERS_PER_BLOCK;
    if (block_index < single_indirect_limit) {
        uint32_t single_indirect_block_num = inode.single_indirect;

        // Allocate single indirect block itself if needed
        if (single_indirect_block_num == 0 || single_indirect_block_num == UINT32_MAX) {
            if (allocate) {
                 single_indirect_block_num = find_free_data_block();
                 if (single_indirect_block_num == UINT32_MAX) return UINT32_MAX;
                 // Zero out the new indirect block before use
                 char zero_buffer[BLOCK_SIZE] = {0};
                 if (write_data_block(single_indirect_block_num, zero_buffer) != 0) {
                     fprintf(stderr, "get_block_for_offset: Failed to zero single indirect block %u\n", single_indirect_block_num);
                     free_data_block(single_indirect_block_num); // Rollback allocation
                     return UINT32_MAX;
                 }
                 inode.single_indirect = single_indirect_block_num;
                 inode_dirty = 1;
            } else {
                return UINT32_MAX; // Not allocated
            }
        }

        // Read the single indirect block
        uint32_t pointers[POINTERS_PER_BLOCK];
        char indirect_block_buffer[BLOCK_SIZE];
        if(read_data_block(single_indirect_block_num, indirect_block_buffer) != 0) {
             fprintf(stderr, "get_block_for_offset: Failed read single indirect block %u\n", single_indirect_block_num);
             return UINT32_MAX;
        }
        memcpy(pointers, indirect_block_buffer, BLOCK_SIZE);

        // Get/Allocate the data block pointer within the indirect block
        current_block_num = pointers[block_index];
        if (current_block_num == 0 || current_block_num == UINT32_MAX) {
            if (allocate) {
                uint32_t new_block = find_free_data_block();
                if (new_block == UINT32_MAX) return UINT32_MAX;
                pointers[block_index] = new_block;
                 // Write the updated single indirect block back
                 memcpy(indirect_block_buffer, pointers, BLOCK_SIZE);
                 if (write_data_block(single_indirect_block_num, indirect_block_buffer) != 0) {
                     fprintf(stderr, "get_block_for_offset: Failed write single indirect block %u after alloc data block\n", single_indirect_block_num);
                     free_data_block(new_block); // Rollback data block allocation
                     return UINT32_MAX;
                 }
                 current_block_num = new_block;
                 // Zero out new data block (optional)
                 // char zero_buffer[BLOCK_SIZE] = {0};
                 // write_data_block(new_block, zero_buffer);
            } else {
                return UINT32_MAX; // Not allocated
            }
        }
        goto end_get_block; // Found/allocated block via single indirect
    }

    // --- 3. Double Indirect ---
    block_index -= single_indirect_limit; // Adjust index relative to start of double indirect
    uint32_t double_indirect_limit = POINTERS_PER_BLOCK * POINTERS_PER_BLOCK;
    if (block_index < double_indirect_limit) {
        uint32_t double_indirect_block_num = inode.double_indirect;
        uint32_t idx1 = block_index / POINTERS_PER_BLOCK; // Index into double indirect block
        uint32_t idx2 = block_index % POINTERS_PER_BLOCK; // Index into single indirect block

        // Allocate double indirect block itself if needed
        if (double_indirect_block_num == 0 || double_indirect_block_num == UINT32_MAX) {
            if (!allocate) return UINT32_MAX;
            double_indirect_block_num = find_free_data_block();
            if (double_indirect_block_num == UINT32_MAX) return UINT32_MAX;
            char zero_buffer[BLOCK_SIZE] = {0};
            if (write_data_block(double_indirect_block_num, zero_buffer) != 0) {
                fprintf(stderr, "get_block_for_offset: Failed zero double indirect block %u\n", double_indirect_block_num);
                free_data_block(double_indirect_block_num); return UINT32_MAX;
            }
            inode.double_indirect = double_indirect_block_num;
            inode_dirty = 1;
        }

        // Read double indirect block
        uint32_t pointers1[POINTERS_PER_BLOCK];
        char block_buffer1[BLOCK_SIZE];
        if(read_data_block(double_indirect_block_num, block_buffer1) != 0) {
            fprintf(stderr, "get_block_for_offset: Failed read double indirect block %u\n", double_indirect_block_num);
            return UINT32_MAX;
        }
        memcpy(pointers1, block_buffer1, BLOCK_SIZE);

        // Get/Allocate the single indirect block pointer within the double indirect block
        uint32_t single_indirect_block_num = pointers1[idx1];
        if (single_indirect_block_num == 0 || single_indirect_block_num == UINT32_MAX) {
             if (!allocate) return UINT32_MAX;
             single_indirect_block_num = find_free_data_block();
             if (single_indirect_block_num == UINT32_MAX) return UINT32_MAX;
             char zero_buffer[BLOCK_SIZE] = {0};
             if (write_data_block(single_indirect_block_num, zero_buffer) != 0) {
                 fprintf(stderr, "get_block_for_offset: Failed zero single indirect block %u (from double)\n", single_indirect_block_num);
                 free_data_block(single_indirect_block_num); return UINT32_MAX;
             }
             pointers1[idx1] = single_indirect_block_num;
             // Write the updated double indirect block back
             memcpy(block_buffer1, pointers1, BLOCK_SIZE);
             if (write_data_block(double_indirect_block_num, block_buffer1) != 0) {
                 fprintf(stderr, "get_block_for_offset: Failed write double indirect block %u after alloc single indirect\n", double_indirect_block_num);
                 free_data_block(single_indirect_block_num); // Rollback
                 return UINT32_MAX;
             }
        }

        // Read the single indirect block
        uint32_t pointers2[POINTERS_PER_BLOCK];
        char block_buffer2[BLOCK_SIZE];
         if(read_data_block(single_indirect_block_num, block_buffer2) != 0) {
             fprintf(stderr, "get_block_for_offset: Failed read single indirect block %u (from double)\n", single_indirect_block_num);
             return UINT32_MAX;
         }
         memcpy(pointers2, block_buffer2, BLOCK_SIZE);

        // Get/Allocate the data block pointer within the single indirect block
        current_block_num = pointers2[idx2];
        if (current_block_num == 0 || current_block_num == UINT32_MAX) {
            if (!allocate) return UINT32_MAX;
            uint32_t new_block = find_free_data_block();
            if (new_block == UINT32_MAX) return UINT32_MAX;
            pointers2[idx2] = new_block;
            // Write the updated single indirect block back
            memcpy(block_buffer2, pointers2, BLOCK_SIZE);
            if (write_data_block(single_indirect_block_num, block_buffer2) != 0) {
                fprintf(stderr, "get_block_for_offset: Failed write single indirect block %u after alloc data block (from double)\n", single_indirect_block_num);
                free_data_block(new_block); // Rollback
                return UINT32_MAX;
            }
            current_block_num = new_block;
            // Zero out new data block (optional)
        }
        goto end_get_block; // Found/allocated block via double indirect
    }


    // --- 4. Triple Indirect ---
     block_index -= double_indirect_limit; // Adjust index relative to start of triple indirect
     // uint64_t triple_indirect_limit = (uint64_t)POINTERS_PER_BLOCK * POINTERS_PER_BLOCK * POINTERS_PER_BLOCK;
     // Check if block_index is within the range of triple indirect block
     // Calculation using uint64_t to avoid potential overflow if POINTERS_PER_BLOCK is large
     // if ((uint64_t)block_index < triple_indirect_limit) {
     // Simplified check assuming block_index won't overflow uint32_t in reasonable scenarios
     // A more robust check might be needed for extremely large filesystems/block sizes
     // if (block_index is within valid range for triple indirect) {
         // --- Implementation similar to double indirect, but with three levels ---
         // a. Check/Allocate Triple Indirect Block (inode.triple_indirect)
         // b. Read Triple Indirect Block -> pointers1
         // c. Calculate idx1 = block_index / (POINTERS_PER_BLOCK * POINTERS_PER_BLOCK)
         // d. Check/Allocate Double Indirect Block (pointers1[idx1])
         // e. Read Double Indirect Block -> pointers2
         // f. Calculate idx2 = (block_index / POINTERS_PER_BLOCK) % POINTERS_PER_BLOCK
         // g. Check/Allocate Single Indirect Block (pointers2[idx2])
         // h. Read Single Indirect Block -> pointers3
         // i. Calculate idx3 = block_index % POINTERS_PER_BLOCK
         // j. Check/Allocate Data Block (pointers3[idx3])
         // k. Return Data Block number
         fprintf(stderr, "Triple indirect blocks not fully implemented in get_block_for_offset.\n");
         // return UINT32_MAX; // Placeholder
     // }


    // --- Offset is beyond the maximum file size supported ---
    fprintf(stderr, "Offset %zu is beyond the maximum file size supported by implemented block pointers.\n", offset);
    return UINT32_MAX;

end_get_block:
    // Write back the inode if it was modified during allocation
    if (inode_dirty) {
        if (write_inode(inode_num, &inode) != 0) {
             fprintf(stderr, "get_block_for_offset: Failed to write updated inode %u back to disk.\n", inode_num);
             // Critical error: Allocation happened, but inode update failed.
             // Filesystem potentially inconsistent. May need to rollback allocations.
             // For now, return error. Rollback is complex.
             return UINT32_MAX;
        }
    }
    return current_block_num;
}


// --- Core File System Operations ---

// --- Helper function for qsort to compare DirectoryEntry structs by name ---
int compare_direntry_names(const void *a, const void *b) {
    const DirectoryEntry *entry_a = (const DirectoryEntry *)a;
    const DirectoryEntry *entry_b = (const DirectoryEntry *)b;
    return strcmp(entry_a->name, entry_b->name);
}


// --- Updated Recursive Listing Function ---
void list_recursive(uint32_t dir_inode_num, int depth, int debug_mode) {
    Inode dir_inode;
    if (read_inode(dir_inode_num, &dir_inode) != 0 || !dir_inode.is_directory) {
        // Don't print error if called on non-dir during normal operation,
        // but maybe if debug mode is on?
        // fprintf(stderr, "Error: Cannot list inode %u - not a valid directory.\n", dir_inode_num);
        return;
    }

    // --- Step 1: Collect all valid directory entries ---
    DirectoryEntry *all_entries = NULL;
    size_t entry_count = 0;
    size_t capacity = 0; // For dynamic resizing

    char block_buffer[BLOCK_SIZE];
    DirectoryEntry *entries_in_block = (DirectoryEntry *)block_buffer;
    size_t entries_processed_total = 0; // Track total valid entries found across blocks
    size_t valid_entries_in_inode = dir_inode.size; // Total valid entries expected according to inode

    // TODO: Iterate through direct, single, double, triple blocks of the directory
    // This simplified version only processes direct blocks. A full implementation
    // needs to use get_block_for_offset or similar logic to iterate through ALL blocks.

    for (int i = 0; i < MAX_DIRECT_POINTERS && entries_processed_total < valid_entries_in_inode; ++i) {
        uint32_t block_num = dir_inode.direct_blocks[i];
        if (block_num == 0 || block_num == UINT32_MAX) continue; // Skip unused/invalid pointers

        if (read_data_block(block_num, block_buffer) != 0) {
            fprintf(stderr, "Warning: Error reading directory data block %u during list.\n", block_num);
            continue; // Skip this block
        }

        for (int j = 0; j < DIRENTRIES_PER_BLOCK; ++j) {
            // Check if entry is valid (inode number is not 0 or error marker)
            if (entries_in_block[j].inode_num != 0 && entries_in_block[j].inode_num != UINT32_MAX) {
                entries_processed_total++; // Count this valid entry found

                // Skip "." and ".." entries specifically for listing output
                if (strcmp(entries_in_block[j].name, ".") != 0 && strcmp(entries_in_block[j].name, "..") != 0) {
                    // Resize dynamic array if needed
                    if (entry_count >= capacity) {
                        capacity = (capacity == 0) ? 10 : capacity * 2; // Initial capacity 10, then double
                        DirectoryEntry *temp = realloc(all_entries, capacity * sizeof(DirectoryEntry));
                        if (!temp) {
                            perror("Failed to allocate memory for directory listing");
                            free(all_entries); // Free previously allocated memory
                            return; // Cannot proceed
                        }
                        all_entries = temp;
                    }
                    // Copy the valid entry to our temporary array
                    all_entries[entry_count++] = entries_in_block[j];
                }
                 // Optimization: If we've found all entries expected by inode size, stop scanning blocks
                 if (entries_processed_total >= valid_entries_in_inode) {
                     goto collect_end; // Exit outer loop too
                 }
            }
        }
    }
    // ... Add logic here to iterate through indirect blocks and collect entries ...
    // Remember to increment entries_processed_total and add valid entries (not . or ..)
    // to the all_entries dynamic array. Check entries_processed_total >= valid_entries_in_inode.

collect_end:

    // --- Step 2: Sort the collected entries alphabetically ---
    if (all_entries && entry_count > 0) {
        qsort(all_entries, entry_count, sizeof(DirectoryEntry), compare_direntry_names);
    }

    // --- Step 3: Print sorted entries and recurse ---
    for (size_t k = 0; k < entry_count; ++k) {
        // Indentation for entry
        for (int indent = 0; indent < depth; ++indent) { // Indent based on current depth
             printf("  "); // 2 spaces per depth level
        }

        // Print the entry name
        if (debug_mode) {
            printf("'%s' -> %u\n", all_entries[k].name, all_entries[k].inode_num);
        } else {
            printf("%s\n", all_entries[k].name);
        }

        // Recurse if it's a directory
        Inode entry_inode;
        if (read_inode(all_entries[k].inode_num, &entry_inode) == 0) {
            if (entry_inode.is_directory) {
                // No extra '/' print here
                list_recursive(all_entries[k].inode_num, depth + 1, debug_mode); // Recurse deeper
            } else if (debug_mode) {
                 // Optionally print file details in debug mode
                 for (int indent = 0; indent < depth + 1; ++indent) printf("  "); // Indent file info
                 printf("  (file, size %zu)\n", entry_inode.size);
            }
        } else {
             fprintf(stderr, "Warning: Could not read inode %u for entry '%s' during list.\n", all_entries[k].inode_num, all_entries[k].name);
        }
    }

    // --- Step 4: Clean up allocated memory ---
    free(all_entries);
}


// Main listing function called by command line handler
void list_fs(const char *path, int debug_mode) {
    uint32_t parent_inode_num = UINT32_MAX;
    uint32_t target_inode_num = UINT32_MAX;
    char target_name[MAX_FILENAME_LEN + 1];
    uint32_t start_inode_num = 0; // Default to root

    // Parse the path to find the starting directory inode
    if (strcmp(path, "/") != 0) {
        if (parse_path(path, &parent_inode_num, &target_inode_num, target_name) != 0) {
            // Error message already printed by parse_path
            return;
        }
        if (target_inode_num == UINT32_MAX) {
             fprintf(stderr, "Error: Path '%s' not found.\n", path);
             return;
        }
        // Check if the target is actually a directory
        Inode target_inode;
        if (read_inode(target_inode_num, &target_inode) != 0 || !target_inode.is_directory) {
             fprintf(stderr, "Error: Path '%s' is not a directory.\n", path);
             return;
        }
        start_inode_num = target_inode_num;
    }

    // Start the recursive listing from the determined start inode at depth 0
    // No initial print here, list_recursive handles printing entries within the target dir
    list_recursive(start_inode_num, 0, debug_mode);
}


// Adds a local file to the ExFS2 path
void add_file_to_fs(const char *exfs_path, const char *local_path) {
    // printf("Adding local file '%s' to exfs path '%s'\n", local_path, exfs_path); // Debug

    // 1. Open local file for reading
    FILE *local_fp = fopen(local_path, "rb");
    if (!local_fp) {
        perror("Failed to open local file for reading");
        return;
    }

    // 2. Parse ExFS path, create directories if they don't exist
    uint32_t parent_inode_num = 0; // Start search from root
    uint32_t target_inode_num = UINT32_MAX;
    char target_name[MAX_FILENAME_LEN + 1];
    // char current_path[PATH_MAX] = ""; // Keep track of created path (not needed here)
    uint32_t current_dir_inode = 0; // Root

    char exfs_path_copy[PATH_MAX];
    strncpy(exfs_path_copy, exfs_path, PATH_MAX - 1);
    exfs_path_copy[PATH_MAX - 1] = '\0';

    char *token;
    char *rest = exfs_path_copy;
    if (rest[0] == '/') rest++; // Skip leading '/'

    char *next_token = strtok_r(rest, "/", &rest);
    if (next_token == NULL && strcmp(exfs_path,"/") == 0) {
        fprintf(stderr, "Error: Cannot add a file named '/'.\n");
        fclose(local_fp);
        return;
    }
    if (next_token == NULL) { // Path was just "/", trying to add ""?
        fprintf(stderr, "Error: Invalid target filename in path '%s'.\n", exfs_path);
        fclose(local_fp);
        return;
    }


    while (next_token != NULL) {
        char *current_token = next_token;
        next_token = strtok_r(rest, "/", &rest); // Peek ahead

        // strncat(current_path, "/", PATH_MAX - strlen(current_path) -1);
        // strncat(current_path, current_token, PATH_MAX - strlen(current_path) -1);


        uint32_t found_inode;
        if (find_entry_in_dir(current_dir_inode, current_token, &found_inode) != 0) {
            // Not found
            if (next_token != NULL) { // It's an intermediate directory that needs creation
                 // printf("Directory '%s' not found, creating...\n", current_token); // Debug
                 uint32_t new_dir = create_directory(current_dir_inode, current_token);
                 if (new_dir == UINT32_MAX) {
                     fprintf(stderr, "Failed to create intermediate directory '%s'\n", current_token);
                     fclose(local_fp);
                     return;
                 }
                 current_dir_inode = new_dir; // Move into the new directory
            } else { // It's the final component (the file to be created)
                strncpy(target_name, current_token, MAX_FILENAME_LEN);
                target_name[MAX_FILENAME_LEN]='\0';
                parent_inode_num = current_dir_inode;
                target_inode_num = UINT32_MAX; // Mark as not existing yet
                 // Break loop, we found the parent and target name
                 break;
            }
        } else {
            // Found
             Inode temp_inode;
             if(read_inode(found_inode, &temp_inode) != 0) {
                 fprintf(stderr, "Error reading inode %u for '%s'\n", found_inode, current_token);
                 fclose(local_fp);
                 return;
             }

            if (next_token != NULL) { // Intermediate component must be a directory
                 if (!temp_inode.is_directory) {
                     fprintf(stderr, "Error: '%s' in path '%s' exists but is not a directory.\n", current_token, exfs_path);
                     fclose(local_fp);
                     return;
                 }
                 current_dir_inode = found_inode; // Move into existing directory
            } else { // Final component
                strncpy(target_name, current_token, MAX_FILENAME_LEN);
                 target_name[MAX_FILENAME_LEN]='\0';
                parent_inode_num = current_dir_inode;
                 target_inode_num = found_inode; // File/Dir already exists
                 fprintf(stderr, "Error: '%s' already exists at path '%s'. Remove it first.\n", target_name, exfs_path);
                 // Or implement overwrite logic if desired
                 fclose(local_fp);
                 return;
            }
        }
    } // End path parsing loop

     // Check if target_name was actually set (should be unless path was just "/")
     if (target_name[0] == '\0') {
         fprintf(stderr, "Error: Could not determine target filename from path '%s'.\n", exfs_path);
         fclose(local_fp);
         return;
     }
     // Ensure target doesn't already exist (double check after loop)
     if (target_inode_num != UINT32_MAX) {
          fprintf(stderr, "Error: Target '%s' already exists.\n", exfs_path);
          fclose(local_fp);
          return;
     }


    // 3. Allocate inode for the new file
    uint32_t new_file_inode_num = find_free_inode();
    if (new_file_inode_num == UINT32_MAX) {
        fprintf(stderr, "Failed to allocate inode for file '%s'\n", target_name);
        fclose(local_fp);
        return;
    }

    // 4. Initialize file inode (size starts at 0)
    Inode new_file_inode;
    memset(&new_file_inode, 0, sizeof(Inode));
    new_file_inode.is_directory = 0;
    new_file_inode.size = 0;
    new_file_inode.mode = S_IFREG | 0644; // Example permissions

    // 5. Read local file and write data to ExFS blocks
    char buffer[BLOCK_SIZE];
    size_t bytes_read;
    size_t total_bytes_written = 0;
    int error_occurred = 0;

    // Write inode initially (with size 0) before allocating blocks
    // This helps if get_block_for_offset needs to read it during allocation.
    if (write_inode(new_file_inode_num, &new_file_inode) != 0) {
         fprintf(stderr, "Failed to write initial inode %u for file '%s'\n", new_file_inode_num, target_name);
         free_inode(new_file_inode_num); // Rollback inode allocation
         fclose(local_fp);
         return;
    }


    while ((bytes_read = fread(buffer, 1, BLOCK_SIZE, local_fp)) > 0) {
        // Get the block number, allocating if necessary
        uint32_t target_block = get_block_for_offset(new_file_inode_num, total_bytes_written, 1); // Allocate=1
        if (target_block == UINT32_MAX) {
            fprintf(stderr, "Failed to allocate/get data block for file '%s' at offset %zu\n", target_name, total_bytes_written);
            error_occurred = 1;
            break;
        }

        // If bytes_read < BLOCK_SIZE, zero out the rest of the buffer for the last block
        if (bytes_read < BLOCK_SIZE) {
            memset(buffer + bytes_read, 0, BLOCK_SIZE - bytes_read);
        }

        if (write_data_block(target_block, buffer) != 0) {
             fprintf(stderr, "Failed to write data block %u for file '%s'\n", target_block, target_name);
             error_occurred = 1;
             break;
        }
        total_bytes_written += bytes_read;
    } // End read/write loop

    // Check for read errors on the local file
    if (ferror(local_fp)) {
        perror("Error reading from local file");
        error_occurred = 1;
    }
    fclose(local_fp); // Close local file regardless of ExFS write success

    // 6. Update file inode with final size and write it
    if (!error_occurred) {
        // Read the potentially modified inode (if get_block_for_offset allocated indirect blocks)
        if (read_inode(new_file_inode_num, &new_file_inode) != 0) {
             fprintf(stderr, "Failed to re-read inode %u before final size update for '%s'\n", new_file_inode_num, target_name);
             error_occurred = 1;
        } else {
            new_file_inode.size = total_bytes_written;
            if (write_inode(new_file_inode_num, &new_file_inode) != 0) {
                fprintf(stderr, "Failed to write final inode %u for file '%s'\n", new_file_inode_num, target_name);
                error_occurred = 1;
                // Data blocks are written, but inode size is wrong! Critical error.
            }
        }
    }

    // 7. Add entry to parent directory
    if (!error_occurred) {
        if (add_entry_to_dir(parent_inode_num, target_name, new_file_inode_num) != 0) {
             fprintf(stderr, "Failed to add entry for file '%s' to parent directory %u\n", target_name, parent_inode_num);
             error_occurred = 1;
             // File data exists, inode exists, but not linked in directory! Orphaned.
        }
    }

    // 8. Cleanup on error
    if (error_occurred) {
        fprintf(stderr, "An error occurred during add operation for '%s'. Attempting cleanup...\n", exfs_path);
        // Need to free allocated blocks and the inode. This requires iterating
        // through the potentially partially written inode's block pointers (direct/indirect)
        // and calling free_data_block / free_indirect_blocks.
        Inode cleanup_inode;
         if (read_inode(new_file_inode_num, &cleanup_inode) == 0) { // Read potentially partial inode
            // Free data blocks
            for(int i=0; i<MAX_DIRECT_POINTERS; ++i) free_data_block(cleanup_inode.direct_blocks[i]);
            free_indirect_blocks(cleanup_inode.single_indirect, 0);
            free_indirect_blocks(cleanup_inode.double_indirect, 1);
            free_indirect_blocks(cleanup_inode.triple_indirect, 2);
         } else {
              fprintf(stderr, "Cleanup warning: Could not read inode %u to free its blocks.\n", new_file_inode_num);
         }
        free_inode(new_file_inode_num); // Free the inode itself
        // We don't remove the entry from the parent dir here, as it likely wasn't added successfully on error.
        fprintf(stderr, "Cleanup attempted for failed add of '%s'. Filesystem might be inconsistent.\n", exfs_path);
    } else {
        // printf("Successfully added '%s' (inode %u, size %zu bytes)\n", exfs_path, new_file_inode_num, total_bytes_written); // Debug
    }
}


// Recursive remove helper
void remove_recursive(uint32_t inode_num, uint32_t parent_inode_num, const char* name) {
     Inode current_inode;
     if (read_inode(inode_num, &current_inode) != 0) {
         fprintf(stderr, "remove_recursive: Failed to read inode %u for '%s'\n", inode_num, name ? name : "(unknown)");
         return; // Cannot proceed without inode info
     }

     if (current_inode.is_directory) {
         // printf("Removing directory '%s' (inode %u)\n", name, inode_num); // Debug
         char block_buffer[BLOCK_SIZE];
         DirectoryEntry *entries = (DirectoryEntry *)block_buffer;
         size_t entries_processed = 0;
         size_t total_entries = current_inode.size; // Expected number of valid entries

         // TODO: Iterate through ALL directory blocks (direct, indirect)
         // Simplified: Direct blocks only
         for (int i = 0; i < MAX_DIRECT_POINTERS && entries_processed < total_entries; ++i) {
             uint32_t block_num = current_inode.direct_blocks[i];
             if (block_num == 0 || block_num == UINT32_MAX) continue;

             if (read_data_block(block_num, block_buffer) != 0) {
                 fprintf(stderr, "Warning: Failed read dir block %u during recursive remove of inode %u\n", block_num, inode_num);
                 continue; // Skip block
             }

             for (int j = 0; j < DIRENTRIES_PER_BLOCK; ++j) {
                 if (entries[j].inode_num != 0 && entries[j].inode_num != UINT32_MAX) { // If valid entry
                     entries_processed++;
                     // Skip . and .. for recursion, handle them later
                     if (strcmp(entries[j].name, ".") != 0 && strcmp(entries[j].name, "..") != 0) {
                         remove_recursive(entries[j].inode_num, inode_num, entries[j].name); // Recurse
                     }
                     if (entries_processed >= total_entries) goto dir_scan_done; // Optimization
                 }
             }
         }
         // ... Add logic for indirect blocks iteration ...
dir_scan_done:

          // After removing contents, free the directory's own data blocks
          // printf("Freeing data blocks for directory inode %u\n", inode_num); // Debug
          for(int i=0; i<MAX_DIRECT_POINTERS; ++i) free_data_block(current_inode.direct_blocks[i]);
          free_indirect_blocks(current_inode.single_indirect, 0);
          free_indirect_blocks(current_inode.double_indirect, 1);
          free_indirect_blocks(current_inode.triple_indirect, 2);

     } else {
          // It's a regular file
          // printf("Removing file '%s' (inode %u)\n", name, inode_num); // Debug
          // Free the file's data blocks
           // printf("Freeing data blocks for file inode %u\n", inode_num); // Debug
          for(int i=0; i<MAX_DIRECT_POINTERS; ++i) free_data_block(current_inode.direct_blocks[i]);
          free_indirect_blocks(current_inode.single_indirect, 0);
          free_indirect_blocks(current_inode.double_indirect, 1);
          free_indirect_blocks(current_inode.triple_indirect, 2);
     }

     // Remove entry from parent directory ONLY if parent and name are valid
     if (parent_inode_num != UINT32_MAX && name != NULL && strcmp(name, "/") != 0 ) { // Don't remove root entry
          // printf("Removing entry '%s' from parent directory inode %u\n", name, parent_inode_num); // Debug
         if(remove_entry_from_dir(parent_inode_num, name) != 0){
             fprintf(stderr, "Warning: Failed to remove entry '%s' from parent %u during cleanup.\n", name, parent_inode_num);
         }
     }

     // Free the inode itself
     // printf("Freeing inode %u ('%s')\n", inode_num, name ? name : ""); // Debug
     free_inode(inode_num);
}


// Main remove function called by command line handler
void remove_from_fs(const char *exfs_path) {
    // printf("Removing '%s'\n", exfs_path); // Debug

    uint32_t parent_inode_num = UINT32_MAX;
    uint32_t target_inode_num = UINT32_MAX;
    char target_name[MAX_FILENAME_LEN + 1];

    if (strcmp(exfs_path, "/") == 0) {
        fprintf(stderr, "Error: Cannot remove root directory '/'.\n");
        return;
    }

    // Find the target inode and its parent
    if (parse_path(exfs_path, &parent_inode_num, &target_inode_num, target_name) != 0) {
        // Error message already printed by parse_path if path is invalid
        // Check if the error was simply "not found" vs. bad path structure
        // If target_inode_num is still UINT32_MAX, it wasn't found.
        if (target_inode_num == UINT32_MAX) {
             fprintf(stderr, "Error: Path '%s' not found.\n", exfs_path);
        } // Otherwise parse_path printed a specific error
        return;
    }

    // Check again if target was found after successful parse
    if (target_inode_num == UINT32_MAX) {
        fprintf(stderr, "Error: '%s' not found.\n", exfs_path);
        return;
    }

    // Start recursive removal. Pass the parent inode number and target name
    // so the entry can be removed from the parent after the target is deleted.
    remove_recursive(target_inode_num, parent_inode_num, target_name);

    // printf("Removal process for '%s' complete.\n", exfs_path); // Debug
}

// Extracts a file's content to stdout
void extract_file_from_fs(const char *exfs_path) {
    // printf("Extracting '%s' to stdout\n", exfs_path); // Debug

    uint32_t parent_inode_num = UINT32_MAX;
    uint32_t target_inode_num = UINT32_MAX;
    char target_name[MAX_FILENAME_LEN + 1];

    if (parse_path(exfs_path, &parent_inode_num, &target_inode_num, target_name) != 0) {
        if (target_inode_num == UINT32_MAX) {
             fprintf(stderr, "Error: Path '%s' not found.\n", exfs_path);
        }
        return; // Error in path
    }

    if (target_inode_num == UINT32_MAX) {
        fprintf(stderr, "Error: File '%s' not found.\n", exfs_path);
        return;
    }

    Inode file_inode;
    if (read_inode(target_inode_num, &file_inode) != 0) {
        fprintf(stderr, "Error reading inode %u for extraction.\n", target_inode_num);
        return;
    }

    if (file_inode.is_directory) {
        fprintf(stderr, "Error: '%s' is a directory. Please specify a regular file for extraction.\n", exfs_path);
        return;
    }

    // Read data blocks and write to stdout
    char buffer[BLOCK_SIZE];
    size_t bytes_remaining = file_inode.size;
    size_t current_offset = 0;

    while (bytes_remaining > 0) {
        uint32_t block_num = get_block_for_offset(target_inode_num, current_offset, 0); // Allocate=0
        if (block_num == UINT32_MAX) {
            fprintf(stderr, "Error: Could not find data block for file '%s' at offset %zu. File possibly corrupt.\n", exfs_path, current_offset);
            return;
        }

        if (read_data_block(block_num, buffer) != 0) {
             fprintf(stderr, "Error reading data block %u for file '%s'.\n", block_num, exfs_path);
             return;
        }

        size_t bytes_to_write = (bytes_remaining < BLOCK_SIZE) ? bytes_remaining : BLOCK_SIZE;
        if (fwrite(buffer, 1, bytes_to_write, stdout) != bytes_to_write) {
             // Check for actual error vs. just pipe closed etc.
             if (ferror(stdout)) {
                 perror("Error writing file content to stdout");
             } // else: output pipe likely closed, stop writing.
             clearerr(stdout); // Clear error indicator for stdout
             return;
        }

        bytes_remaining -= bytes_to_write;
        current_offset += bytes_to_write;
    }
    // Ensure stdout is flushed if needed (often buffered)
    fflush(stdout);
}


// --- Initialization ---
void init_exfs2() {
     // Scan for existing segments to set next_*_segment_idx accurately
     // Check segment 0 specifically first.
     FILE *fp_i0 = open_segment(INODE_SEGMENT_PREFIX, 0, "rb");
     FILE *fp_d0 = open_segment(DATA_SEGMENT_PREFIX, 0, "rb");

     if (fp_i0 && fp_d0) {
         // printf("Found existing ExFS2 segments. (Basic Check)\n"); // Debug
         fclose(fp_i0);
         fclose(fp_d0);

         // Scan for highest numbered segment files to set next_*_idx correctly
         int i = 0;
         char fname[100];
         while (1) {
             get_segment_filename(INODE_SEGMENT_PREFIX, i, fname, sizeof(fname));
             if (access(fname, F_OK) == 0) { // Check if file exists
                 i++;
             } else {
                 break; // Stop when file doesn't exist
             }
         }
         next_inode_segment_idx = i; // Next index to create is the first one not found

         i = 0;
          while (1) {
             get_segment_filename(DATA_SEGMENT_PREFIX, i, fname, sizeof(fname));
             if (access(fname, F_OK) == 0) {
                 i++;
             } else {
                 break;
             }
         }
         next_data_segment_idx = i;
         // printf("Detected next inode segment: %d, next data segment: %d\n", next_inode_segment_idx, next_data_segment_idx); // Debug

         // Here you could also read some superblock info if you implement one.
     } else {
         // printf("Initializing new ExFS2 filesystem...\n"); // Debug
         if (fp_i0) fclose(fp_i0); // Close if only one existed
         if (fp_d0) fclose(fp_d0);

         // Create Segment 0 for inodes
         if (create_inode_segment(0) != 0) {
             fprintf(stderr, "Fatal: Could not create initial inode segment.\n");
             exit(EXIT_FAILURE);
         }
         // Create Segment 0 for data
         if (create_data_segment(0) != 0) {
             fprintf(stderr, "Fatal: Could not create initial data segment.\n");
             // Attempt cleanup? Remove inode_segment_0?
             remove("inode_segment_0.exfs"); // Attempt to remove
             exit(EXIT_FAILURE);
         }

         // Allocate and initialize root directory (inode 0)
         uint32_t root_inode_num = find_free_inode(); // Should allocate inode 0 from segment 0
         if (root_inode_num != 0) {
              fprintf(stderr, "Fatal: First allocated inode is not 0! (%u)\n", root_inode_num);
              exit(EXIT_FAILURE);
         }
         uint32_t root_data_block = find_free_data_block(); // Should allocate block 0 from segment 0
         if (root_data_block != 0) {
              fprintf(stderr, "Fatal: First allocated data block is not 0! (%u)\n", root_data_block);
              exit(EXIT_FAILURE);
         }

         // Write root inode
         Inode root_inode;
         memset(&root_inode, 0, sizeof(Inode));
         root_inode.is_directory = 1;
         root_inode.mode = S_IFDIR | 0755;
         root_inode.size = 2; // For "." and ".."
         root_inode.direct_blocks[0] = root_data_block;
         if (write_inode(root_inode_num, &root_inode) != 0) {
             fprintf(stderr, "Fatal: Failed to write root inode.\n");
             exit(EXIT_FAILURE);
         }

         // Write root data block (".", "..")
         char root_block_buffer[BLOCK_SIZE];
         DirectoryEntry *entries = (DirectoryEntry *)root_block_buffer;
         memset(root_block_buffer, 0, BLOCK_SIZE);
         strncpy(entries[0].name, ".", MAX_FILENAME_LEN);
         entries[0].inode_num = root_inode_num; // Root "." points to itself
         strncpy(entries[1].name, "..", MAX_FILENAME_LEN);
         entries[1].inode_num = root_inode_num; // Root ".." points to itself
         if (write_data_block(root_data_block, root_block_buffer) != 0) {
              fprintf(stderr, "Fatal: Failed to write root data block.\n");
              exit(EXIT_FAILURE);
         }

         // printf("Filesystem initialized successfully.\n"); // Debug
     }
}


// --- Main Function ---

int main(int argc, char *argv[]) {
    int opt;
    char *operation = NULL;
    char *exfs_path = NULL;
    char *local_path = NULL;
    int debug_mode = 0;

    // Option parsing using getopt
    while ((opt = getopt(argc, argv, "la:r:e:D:f:")) != -1) {
        switch (opt) {
            case 'l':
                if (operation) { fprintf(stderr, "Error: Multiple operations specified (-l and -%c).\n", operation[0]); return EXIT_FAILURE; }
                operation = "list";
                // List defaults to root if no path given via -D
                if (!exfs_path) exfs_path = "/";
                break;
            case 'a':
                 if (operation) { fprintf(stderr, "Error: Multiple operations specified (-a and -%c).\n", operation[0]); return EXIT_FAILURE; }
                 operation = "add";
                 exfs_path = optarg;
                 break;
            case 'r':
                 if (operation) { fprintf(stderr, "Error: Multiple operations specified (-r and -%c).\n", operation[0]); return EXIT_FAILURE; }
                 operation = "remove";
                 exfs_path = optarg;
                 break;
            case 'e':
                 if (operation) { fprintf(stderr, "Error: Multiple operations specified (-e and -%c).\n", operation[0]); return EXIT_FAILURE; }
                 operation = "extract";
                 exfs_path = optarg;
                 break;
             case 'D':
                 // Debug implies list, but can specify a path
                 debug_mode = 1;
                 exfs_path = optarg; // Path to debug/list
                 if (!operation) {
                     operation = "list"; // Default to list if only -D /path is given
                 } else if (strcmp(operation, "list") != 0) {
                     fprintf(stderr, "Warning: -D option ignored when combined with operation other than -l.\n");
                     // Keep the original operation, but debug flag is set (might be useful for other ops later)
                 }
                 break;
            case 'f': // Required argument for '-a'
                 // This option should only appear *after* -a has set the operation
                 if (!operation || strcmp(operation, "add") != 0) {
                      fprintf(stderr, "Error: -f option requires -a operation.\n");
                      return EXIT_FAILURE;
                 }
                 local_path = optarg;
                 break;
            case '?':
                // getopt prints an error message for unknown options or missing args
                 fprintf(stderr, "Usage: %s [-l | -D /exfs/path | -a /exfs/path -f /local/path | -r /exfs/path | -e /exfs/path]\n", argv[0]);
                return EXIT_FAILURE;
            default:
                // Should not happen with the options string provided
                abort();
        }
    }

    // Check for non-option arguments (should not be any)
    if (optind < argc) {
        fprintf(stderr, "Error: Unexpected non-option argument: %s\n", argv[optind]);
         fprintf(stderr, "Usage: %s [-l | -D /exfs/path | -a /exfs/path -f /local/path | -r /exfs/path | -e /exfs/path]\n", argv[0]);
        return EXIT_FAILURE;
    }

    // Validate arguments based on operation
    if (!operation) {
         fprintf(stderr, "No operation specified.\nUsage: %s [-l | -D /exfs/path | -a /exfs/path -f /local/path | -r /exfs/path | -e /exfs/path]\n", argv[0]);
         return EXIT_FAILURE;
    }
     if (strcmp(operation, "add") == 0 && (!exfs_path || !local_path)) {
         fprintf(stderr, "Error: -a operation requires both an exfs path (-a) and a local file path (-f).\n");
         return EXIT_FAILURE;
     }
     // For list/debug, remove, extract, exfs_path must be set (either by option or defaulted to "/" for -l)
     if ((strcmp(operation, "list") == 0 || strcmp(operation, "remove") == 0 || strcmp(operation, "extract") == 0) && !exfs_path) {
          fprintf(stderr, "Error: -%c operation requires an exfs path.\n", operation[0]);
          // This case might be redundant due to default path setting for -l/-D
          return EXIT_FAILURE;
     }


    // Initialize the filesystem (check existence or create)
    init_exfs2();

    // Execute the requested operation
    if (strcmp(operation, "list") == 0) {
        list_fs(exfs_path, debug_mode); // Pass debug mode flag
    } else if (strcmp(operation, "add") == 0) {
        add_file_to_fs(exfs_path, local_path);
    } else if (strcmp(operation, "remove") == 0) {
        remove_from_fs(exfs_path);
    } else if (strcmp(operation, "extract") == 0) {
        extract_file_from_fs(exfs_path);
    } else {
        // Should not happen due to argument validation
        fprintf(stderr, "Internal error: Unknown operation '%s'\n", operation);
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}