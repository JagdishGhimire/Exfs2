#ifndef EXFS2_H
#define EXFS2_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>     // For uint32_t, uint8_t
#include <unistd.h>     // For getopt
#include <sys/stat.h>   // For mode_t constants (like S_IFDIR)
#include <sys/types.h>  // For size_t, mode_t
#include <math.h>       // For ceil (potentially needed if calculations were dynamic)
#include <errno.h>
#include <limits.h>     // For PATH_MAX, UINT32_MAX
#include <assert.h>     // Include for static_assert (C11 or later)

// --- Constants ---
#define SEGMENT_SIZE (1024 * 1024) // 1MB
#define BLOCK_SIZE 4096
#define MAX_FILENAME_LEN 251 // Max filename length within directory entry
#define INODE_SIZE BLOCK_SIZE // Make inode struct exactly one block

#define INODE_SEGMENT_PREFIX "inode_segment_"
#define DATA_SEGMENT_PREFIX "data_segment_"
#define SEGMENT_SUFFIX ".exfs"

// --- Robust Inode Size Calculations ---

// Define a helper struct containing only the fixed-size fields
// This allows the compiler to determine its size including any internal padding.
typedef struct {
    uint8_t is_directory;
    mode_t mode;
    size_t size;
    uint32_t single_indirect;
    uint32_t double_indirect;
    uint32_t triple_indirect;
} InodeFixedPart;

// Calculate the actual size the compiler uses for the fixed part (accounts for padding)
#define INODE_FIXED_PART_ACTUAL_SIZE (sizeof(InodeFixedPart))

// Calculate space remaining within the block for direct pointers and any final padding
#define INODE_REMAINING_SPACE (INODE_SIZE - INODE_FIXED_PART_ACTUAL_SIZE)

// Calculate how many direct pointers fit in the remaining space
// Integer division automatically handles truncation if space isn't a multiple of pointer size.
#define MAX_DIRECT_POINTERS (INODE_REMAINING_SPACE / sizeof(uint32_t))

// Calculate the exact size occupied by the direct pointers array
#define DIRECT_POINTERS_ARRAY_SIZE (MAX_DIRECT_POINTERS * sizeof(uint32_t))

// Calculate the final padding needed to fill the block exactly (might be 0)
#define INODE_PADDING_SIZE (INODE_REMAINING_SPACE - DIRECT_POINTERS_ARRAY_SIZE)

// REMOVED the preprocessor check that caused the error:
// #if INODE_PADDING_SIZE < 0
// #error "Inode padding calculation resulted in negative size. Check struct layout/alignment."
// #endif

// --- Data Structures ---

// Inode Structure (Fits in BLOCK_SIZE)
typedef struct {
    // Fixed metadata fields
    uint8_t is_directory;       // Flag: 1 for directory, 0 for file
    mode_t mode;                // Permissions (using standard type)
    size_t size;                // File size bytes, or Dir entry count
    uint32_t single_indirect;   // Block number holding block pointers
    uint32_t double_indirect;   // Block number holding single indirect block numbers
    uint32_t triple_indirect;   // Block number holding double indirect block numbers

    // The direct pointers array (calculated size based on remaining space)
    uint32_t direct_blocks[MAX_DIRECT_POINTERS];

    // Final padding (if needed) to ensure the struct size is exactly BLOCK_SIZE
    char padding[INODE_PADDING_SIZE];
} Inode;

// Verify struct size at compile time using static_assert (C11+)
// This assertion should now pass with the revised calculation method.
static_assert(sizeof(Inode) == BLOCK_SIZE, "Inode size does not match BLOCK_SIZE");


// Constants derived from Inode structure (used elsewhere)
#define POINTERS_PER_BLOCK (BLOCK_SIZE / sizeof(uint32_t))

// Calculate max inodes/blocks per segment (approximate, adjust based on exact bitmap size)
// These calculations remain the same as they depend on the overall segment/block sizes
#define MAX_INODES_PER_SEGMENT 255
#define INODE_BITMAP_SIZE ((MAX_INODES_PER_SEGMENT + 7) / 8) // Ceiling division
#define INODE_AREA_SIZE (MAX_INODES_PER_SEGMENT * INODE_SIZE) // Not strictly used in code, but for understanding

#define MAX_BLOCKS_PER_DATA_SEGMENT 255
#define DATA_BITMAP_SIZE ((MAX_BLOCKS_PER_DATA_SEGMENT + 7) / 8) // Ceiling division
#define DATA_AREA_OFFSET (DATA_BITMAP_SIZE) // Data blocks start after bitmap in data segments

// Global Variables (declared here, defined in .c file)
// These track the next segment index to *potentially* create.
// A robust implementation would scan existing files on startup.
extern int next_inode_segment_idx;
extern int next_data_segment_idx;

// Directory Entry Structure
typedef struct {
    char name[MAX_FILENAME_LEN + 1]; // +1 for null terminator
    uint32_t inode_num;              // 0 indicates unused entry
} DirectoryEntry;

#define DIRENTRY_SIZE sizeof(DirectoryEntry)
#define DIRENTRIES_PER_BLOCK (BLOCK_SIZE / DIRENTRY_SIZE)


// --- Function Prototypes ---

// Initialization
void init_exfs2();

// Bitmap Operations
int get_bit(const uint8_t *bitmap, uint32_t index);
void set_bit(uint8_t *bitmap, uint32_t index);
void clear_bit(uint8_t *bitmap, uint32_t index);

// Segment Management
FILE* open_segment(const char* prefix, int index, const char* mode);
void get_segment_filename(const char* prefix, int index, char* buffer, size_t buffer_size);
int create_inode_segment(int index);
int create_data_segment(int index);

// Inode Operations
uint32_t find_free_inode();
int read_inode(uint32_t inode_num, Inode *inode_buffer);
int write_inode(uint32_t inode_num, const Inode *inode_buffer);
void free_inode(uint32_t inode_num);

// Data Block Operations
uint32_t find_free_data_block();
int read_data_block(uint32_t block_num, char *buffer);
int write_data_block(uint32_t block_num, const char *buffer);
void free_data_block(uint32_t block_num);
void free_indirect_blocks(uint32_t block_num, int level); // Helper for freeing blocks recursively

// Path and Directory Operations
int parse_path(const char *path, uint32_t *parent_inode_num, uint32_t *target_inode_num, char *target_name);
int find_entry_in_dir(uint32_t dir_inode_num, const char *name, uint32_t *entry_inode_num);
int add_entry_to_dir(uint32_t dir_inode_num, const char *name, uint32_t entry_inode_num);
int remove_entry_from_dir(uint32_t dir_inode_num, const char *name);
uint32_t create_directory(uint32_t parent_inode_num, const char *name);

// Core File System Operations
void list_fs(const char *path, int debug_mode);
void add_file_to_fs(const char *exfs_path, const char *local_path);
void remove_from_fs(const char *exfs_path);
void extract_file_from_fs(const char *exfs_path);

// Helper function for listing recursively
void list_recursive(uint32_t dir_inode_num, int depth, int debug_mode);

// Helper function for removing recursively
void remove_recursive(uint32_t inode_num, uint32_t parent_inode_num, const char* name);

// Helper for getting block number for a file offset
uint32_t get_block_for_offset(uint32_t inode_num, size_t offset, int allocate); // allocate=1 to allocate if needed

#endif // EXFS2_H
