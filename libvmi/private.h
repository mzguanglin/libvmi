/* The LibVMI Library is an introspection library that simplifies access to
 * memory in a target virtual machine or in a file containing a dump of
 * a system's physical memory.  LibVMI is based on the XenAccess Library.
 *
 * Copyright 2011 Sandia Corporation. Under the terms of Contract
 * DE-AC04-94AL85000 with Sandia Corporation, the U.S. Government
 * retains certain rights in this software.
 *
 * Author: Bryan D. Payne (bdpayne@acm.org)
 *
 * This file is part of LibVMI.
 *
 * LibVMI is free software: you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your
 * option) any later version.
 *
 * LibVMI is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public
 * License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with LibVMI.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef PRIVATE_H
#define PRIVATE_H
#define _GNU_SOURCE

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /* HAVE_CONFIG_H */

#include <glib.h>
#include <stdlib.h>
#include <stdio.h>
#include <math.h>
#include <ctype.h>
#include <time.h>
#include <inttypes.h>
#include "libvmi.h"
#include "os/os_interface.h"

/**
 * @brief LibVMI Instance.
 *
 * This struct holds all of the relavent information for an instance of
 * LibVMI.  Each time a new domain is accessed, a new instance must
 * be created using the vmi_init function.  When you are done with an instance,
 * its resources can be freed using the vmi_destroy function.
 */
struct vmi_instance {

    vmi_mode_t mode;        /**< VMI_FILE, VMI_XEN, VMI_KVM */

    uint32_t flags;         /**< flags passed to init function */

    uint32_t init_mode;     /**< VMI_INIT_PARTIAL or VMI_INIT_COMPLETE */

    GHashTable* config;    /**< configuration */

    uint32_t config_mode;     /**< VMI_CONFIG_NONE/FILE/STRING/GHASHTABLE */

    char *image_type;       /**< image type that we are accessing */

    char *image_type_complete;  /**< full path for file images */

    uint32_t page_shift;    /**< page shift for last mapped page */

    uint32_t page_size;     /**< page size for last mapped page */

    addr_t kpgd;            /**< kernel page global directory */

    addr_t init_task;       /**< address of task struct for init */

    os_t os_type;           /**< type of os: VMI_OS_LINUX, etc */

    int pae;                /**< nonzero if PAE is enabled */

    int pse;                /**< nonzero if PSE is enabled */

    int lme;                /**< nonzero if LME is enabled */

    page_mode_t page_mode;  /**< paging mode in use */

    uint64_t size;          /**< total size of target's memory */

    int hvm;                /**< nonzero if HVM */

    os_interface_t os_interface; /**< Guest OS specific functions */

    void* os_data; /**< Guest OS specific data */

    GHashTable *pid_cache;  /**< hash table to hold the PID cache data */

    GHashTable *sym_cache;  /**< hash table to hold the sym cache data */

    GHashTable *rva_cache;  /**< hash table to hold the rva cache data */

    GHashTable *v2p_cache;  /**< hash table to hold the v2p cache data */

#if ENABLE_SHM_SNAPSHOT == 1
    GHashTable *v2m_cache;  /**< hash table to hold the v2m cache data */
#endif

    void *driver;           /**< driver-specific information */

    GHashTable *memory_cache;  /**< hash table for memory cache */

    GList *memory_cache_lru;  /**< list holding the most recently used pages */

    uint32_t memory_cache_age; /**< max age of memory cache entry */

    uint32_t memory_cache_size;/**< current size of memory cache */

    uint32_t memory_cache_size_max;/**< max size of memory cache */

    unsigned int num_vcpus; /**< number of VCPUs used by this instance */

    GHashTable *interrupt_events; /**< interrupt event to function mapping (key: interrupt) */

    GHashTable *mem_events; /**< mem event to functions mapping (key: physical address) */

    GHashTable *reg_events; /**< reg event to functions mapping (key: reg) */

    GHashTable *ss_events; /**< single step event to functions mapping (key: vcpu_id) */

    gboolean shutting_down; /**< flag indicating that libvmi is shutting down */
};

/** Page-level memevent struct to also hold byte-level events in the embedded hashtable */
typedef struct memevent_page {

    vmi_mem_access_t access_flag; /**< combined page access flag */
    vmi_event_t *event; /**< page event registered */
    addr_t key; /**< page # */

    GHashTable  *byte_events; /**< byte events */

} memevent_page_t;

/** Windows' UNICODE_STRING structure (x86) */
typedef struct _windows_unicode_string32 {
    uint16_t length;
    uint16_t maximum_length;
    uint32_t pBuffer;   // pointer to string contents
} __attribute__ ((packed))
    win32_unicode_string_t;

/** Windows' UNICODE_STRING structure (x64) */
    typedef struct _windows_unicode_string64 {
        uint16_t length;
        uint16_t maximum_length;
        uint64_t pBuffer;   // pointer to string contents
    } __attribute__ ((packed))
    win64_unicode_string_t;

#if ENABLE_SHM_SNAPSHOT == 1

/** Guest virtual-medial-physical address mapping enables
 *   Direct Guest Virtual Memory Access (DGVMA) to the
 *   shm-snapshot.
 *  While the m2p mapping will be established at process
 *   page table and so MMU will take care of it, we must
 *   maintain v2m mapping by ourself.
 *  We use 3 structures to establish and maintain the v2m
 *   mapping. The three, from top to bottom, are v2m table,
 *   v2m_chunk and m2p mapping clue chunk.
 */

/* m2p mapping clue chunk is used to mmap guest physical
 *  address to medial address (i.e. LibVMI virtual address),
 *  and will be deleted just after mmap() because munmap()
 *  can be done with v2m chunk.
 * In a m2p chunk, the mappings between m and p are consecutive.
 */
typedef struct m2p_mapping_clue_chunk_struct {
    void * medial_mapping_addr;
    addr_t paddr_begin;
    addr_t paddr_end;
    addr_t vaddr_begin;
    addr_t vaddr_end;
    struct m2p_mapping_clue_chunk_struct* next;
} m2p_mapping_clue_chunk, *m2p_mapping_clue_chunk_t;

/* v2m chunk is used to maintain the mapping of v and m.
 *  We search an medial address of a given virtual address
 *  in a collection of v2m chunk.
 * In a m2p chunk, the virtual address range are continuous.
 */
typedef struct v2m_chunk_struct {
    addr_t vaddr_begin;
    addr_t vaddr_end;
    void * medial_mapping_addr;
    m2p_mapping_clue_chunk_t m2p_chunks;
    struct v2m_chunk_struct* next;
} v2m_chunk, *v2m_chunk_t;

// v2m table binds a pid and a list of v2m chunks
typedef struct v2m_table_struct {
    pid_t pid;
    v2m_chunk_t v2m_chunks;
    struct v2m_table_struct* next;
} v2m_table, *v2m_table_t;


/** Red black tree */
    /* Colors of a node of a red black tree. */
    typedef enum rb_color
    {
      red,
      black
    } rb_color_t;

    /* Key of a red black tree, describing a virtual memory area. */
    typedef struct rb_key
    {
      addr_t start_addr;            /** starting address of the VA block */
      addr_t end_addr;
    } rb_key_t;

    /* Internal node of a red black tree, describing a v2m mapping. */
    typedef struct v2m_rb_node
    {
      rb_color_t color;                             /** the color: red or black */
      rb_key_t key;                                 /** the key */
      m2p_mapping_clue_chunk_t m2p_chunks; /** be used to do mmap(), be NULL after mmap()  */
      void* media_mapping_addr;           /** mapping address of the VA block, be NULL before mmap() */
      struct v2m_rb_node * left;                              /** pointer to the left child node, NULL if no left child */
      struct v2m_rb_node * right;                             /** pointer to the right child node NULL if no right child */
      struct v2m_rb_node * p;                                 /** pointer to its parent node, NULL if it's a root node */
    } v2m_rb_node_t;

    // v2m table binds a pid and a list of v2m chunks
    typedef struct v2m_rb_tree {
        pid_t pid;
        v2m_rb_node_t * root_node;
        struct v2m_rb_tree* next;
        v2m_rb_node_t * leaf;
    } v2m_rb_tree_t;

#endif



/*----------------------------------------------
 * convenience.c
 */
#ifndef VMI_DEBUG
#define dbprint(format, args...) ((void)0)
#else
    void dbprint(
    char *format,
    ...) __attribute__((format(printf,1,2)));
#endif
    void errprint(
    char *format,
    ...) __attribute__((format(printf,1,2)));
    void warnprint(
    char *format,
    ...) __attribute__((format(printf,1,2)));

#define safe_malloc(size) safe_malloc_ (size, __FILE__, __LINE__)
    void *safe_malloc_(
    size_t size,
    char const *file,
    int line);
    unsigned long get_reg32(
    reg_t r);
    int vmi_get_bit(
    reg_t reg,
    int bit);
    addr_t aligned_addr(
    vmi_instance_t vmi,
    addr_t addr);
    int is_addr_aligned(
    vmi_instance_t vmi,
    addr_t addr);

/*-------------------------------------
 * cache.c
 */
    void pid_cache_init(
    vmi_instance_t vmi);
    void pid_cache_destroy(
    vmi_instance_t vmi);
    status_t pid_cache_get(
    vmi_instance_t vmi,
    vmi_pid_t pid,
    addr_t *dtb);
    void pid_cache_set(
    vmi_instance_t vmi,
    vmi_pid_t pid,
    addr_t dtb);
    status_t pid_cache_del(
    vmi_instance_t vmi,
    vmi_pid_t pid);
    void pid_cache_flush(
    vmi_instance_t vmi);

    void sym_cache_init(
    vmi_instance_t vmi);
    void sym_cache_destroy(
    vmi_instance_t vmi);
    status_t sym_cache_get(
    vmi_instance_t vmi,
    addr_t base_addr,
    vmi_pid_t pid,
    const char *sym,
    addr_t *va);
    void sym_cache_set(
    vmi_instance_t vmi,
    addr_t base_addr,
    vmi_pid_t pid,
    const char *sym,
    addr_t va);
    status_t sym_cache_del(
    vmi_instance_t vmi,
    addr_t base_addr,
    vmi_pid_t pid,
    char *sym);
    void sym_cache_flush(
    vmi_instance_t vmi);

    void v2p_cache_init(
    vmi_instance_t vmi);
    void v2p_cache_destroy(
    vmi_instance_t vmi);
    status_t v2p_cache_get(
    vmi_instance_t vmi,
    addr_t va,
    addr_t dtb,
    addr_t *pa);
    void v2p_cache_set(
    vmi_instance_t vmi,
    addr_t va,
    addr_t dtb,
    addr_t pa);
    status_t v2p_cache_del(
    vmi_instance_t vmi,
    addr_t va,
    addr_t dtb);
    void v2p_cache_flush(
    vmi_instance_t vmi);
#if ENABLE_SHM_SNAPSHOT == 1
    void v2m_cache_init(
    vmi_instance_t vmi);
    void v2m_cache_destroy(
    vmi_instance_t vmi);
    status_t v2m_cache_get(
    vmi_instance_t vmi,
    addr_t va,
    pid_t pid,
    addr_t *ma,
    uint64_t *length);
    void v2m_cache_set(
    vmi_instance_t vmi,
    addr_t va,
    pid_t pid,
    addr_t ma,
    uint64_t length);
    status_t v2m_cache_del(
    vmi_instance_t vmi,
    addr_t va,
    pid_t pid);
    void v2m_cache_flush(
    vmi_instance_t vmi);
#endif

/*-----------------------------------------
 * core.c
 */
    status_t
    get_memory_layout(
    vmi_instance_t vmi,
    page_mode_t *set_pm,
    int *set_pae,
    int *set_pse,
    int *set_lme);

/*-----------------------------------------
 * memory.c
 */
    void *vmi_read_page(
    vmi_instance_t vmi,
    addr_t frame_num);

/*-----------------------------------------
 * strmatch.c
 */

    void *boyer_moore_init(
    unsigned char *x,
    int m);
    int boyer_moore2(
    void *bm,
    unsigned char *y,
    int n);
    void boyer_moore_fini(
    void *bm);

    int boyer_moore(
    unsigned char *x,
    int m,
    unsigned char *y,
    int n);

/*-----------------------------------------
 * performance.c
 */
    void timer_start(
    );
    void timer_stop(
    const char *id);

/*----------------------------------------------
 * events.c
 */
    void events_init(
        vmi_instance_t vmi);
    void events_destroy(
        vmi_instance_t vmi);
    gboolean event_entry_free (
        gpointer key,
        gpointer value,
        gpointer data);
    typedef GHashTableIter event_iter_t;
    #define for_each_event(vmi, iter, table, key, val) \
        g_hash_table_iter_init(&iter, table); \
        while(g_hash_table_iter_next(&iter,(void**)key,(void**)val))


#if ENABLE_SHM_SNAPSHOT == 1
    void m2p_chunk_list_add_v2p_pairs(
        m2p_mapping_clue_chunk_t *m2p_chunk_list_ptr,
        m2p_mapping_clue_chunk_t *m2p_chunk_head_ptr,
        addr_t start_vaddr,
        addr_t end_vaddr,
        addr_t start_paddr,
        addr_t end_paddr);
    status_t m2p_chunk_list_delete(
        m2p_mapping_clue_chunk_t* m2p_chunk_list_ptr);
    status_t m2p_chunk_list_mmap(
        void* medial_addr_indicator,
        m2p_mapping_clue_chunk_t m2p_chunk_list,
        int shm_snapshot_fd);
    status_t m2p_chunk_list_munmap(
        v2m_chunk_t v2m_chunk_list);
    status_t probe_mmap_base_addr(
        size_t map_size,
        void ** base_addr_ptr);
    status_t dgvma_pid_to_dtb(
        vmi_instance_t vmi,
        pid_t pid,
        addr_t * dtb_ptr);


/*----------------------------------------------
 * dgvma_table.c
 */
    /*status_t create_v2m_table(
        vmi_instance_t vmi,
        pid_t pid,
        v2m_table_t * v2m_tables_ptr,
        int shm_snapshot_fd);*/
    status_t destroy_v2m_table_list(
        v2m_table_t * v2m_tables_ptr);
    status_t search_v2m_table(
        vmi_instance_t vmi,
        pid_t pid,
        v2m_table_t * v2m_table_list_ptr,
        addr_t vaddr,
        void ** maddr_ptr,
        size_t * mem_size_ptr,
        int shm_snapshot_fd);


    /*----------------------------------------------
     * dgvma_rb.c
     */
    /*status_t create_v2m_rb_tree(
        vmi_instance_t vmi,
        pid_t pid,
        v2m_rb_tree_t ** v2m_rb_tree_list_ptr);*/
    /*status_t destroy_v2m_rb_tree(
        pid_t pid,
        v2m_rb_tree_t ** v2m_rb_tree_ptr);*/
    status_t search_v2m_rb_tree(
        vmi_instance_t vmi,
        pid_t pid,
        v2m_rb_tree_t ** rb_tree_list_ptr,
        addr_t vaddr,
        void ** maddr_ptr,
        size_t * mem_size_ptr,
        int shm_snapshot_fd);
    status_t destroy_v2m_rb_tree_list(
        v2m_rb_tree_t ** tree_list_ptr);



#endif


#endif /* PRIVATE_H */
