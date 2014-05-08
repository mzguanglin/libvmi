/*
 * dgvma_m2p.c
 *
 *  Created on: May 6, 2014
 *      Author: root
 */

#include "libvmi.h"
#include "private.h"

/**
 * Throw v2p consecutive mapping range to the m2p chunk linked list.
 *  Depends on the new v2p pair, it either enlarges the head m2p
 *  chunk or add a new m2p chunk to the linked list.
 * @param[out] m2p_chunk_list_ptr will be created if NULL
 * @param[out] m2p_chunk_head_ptr will be updated if adding a new m2p chunk
 * @param[in] start_vaddr
 * @param[in] end_vaddr
 * @param[in] start_paddr
 * @param[in] end_paddr
 */
void m2p_chunk_list_add_v2p_pairs(
    m2p_mapping_clue_chunk_t * m2p_chunk_list_ptr,
    m2p_mapping_clue_chunk_t * m2p_chunk_head_ptr,
    addr_t start_vaddr,
    addr_t end_vaddr,
    addr_t start_paddr,
    addr_t end_paddr)
{
    // the first chunk
    if (NULL == *m2p_chunk_list_ptr) {
        *m2p_chunk_list_ptr = malloc(sizeof(m2p_mapping_clue_chunk));
        memset(*m2p_chunk_list_ptr, 0, sizeof(m2p_mapping_clue_chunk));
        (*m2p_chunk_list_ptr)->vaddr_begin = start_vaddr;
        (*m2p_chunk_list_ptr)->vaddr_end = end_vaddr;
        (*m2p_chunk_list_ptr)->paddr_begin = start_paddr;
        (*m2p_chunk_list_ptr)->paddr_end = end_paddr;
        (*m2p_chunk_head_ptr) = *m2p_chunk_list_ptr;
    } else {
        if (start_paddr == (*m2p_chunk_head_ptr)->paddr_end + 1) {
            // merge continuous mapping
            (*m2p_chunk_head_ptr)->vaddr_end = end_vaddr;
            (*m2p_chunk_head_ptr)->paddr_end = end_paddr;
        } else {
            // new entry
            m2p_mapping_clue_chunk_t new_page = malloc(sizeof(m2p_mapping_clue_chunk));
            memset(new_page, 0, sizeof(m2p_mapping_clue_chunk));
            new_page->vaddr_begin = start_vaddr;
            new_page->vaddr_end = end_vaddr;
            new_page->paddr_begin = start_paddr;
            new_page->paddr_end = end_paddr;
            (*m2p_chunk_head_ptr)->next = new_page;
            (*m2p_chunk_head_ptr) = new_page;
        }
    }
}

/**
 * Delete the m2p chunks linked list.
 *  After we have mapped the whole v2m area, we will never
 *  need m2p chunks.
 * @param[out] m2p_chunk_list_ptr will be NULL after deleting.
 */
status_t m2p_chunk_list_delete(
    m2p_mapping_clue_chunk_t* m2p_chunk_list_ptr)
{
    m2p_mapping_clue_chunk_t tmp = *m2p_chunk_list_ptr;
    while (NULL != tmp) {
        m2p_mapping_clue_chunk_t tmp2 = tmp->next;
        free(tmp);
        tmp = tmp2;
    }
    *m2p_chunk_list_ptr = NULL;
    return VMI_SUCCESS;
}

/**
 * mmap m2p indicated by a list of m2p mappping clue chunks and a medial address.
 * @param[in] medial_addr_indicator the start address
 * @param[in] m2p_chunk_list
 */
status_t m2p_chunk_list_mmap(
    void* medial_addr_indicator,
    m2p_mapping_clue_chunk_t m2p_chunk_list,
    int shm_snapshot_fd)
{
    size_t map_offset = 0;
     while (NULL != m2p_chunk_list) {
         dbprint("map va: %016llx - %016llx, pa: %016llx - %016llx, size: %dKB\n",
             m2p_chunk_list->vaddr_begin, m2p_chunk_list->vaddr_end,
             m2p_chunk_list->paddr_begin, m2p_chunk_list->paddr_end,
             (m2p_chunk_list->vaddr_end - m2p_chunk_list->vaddr_begin+1)>>10);
         size_t size = m2p_chunk_list->vaddr_end - m2p_chunk_list->vaddr_begin + 1;

         void *map = mmap(medial_addr_indicator + map_offset,  // addr
             (long long unsigned int)size,   // len
             PROT_READ,   // prot
             MAP_PRIVATE | MAP_NORESERVE | MAP_POPULATE | MAP_FIXED,  // flags
             shm_snapshot_fd,    // file descriptor
             m2p_chunk_list->paddr_begin);  // offset

         if (MAP_FAILED == map) {
             perror("Failed to mmap page");
             return VMI_FAILURE;
         }

         map_offset += size;
         m2p_chunk_list->medial_mapping_addr = map;
         m2p_chunk_list = m2p_chunk_list->next;
     }
     return VMI_SUCCESS;
}

/**
 * munmap many m2p mappings in a same v2m chunk.
 * @param[in] v2m_chunk_list
 */
status_t
m2p_chunk_list_munmap(
    v2m_chunk_t v2m_chunk_list)
{
    v2m_chunk_t tail = v2m_chunk_list;
    if (NULL != tail) {
        do {
            v2m_chunk_t tmp = tail->next;
            munmap(tail->medial_mapping_addr,
                (tail->vaddr_end - tail->vaddr_begin + 1));
            free(tail);
            tail = tmp;
        } while (NULL != tail);
        return VMI_SUCCESS;
    }
    else {
        errprint("try to free NULL v2m_entry->chunks");
        return VMI_FAILURE;
    }
}

/**
 * As we must ensure consecutive v2m mappings which are usually constituted by
 *  many m2p chunks, we should probe a large enough medial address range (i.e.
 *  LibVMI virtual address) to place those m2p mappings together.
 * @param[in] map_size
 * @param[out] base_addr_ptr
 */
status_t
probe_mmap_base_addr(
    size_t map_size,
    void** base_addr_ptr)
{
    // find a large enough vaddr base
    void *map = mmap(NULL,  // addr
        (long long unsigned int)map_size,   // vaddr space
        PROT_READ,   // prot
        MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE,  // flags
        0,    // file descriptor
        0);  // offset
    if (MAP_FAILED != map) {
        *base_addr_ptr = map;
        (void) munmap(map, map_size);
    }
    else {
        errprint("Failed to find large enough medial address space,"
            " size:"PRIu64" MB\n", map_size>>20);
        perror("");
        return VMI_FAILURE;
    }
    return VMI_SUCCESS;
}

status_t
dgvma_pid_to_dtb(
    vmi_instance_t vmi,
    pid_t pid,
    addr_t * dtb_ptr)
{
    addr_t dtb = 0;
    // kernel page table
    if (0 == pid) {
        reg_t cr3 = 0;
        if (vmi->kpgd) {
            cr3 = vmi->kpgd;
        }
        else {
            driver_get_vcpureg(vmi, &cr3, CR3, 0);
        }
        if (!cr3) {
            errprint("--early bail on dgvma_pid_to_dtb() because cr3 is zero\n");
            return VMI_FAILURE;
        }
        else {
            dtb = cr3;
        }
    }
    else {
        // user process page table
        dtb = vmi_pid_to_dtb(vmi, pid);
        if (!dtb) {
            errprint("--early bail on dgvma_pid_to_dtb() because dtb is zero\n");
            return VMI_FAILURE;
        }
    }
    *dtb_ptr = dtb;
    return VMI_SUCCESS;
}
