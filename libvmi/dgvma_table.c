/* The LibVMI Library is an introspection library that simplifies access to
 * memory in a target virtual machine or in a file containing a dump of
 * a system's physical memory.  LibVMI is based on the XenAccess Library.
 *
 * Copyright 2011 Sandia Corporation. Under the terms of Contract
 * DE-AC04-94AL85000 with Sandia Corporation, the U.S. Government
 * retains certain rights in this software.
 *
 * Author: Bryan D. Payne (bdpayne@acm.org)
 * Author: Guanglin Xu (mzguanglin@gmail.com)
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

#include "libvmi.h"
#include "private.h"

#if ENABLE_SHM_SNAPSHOT == 1


/**
 * Throw v2p consecutive mapping range to this v2m chunk creator.
 * @param[in] vmi LibVMI instance
 * @param[out] v2m_chunk_list_ptr
 * @param[out] v2m_chunk_head_ptr
 * @param[out] m2p_chunk_list_ptr
 * @param[out] m2p_chunk_head_ptr
 * @param[in] start_vaddr
 * @param[in] end_vaddr
 * @param[in] start_paddr
 * @param[in] end_paddr
 */
static void insert_v2p_page_pair_to_v2m_chunk_list(
    vmi_instance_t vmi,
    v2m_chunk_t *v2m_chunk_list_ptr,
    v2m_chunk_t *v2m_chunk_head_ptr,
    m2p_mapping_clue_chunk_t *m2p_chunk_list_ptr,
    m2p_mapping_clue_chunk_t *m2p_chunk_head_ptr,
    addr_t start_vaddr,
    addr_t end_vaddr,
    addr_t start_paddr,
    addr_t end_paddr)
{
#ifdef PRINT_V2P_BLOCK
    // v2p block
    printf("v2pva: 0x%lx ~ 0x%lx, pa: 0x%lx ~ 0x%lx, size: %ld KB\n", start_vaddr, end_vaddr,start_paddr,  end_paddr, (end_paddr+1 - start_paddr)>>10);
#endif
    // the first v2m chunk
    if (NULL == *v2m_chunk_list_ptr) {
        *v2m_chunk_list_ptr = malloc(sizeof(v2m_chunk));
        memset(*v2m_chunk_list_ptr, 0, sizeof(v2m_chunk));
        (*v2m_chunk_list_ptr)->vaddr_begin = start_vaddr;
        (*v2m_chunk_list_ptr)->vaddr_end = end_vaddr;
        (*v2m_chunk_head_ptr) = *v2m_chunk_list_ptr;

        *m2p_chunk_list_ptr = (*v2m_chunk_head_ptr)->m2p_chunks;
        *m2p_chunk_head_ptr = (*v2m_chunk_head_ptr)->m2p_chunks;

        // the first m2p chunk
        m2p_chunk_list_add_v2p_pairs(m2p_chunk_list_ptr, m2p_chunk_head_ptr, start_vaddr,
            end_vaddr, start_paddr, end_paddr);
        (*v2m_chunk_head_ptr)->m2p_chunks = *m2p_chunk_list_ptr;
    } else {
        if (start_vaddr == (*v2m_chunk_head_ptr)->vaddr_end + 1) {
            // continuous vaddr
            //  1. insert p2m chunk.
            m2p_chunk_list_add_v2p_pairs(m2p_chunk_list_ptr, m2p_chunk_head_ptr, start_vaddr,
                end_vaddr, start_paddr, end_paddr);
            //  2. expand v2m chunk
            (*v2m_chunk_head_ptr)->vaddr_end = end_vaddr;
        } else {
#ifdef PRINT_V2M_BLOCK
            // v2m block
            printf("v2mva: 0x%lx ~ 0x%lx, size: %ld KB\n", (*v2m_chunk_head_ptr)->vaddr_begin,
                (*v2m_chunk_head_ptr)->vaddr_end,  ((*v2m_chunk_head_ptr)->vaddr_end + 1 - (*v2m_chunk_head_ptr)->vaddr_begin)>>10);
#endif

            // incontinuous vaddr, so new v2m chunk
            v2m_chunk_t new_page = malloc(sizeof(v2m_chunk));
            memset(new_page, 0, sizeof(v2m_chunk));
            new_page->vaddr_begin = start_vaddr;
            new_page->vaddr_end = end_vaddr;
            (*v2m_chunk_head_ptr)->next = new_page;
            (*v2m_chunk_head_ptr) = new_page;

            *m2p_chunk_list_ptr = (*v2m_chunk_head_ptr)->m2p_chunks;
            *m2p_chunk_head_ptr = (*v2m_chunk_head_ptr)->m2p_chunks;

            // the first p2m chunk
            m2p_chunk_list_add_v2p_pairs(m2p_chunk_list_ptr, m2p_chunk_head_ptr, start_vaddr,
                end_vaddr, start_paddr, end_paddr);
            (*v2m_chunk_head_ptr)->m2p_chunks = *m2p_chunk_list_ptr;
        }
    }
}

static status_t
walkthrough_shm_snapshot_pagetable_nopae(
    vmi_instance_t vmi,
    addr_t dtb,
    v2m_chunk_t* v2m_chunk_list_ptr)
{
    v2m_chunk_t v2m_chunk_list = *v2m_chunk_list_ptr;
    v2m_chunk_t v2m_chunk_head = NULL;
    m2p_mapping_clue_chunk_t m2p_chunk_list = NULL;
    m2p_mapping_clue_chunk_t m2p_chunk_head = NULL;

    //read page directory (1 page size)
    addr_t pd_pfn = dtb >> vmi->page_shift;
    unsigned char *pd = vmi_read_page(vmi, pd_pfn); // page directory

    // walk through page directory entries (1024 entries)
    addr_t i;
    for (i = 0; i < 1024; i++) {
        uint32_t pde = *(uint32_t*) (pd + sizeof(uint32_t) * i); // pd entry

        // valid entry
        if (entry_present(vmi->os_type, pde)) {

            // large page (4mb)
            if (page_size_flag(pde)) {
                addr_t start_vaddr = i << 22; // left 10 bits
                addr_t end_vaddr = start_vaddr | 0x3FFFFF; // begin + 4mb
                addr_t start_paddr = pde & 0xFFC00000; // left 10 bits
                addr_t end_paddr = start_paddr | 0x3FFFFF; // begin + 4mb
                if (start_paddr < vmi->size) {
                    insert_v2p_page_pair_to_v2m_chunk_list(vmi, &v2m_chunk_list, &v2m_chunk_head,
                        &m2p_chunk_list, &m2p_chunk_head,
                        start_vaddr, end_vaddr, start_paddr, end_paddr);
                }
            }
            else {
                // read page table (1 page size)
                addr_t pt_pfn = ptba_base_nopae(pde) >> vmi->page_shift;
                unsigned char *pt = vmi_read_page(vmi, pt_pfn); // page talbe

                // walk through page table entries (1024 entries)
                addr_t j;
                for (j = 0; j < 1024; j++) {
                    uint32_t pte = *(uint32_t*) (pt + sizeof(uint32_t) * j); // page table entry

                    //valid entry
                    if (entry_present(vmi->os_type, pte)) {
                        dbprint("valid page table entry %d, %8x:\n", i, pte);
                        // 4kb page
                        addr_t start_vaddr = i << 22 | j << 12; // left 20 bits
                        addr_t end_vaddr = start_vaddr | 0xFFF; // begin + 4kb
                        addr_t start_paddr = pte_pfn_nopae(pte); // left 20 bits
                        addr_t end_paddr = start_paddr | 0xFFF; // begin + 4kb
                        if (start_paddr < vmi->size) {
                            insert_v2p_page_pair_to_v2m_chunk_list(vmi, &v2m_chunk_list, &v2m_chunk_head,
                                &m2p_chunk_list, &m2p_chunk_head,
                                start_vaddr, end_vaddr, start_paddr, end_paddr);
                        }
                    }
                }
            }
        }
    }
    *v2m_chunk_list_ptr = v2m_chunk_list;
    return VMI_SUCCESS;
}

static status_t
walkthrough_shm_snapshot_pagetable_pae(
    vmi_instance_t vmi,
    addr_t dtb,
    v2m_chunk_t* v2m_chunk_list_ptr)
{
    v2m_chunk_t v2m_chunk_list = *v2m_chunk_list_ptr;
    v2m_chunk_t v2m_chunk_head = NULL;
    m2p_mapping_clue_chunk_t m2p_chunk_list = NULL;
    m2p_mapping_clue_chunk_t m2p_chunk_head = NULL;

    // read page directory pointer page (4 entries, 64bit per entry)
    addr_t pdpt_pfn = dtb >> vmi->page_shift;
    unsigned char *pdpt = vmi_read_page(vmi, pdpt_pfn); // pdp table

    // walk through page directory pointer entries (4 entries, 64bit per entry)
    addr_t i;
    for (i = 0; i < 4; i++) {
        uint64_t pdpte = *(uint64_t *) (pdpt + sizeof(uint64_t) * i); // pdp table entry

        // valid page directory pointer entry
        if (entry_present(vmi->os_type, pdpte)) {

            //read page directory  (1 page size)
            addr_t pd_pfn = pdba_base_pae(pdpte) >> vmi->page_shift; // 24 (35th ~ 12th) bits
            unsigned char *pd = vmi_read_page(vmi, pd_pfn); // page directory

            // walk through page directory entry (512 entries, 64 bit per entry)
            addr_t j;
            for (j = 0; j < 512; j++) {
                uint64_t pde = *(uint64_t *) (pd + sizeof(uint64_t) * j); // page directory entry

                // valid page directory entry
                if (entry_present(vmi->os_type, pde)) {

                    if (page_size_flag(pde)) { // 2MB large page

                        addr_t start_vaddr = i << 30 | j << 21; // left 11 bits
                        addr_t end_vaddr = start_vaddr | 0x1FFFFF; // begin + 2mb
                        addr_t start_paddr = pde & 0xFFFE00000; // 11 bits,  should be 15 (35th - 21th) bits
                        addr_t end_paddr = start_paddr | 0x1FFFFF; // begin + 2mb

                        if (start_paddr < vmi->size) {
                            insert_v2p_page_pair_to_v2m_chunk_list(vmi, &v2m_chunk_list, &v2m_chunk_head,
                                &m2p_chunk_list, &m2p_chunk_head,
                                start_vaddr, end_vaddr, start_paddr, end_paddr);
                        }
                    }
                    else {
                        // read page tables
                        addr_t pt_pfn = ptba_base_pae(pde) >> vmi->page_shift; // 24 (35th ~ 12th) bits
                        unsigned char *pt = vmi_read_page(vmi, pt_pfn); // page table

                        // walk through page table entry (512 entries, 64bit per entry)
                        addr_t k;
                        for (k = 0; k < 512; k++) {
                            uint64_t pte = *(uint64_t *) (pt
                                + sizeof(uint64_t) * k); // page table entry

                            // valid page table entry
                            if (entry_present(vmi->os_type, pte)) {
                                // 4kb page
                                addr_t start_vaddr = i << 30 | j << 21
                                    | k << 12; // left 20 bits
                                addr_t end_vaddr = start_vaddr | 0xFFF; // begin + 4kb
                                addr_t start_paddr = pte_pfn_pae(pte); // 24 (35th ~ 12th) bits
                                addr_t end_paddr = start_paddr | 0xFFF; // begin + 4kb

                                if (start_paddr < vmi->size) {
                                    insert_v2p_page_pair_to_v2m_chunk_list(vmi, &v2m_chunk_list,
                                        &v2m_chunk_head,
                                        &m2p_chunk_list, &m2p_chunk_head,
                                        start_vaddr, end_vaddr,
                                        start_paddr, end_paddr);
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    *v2m_chunk_list_ptr = v2m_chunk_list;
    return VMI_SUCCESS;
}

static status_t
walkthrough_shm_snapshot_pagetable_ia32e(
    vmi_instance_t vmi,
    addr_t dtb,
    v2m_chunk_t* v2m_chunk_list_ptr)
{
    v2m_chunk_t v2m_chunk_list = *v2m_chunk_list_ptr;
    v2m_chunk_t v2m_chunk_head = NULL;
    m2p_mapping_clue_chunk_t m2p_chunk_list = NULL;
    m2p_mapping_clue_chunk_t m2p_chunk_head = NULL;

    // read PML4 table (512 * 64-bit entries)
    addr_t pml4t_pfn = get_bits_51to12(dtb) >> vmi->page_shift;
    unsigned char* pml4t = vmi_read_page(vmi, pml4t_pfn); // pml4 table

    // walk through PML4 entries (512 * 64-bit entries)
    addr_t i;
    for (i = 0; i < 512; i++) {
        uint64_t pml4e = *(uint64_t *) (pml4t + sizeof(uint64_t) * i);

        // valid page directory pointer entry
        if (entry_present(vmi->os_type, pml4e)) {
            // read page directory pointer table (512 * 64-bit entries)
            addr_t pdpt_pfn = get_bits_51to12(pml4e) >> vmi->page_shift;
            unsigned char *pdpt = vmi_read_page(vmi, pdpt_pfn); // pdp table

            // walk through page directory pointer entries (512 * 64-bit entries)
            addr_t j;
            for (j = 0; j < 512; j++) {
                uint64_t pdpte = *(uint64_t *) (pdpt + sizeof(uint64_t) * j); // pdp table entry

                // valid page directory pointer entry
                if (entry_present(vmi->os_type, pdpte)) {
                    if (page_size_flag(pdpte)) { // 1GB large page
                        addr_t start_vaddr = i << 39 | j << 30; // 47th ~ 30th bits
                        addr_t end_vaddr = start_vaddr | 0xFFFFFFFF; // begin + 1GB
                        addr_t start_paddr = pdpte & 0x000FFFFFC0000000ULL; //  22 (51th - 30th) bits
                        addr_t end_paddr = start_paddr | 0xFFFFFFFF; // begin + 1GB

                        if (start_paddr < vmi->size) {
                            insert_v2p_page_pair_to_v2m_chunk_list(vmi, &v2m_chunk_list, &v2m_chunk_head,
                                &m2p_chunk_list, &m2p_chunk_head,
                                start_vaddr, end_vaddr, start_paddr, end_paddr);
                        }

                    }
                    else {
                        //read page directory  (1 page size)
                        addr_t pd_pfn = get_bits_51to12(pdpte)
                            >> vmi->page_shift; // 40 (51th ~ 12th) bits
                        unsigned char *pd = vmi_read_page(vmi, pd_pfn); // page directory

                        // walk through page directory entry (512 entries, 64 bit per entry)
                        addr_t k;
                        for (k = 0; k < 512; k++) {
                            uint64_t pde = *(uint64_t *) (pd
                                + sizeof(uint64_t) * k); // pd entry

                            // valid page directory entry
                            if (entry_present(vmi->os_type, pde)) {
                                if (page_size_flag(pde)) { // 2MB large page

                                    addr_t start_vaddr = i << 39 | j << 30
                                        | k << 21; //
                                    addr_t end_vaddr = start_vaddr | 0x1FFFFF; // begin + 2mb
                                    addr_t start_paddr = pde
                                        & 0x000FFFFFFFE00000ULL; // 31 (51th - 21th) bits
                                    addr_t end_paddr = start_paddr | 0x1FFFFF; // begin + 2mb

                                    if (start_paddr < vmi->size) {
                                        insert_v2p_page_pair_to_v2m_chunk_list(vmi, &v2m_chunk_list,
                                            &v2m_chunk_head,
                                            &m2p_chunk_list, &m2p_chunk_head,
                                            start_vaddr, end_vaddr,
                                            start_paddr, end_paddr);
                                    }
                                }
                                else {
                                    // read page tables
                                    addr_t pt_pfn = get_bits_51to12(pde)
                                        >> vmi->page_shift; // 40 (51th ~ 12th) bits
                                    unsigned char *pt = vmi_read_page(vmi,
                                        pt_pfn); // page table

                                    // walk through page table entry (512 entries, 64bit per entry)
                                    addr_t l;
                                    for (l = 0; l < 512; l++) {
                                        uint64_t pte = *(uint64_t *) (pt
                                            + sizeof(uint64_t) * l); // pt entry

                                        // valid page table entry
                                        if (entry_present(vmi->os_type, pte)) {
                                            // 4kb page
                                            addr_t start_vaddr = i << 39
                                                | j << 30 | k << 21 | l << 12; // 47th - 12th bits
                                            addr_t end_vaddr = start_vaddr
                                                | 0xFFF; // begin + 4kb
                                            addr_t start_paddr =
                                                get_bits_51to12(pte); // 40 (51th ~ 12th) bits
                                            addr_t end_paddr = start_paddr
                                                | 0xFFF; // begin + 4kb

                                            if (start_paddr < vmi->size) {
                                                insert_v2p_page_pair_to_v2m_chunk_list(vmi,
                                                    &v2m_chunk_list, &v2m_chunk_head,
                                                    &m2p_chunk_list, &m2p_chunk_head,
                                                    start_vaddr, end_vaddr,
                                                    start_paddr, end_paddr);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    *v2m_chunk_list_ptr = v2m_chunk_list;
    return VMI_SUCCESS;
}

/**
 * Insert a v2m table to the collection
 * @param[in] vmi LibVMI instance
 * @param[in] entry v2m table
 */
static status_t
v2m_table_list_add_table(
    v2m_table_t* current_tables_ptr,
    v2m_table_t entry)
{
    // the first v2m table
    if (*current_tables_ptr == NULL) {
        *current_tables_ptr = entry;
        return VMI_SUCCESS;
    }
    else {
        // append to the existed v2m table link list
        v2m_table_t head = *current_tables_ptr;
        while (NULL != head->next) {
            head = head->next;
        }
        head->next = entry;
        return VMI_SUCCESS;
    }
}

static v2m_table_t
v2m_table_init(
    pid_t pid,
    v2m_chunk_t v2m_list)
{
    v2m_table_t v2m_table_tmp = malloc(sizeof(v2m_table));
    v2m_table_tmp->pid = pid;
    v2m_table_tmp->v2m_chunks = v2m_list;
    v2m_table_tmp->next = NULL;
    return v2m_table_tmp;
}

/**
 * delete a given v2m table structure
 * @param[in] v2m_table the table to delete
 * @param[out] v2m_tables the renewed v2m tables
 */
static status_t
v2m_table_list_remove_table(
    v2m_table_t v2m_table,
    v2m_table_t * v2m_tables_ptr)
{
    // the 1st entry matches
    if (NULL != *v2m_tables_ptr
        && v2m_table == *v2m_tables_ptr) {
        v2m_table_t tmp = *v2m_tables_ptr;
        *v2m_tables_ptr = tmp->next;
        free(tmp);
        return VMI_SUCCESS;
    }
    // there are two or more entries
    else if (NULL != *v2m_tables_ptr
        && NULL != (*v2m_tables_ptr)->next) {
        v2m_table_t tmp[2];
        tmp[0] = *v2m_tables_ptr;
        tmp[1] = (*v2m_tables_ptr)->next;
        while (NULL != tmp[1]) {
            if (v2m_table == tmp[1]) {
                tmp[0]->next = tmp[1]->next;
                free(tmp[1]);
                return VMI_SUCCESS;
            }
            tmp[0] = tmp[1];
            tmp[1] = tmp[1]->next;
        }
        return VMI_FAILURE;
    }
    // no entry matches
    else
        return VMI_FAILURE;
}

// linear growing address.
// @param[in] table not NULL
static v2m_chunk_t
v2m_table_find_chunk(
    v2m_table_t table,
    addr_t vaddr_begin)
{
    v2m_chunk_t chunk = table->v2m_chunks;
    if (vaddr_begin < chunk->vaddr_begin)
        return NULL;

    while (NULL != chunk && vaddr_begin > chunk->vaddr_end) {
        chunk = chunk->next;
    }

    if (NULL == chunk || vaddr_begin < chunk->vaddr_begin)
        return NULL;
    else
        return chunk;
}

static status_t
v2m_chunk_list_mmap(
    v2m_chunk_t v2m_chunk_list,
    int shm_snapshot_fd)
{
    v2m_chunk_t v2m_chunk_tmp = v2m_chunk_list;
    while (NULL != v2m_chunk_tmp) {
        // probe v2m medial address
        void* maddr_indicator;
        size_t v2m_size = v2m_chunk_tmp->vaddr_end - v2m_chunk_tmp->vaddr_begin + 1;
        status_t ret_probe = probe_mmap_base_addr(v2m_size, &maddr_indicator);
        if (VMI_FAILURE == ret_probe) {
            errprint("fail to probe medial space for va: %016lx - %016lx, "
                "size: %ldKB\n", v2m_chunk_tmp->vaddr_begin, v2m_chunk_tmp->vaddr_end, v2m_size>>10);
            return VMI_FAILURE;
        }

        status_t ret_mmap = m2p_chunk_list_mmap(maddr_indicator, v2m_chunk_tmp->m2p_chunks, shm_snapshot_fd);
        // mmap each m2p memory chunk
        if (VMI_SUCCESS != ret_mmap) {
            errprint("fail to mmap for va: %016lx - %016lx, "
                "size: %ldKB\n", v2m_chunk_tmp->vaddr_begin, v2m_chunk_tmp->vaddr_end, v2m_size>>10);
            return VMI_FAILURE;
        }

        status_t ret_del = m2p_chunk_list_delete(&v2m_chunk_tmp->m2p_chunks);
        // delete m2p chunks
        if (VMI_SUCCESS != ret_del) {
            return VMI_FAILURE;
        }

        // assign valid maddr
        v2m_chunk_tmp->medial_mapping_addr = maddr_indicator;

        v2m_chunk_tmp = v2m_chunk_tmp->next;
    }
    return VMI_SUCCESS;
}

/**
 * Search the collection of v2m tables by a pid.
 * @param[in] pid Pid of the virtual address space (0 for kernel)
 * @param[in] v2m_tables
 */
static v2m_table_t
v2m_table_list_find_table(
    v2m_table_t v2m_table_list,
    pid_t pid,
    v2m_table_t * target_prev)
{
    v2m_table_t table = v2m_table_list;
    v2m_table_t hit = NULL;
    v2m_table_t prev = NULL;
    while (NULL != table) {
        if (pid == table->pid) {
            hit = table;
            break;
        }
        prev = table;
        table = table->next;
    }

    // found
    if (NULL != hit) {
        if (NULL != target_prev) {
            *target_prev = prev;
        }
        return hit;
    }
    else {
        dbprint("v2m_table_list_find_table() failed because no pid "
                        "table\n");
        return NULL;
    }
}

/**walkthrough_shm_snapshot_pagetable
 * Create a v2m table of a given pid.
 * This function will walkthrough the page table of the given pid, establish
 *  the mappings of v2m and m2p, and then insert the new v2m table to a
 *  collection.
 * @param[in] vmi LibVMI instance, use to read memory page, etc.
 * @param[in] pid Pid of the virtual address space (0 for kernel)
 * @param[out] v2m_tables_ptr the renewed v2m tables
 * @param[in] shm_snapshot_fd
 */
static status_t
create_v2m_table(
    vmi_instance_t vmi,
    pid_t pid,
    v2m_table_t * v2m_tables_ptr,
    v2m_table_t * new_v2m_table,
    int shm_snapshot_fd)
{
    // 1. pid -> dtb
    addr_t dtb;
    status_t ret_p2d;
    ret_p2d = dgvma_pid_to_dtb(vmi, pid, &dtb);
    if (VMI_FAILURE == ret_p2d)
        return VMI_FAILURE;

    v2m_chunk_t v2m_chunk_list = NULL;

#ifdef WALK_PT_MEASUREMENT
    struct timeval ktv_start;
    struct timeval ktv_end;
    gettimeofday(&ktv_start, 0);
#endif

    status_t ret_walk;

    switch (vmi->page_mode) {
    case VMI_PM_LEGACY:
        ret_walk = walkthrough_shm_snapshot_pagetable_nopae(vmi, dtb,
            &v2m_chunk_list);
        break;
    case VMI_PM_PAE:
        ret_walk =  walkthrough_shm_snapshot_pagetable_pae(vmi, dtb,
            &v2m_chunk_list);
        break;
    case VMI_PM_IA32E:
        ret_walk =  walkthrough_shm_snapshot_pagetable_ia32e(vmi, dtb,
            &v2m_chunk_list);
        break;
    default:
        errprint(
            "Invalid paging mode during walkthrough_shm_snapshot_pagetable\n");
        break;
    }

#ifdef WALK_PT_MEASUREMENT
    gettimeofday(&ktv_end, 0);
    print_measurement("walk page table", ktv_start, ktv_end);
#endif

#ifdef PROBE_MMAP_ADDR_MEASUREMENT
        gettimeofday(&ktv_start, 0);
#endif

    if (VMI_SUCCESS == ret_walk)
    {
        status_t ret_mmap_v2m;
        ret_mmap_v2m = v2m_chunk_list_mmap(v2m_chunk_list, shm_snapshot_fd);
        if (VMI_SUCCESS != ret_mmap_v2m)
            return VMI_FAILURE;

#ifdef PROBE_MMAP_ADDR_MEASUREMENT
        gettimeofday(&ktv_end, 0);
        print_measurement("probe and mmap addr space", ktv_start, ktv_end);
#endif

        v2m_table_t v2m_table_tmp;
        v2m_table_tmp = v2m_table_init(pid, v2m_chunk_list);
        v2m_table_list_add_table(v2m_tables_ptr, v2m_table_tmp);

        *new_v2m_table = v2m_table_tmp;
        return VMI_SUCCESS;
    }
    return VMI_FAILURE;
}

/**
 * Search the medial address of a given virtual address.
 *
 *   automatically create v2m table for new pid
 * @param[in] vmi LibVMI instance
 * @param[in] v2m_table
 * @param[in] vaddr the virtual address
 * @param[out] medial_vaddr_ptr the corresponded medial address
 * @return the size of the DGVMA area
 */
status_t
search_v2m_table(
    vmi_instance_t vmi,
    pid_t pid,
    v2m_table_t * v2m_table_list_ptr,
    addr_t vaddr,
    void ** maddr_ptr,
    size_t * mem_size_ptr,
    int shm_snapshot_fd)
{
    // Get a v2m table by pid from table list
    //   try to find v2m table of pid
    v2m_table_t target_table = NULL;
    target_table = v2m_table_list_find_table(*v2m_table_list_ptr, pid, NULL);
    if (NULL == target_table) {
        // try to create v2m table of pid
        dbprint("No v2m table of pid, try to create new table.\n");
        status_t ret_create;
        ret_create = create_v2m_table(vmi, pid, v2m_table_list_ptr,
            &target_table, shm_snapshot_fd);
        if (VMI_FAILURE == ret_create) {
            errprint("fail to create_v2m_table(), invalid pid?\n");
            goto fail_return;
        }
    }

    // search for a chunk by vaddr from the v2m table
    v2m_chunk_t target_chunk;
    target_chunk = v2m_table_find_chunk(target_table, vaddr);
    if (NULL == target_chunk) {
        dbprint("rb_tree_find_rb_node() not found\n");
        if (NULL != maddr_ptr) {
            *maddr_ptr = NULL;
        }
        *mem_size_ptr = 0;
        return VMI_FAILURE;
    }

    // specify return values
    addr_t vaddr_begin_offset;
    vaddr_begin_offset = vaddr - target_chunk->vaddr_begin;
    if (NULL != maddr_ptr) {
        *maddr_ptr = target_chunk->medial_mapping_addr + vaddr_begin_offset;
    }
    *mem_size_ptr = target_chunk->vaddr_end - vaddr + 1;

    return VMI_SUCCESS;

fail_return:
    if (NULL != maddr_ptr)
        *maddr_ptr = NULL;
    if (NULL != mem_size_ptr)
        *mem_size_ptr = 0;
    return VMI_FAILURE;
}

/**
 * Destroy v2m tables and mappings.
 *  1. munmap many m2p mappings in a v2m;
 *  2. delete v2m table.
 * @param[out] v2m_tables the renewed v2m tables, which would be NULL
 */
status_t
destroy_v2m_table_list(
    v2m_table_t * v2m_tables_ptr)
{
    v2m_table_t tail = *v2m_tables_ptr;
    if (NULL != tail) {
        do {
            v2m_table_t tmp = tail->next;

            if (VMI_SUCCESS
                != m2p_chunk_list_munmap(tail->v2m_chunks)) {
                errprint("fail to munmap_m2p_chunks()\n");
                return VMI_FAILURE;
            }

            tail->v2m_chunks = NULL;

            if (VMI_SUCCESS != v2m_table_list_remove_table(tail, v2m_tables_ptr)) {
                errprint("fail to delete_v2m_table()\n");
                return VMI_FAILURE;
            }
            tail = tmp;
        } while (NULL != tail);
        *v2m_tables_ptr = NULL;
    }
    return VMI_SUCCESS;
}

#endif
