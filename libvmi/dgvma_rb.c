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

static rb_key_t
rb_key_create(
    addr_t start_addr,
    addr_t end_addr)
{
    rb_key_t new_key;
    new_key.start_addr = start_addr;
    new_key.end_addr = end_addr;
    return new_key;
}

/**
* Test if a src key is contained in a dst key.
*
* @param[in] src_key
* @param[in] dst_key
* @return 1 (yes) or 0 (no)
*/
static int
rb_key_in(
    rb_key_t src_key,
    rb_key_t dst_key)
{
    return src_key.start_addr >= dst_key.start_addr && src_key.end_addr <= dst_key.end_addr;
}

static int
rb_key_less(
    rb_key_t src_key,
    rb_key_t dst_key)
{
    return src_key.start_addr < dst_key.end_addr;
}

static v2m_rb_node_t *
rb_node_create(
    addr_t start_addr,
    addr_t end_addr,
    v2m_rb_node_t * leaf)
{
    v2m_rb_node_t * new_node;
    new_node = malloc(sizeof(v2m_rb_node_t));
    bzero(new_node, sizeof(v2m_rb_node_t));
    new_node->color = red;
    new_node->key = rb_key_create(start_addr, end_addr);
    new_node->left = leaf;
    new_node->right = leaf;

    return new_node;
}

static v2m_rb_node_t *
rb_node_create_leaf()
{
    v2m_rb_node_t * new_node;
    new_node = malloc(sizeof(v2m_rb_node_t));
    bzero(new_node, sizeof(v2m_rb_node_t));
    new_node->color = black;
    return new_node;
}

// munmap, free
static void
rb_node_destroy(
    v2m_rb_node_t *node)
{
    if (NULL != node->media_mapping_addr)
    {
        size_t mmap_size;
        mmap_size = node->key.end_addr - node->key.start_addr + 1;
        munmap(node->media_mapping_addr, mmap_size);
    }
    free(node);
}

// in order traversal
static void
rb_node_list_traverse(
    v2m_rb_node_t * root_node_in_tree,
    void (* func)(v2m_rb_node_t *),
    v2m_rb_node_t * leaf)
{
    if (leaf == root_node_in_tree)
        return;
    rb_node_list_traverse(root_node_in_tree->left, func, leaf);
    (*func)(root_node_in_tree);
    rb_node_list_traverse(root_node_in_tree->right, func, leaf);
}

static v2m_rb_tree_t *
rb_tree_init(
    pid_t pid)
{
    v2m_rb_tree_t * tree = malloc(sizeof(v2m_rb_tree_t));
    v2m_rb_node_t * leaf = rb_node_create_leaf();
    tree->pid = pid;
    tree->root_node = leaf;
    tree->next = NULL;
    tree->leaf = leaf;
    return tree;
}

/*
static v2m_rb_tree_t *
rb_tree_create(
    v2m_rb_node_t * root_rb_node,
    pid_t pid)
{
    v2m_rb_tree_t * tree = malloc(sizeof(v2m_rb_tree_t));
    tree->pid = pid;
    tree->root_node = root_rb_node;
    tree->next = NULL;
    return tree;
}
*/

static void
rb_tree_destroy(
    v2m_rb_tree_t * tree)
{
    rb_node_list_traverse(tree->root_node, &rb_node_destroy, tree->leaf);
    free(tree->leaf);
    free(tree);
}

/**
* Rotate a red black tree.
*
* @param[out] root_node_ptr of a tree
* @param[in] op_node the root node
*/
static void
rb_tree_left_rotate(
    v2m_rb_tree_t * rb_tree,
    v2m_rb_node_t * op_node)
{
    v2m_rb_node_t ** root_node_ptr = &(rb_tree->root_node);
    v2m_rb_node_t * x = op_node;

    v2m_rb_node_t * y = x->right;
    x->right = y->left;
    if (rb_tree->leaf != y->left) {
        y->left->p = x;
    }
    y->p = x->p;
    // op_node is a root node.
    if (rb_tree->leaf ==  x->p) {
        // let y be the root node.
        *root_node_ptr = y;
    }
    else if (x == x->p->left) {
        // op_node is the left node of its parent.
        //  let y be the left node.
        x->p->left = y;
    }
    else {
        // op_node is the right node of its parent.
        // let y be the right node.
        x->p->right = y;
    }
    y->left = x;
    x->p = y;
}

/**
* Rotate a red black tree.
*
* @param[out] root_node_ptr of a tree
* @param[in] op_node the root node
*/
static void
rb_tree_right_rotate(
    v2m_rb_tree_t * rb_tree,
    v2m_rb_node_t * op_node)
{
    v2m_rb_node_t ** root_node_ptr = &(rb_tree->root_node);
    v2m_rb_node_t * y = op_node;

    v2m_rb_node_t * x = y->left;
    y->left = x->right;

    if (rb_tree->leaf != x->right) {
        x->right->p = y;
    }
    x->p = y->p;

    // op_node is a root node.
    if (rb_tree->leaf == y->p) {
        // let x be the root node.
        *root_node_ptr = x;
    }
    else if (y == y->p->left) {
        // op_node is the left node of its parent.
        //  let x be the left node.
        y->p->left = x;
    }
    else {
        // op_node is the right node of its parent.
        // let y be the right node.
        y->p->right = x;
    }
    x->right = y;
    y->p = x;
}

/**
* Insert fixing a red black tree.
*
* @param[out] root_node of a tree
*/
static void
rb_tree_insert_fixup(
    v2m_rb_tree_t * rb_tree,
    v2m_rb_node_t *new_node)
{
    v2m_rb_node_t ** root_node_ptr = &(rb_tree->root_node);
    v2m_rb_node_t * z = new_node;
    v2m_rb_node_t * y = NULL;
    while (red == z->p->color) {
        // z's p is a left child
        if (z->p == z->p->p->left) {
            y = z->p->p->right;
            // Case 1
            if (red == y->color) {
                z->p->color = black;
                y->color = black;
                z->p->p->color = red;
                z = z->p->p;
            }
            // Case 2
            else if (z == z->p->right) {
                z = z->p;
                rb_tree_left_rotate(rb_tree, z);

                // Case 3
                z->p->color = black;
                z->p->p->color = red;
                rb_tree_right_rotate(rb_tree, z->p->p);
            }
            else {
                // z == z->p->left
                // Case 3
                z->p->color = black;
                z->p->p->color = red;
                rb_tree_right_rotate(rb_tree, z->p->p);
            }
        }
        else {
            // z's p is a right child
            y = z->p->p->left;
            // Case 1: uncle is red, just change colors.
            if (red == y->color) {
                z->p->color = black;
                y->color = black;
                z->p->p->color = red;
                z = z->p->p;
            }
            // Case 2, z is a left child
            else if (z == z->p->left) {
                z = z->p;
                rb_tree_right_rotate(rb_tree, z);

                // Case 3
                z->p->color = black;
                z->p->p->color = red;
                rb_tree_left_rotate(rb_tree, z->p->p);
            }
            else {
                // z = z->p->right, z is a right child
                // Case 3
                z->p->color = black;
                z->p->p->color = red;
                rb_tree_left_rotate(rb_tree, z->p->p);
            }
        }
    }
    (*root_node_ptr)->color = black;
}

/**
* Insert a node to a red black tree. If the root_node is NULL, init the root node.
*
* @param[out] root_node_ptr of a tree
* @param[in] new_node allocated by malloc()
*/
static void
rb_tree_insert_rb_node(
    v2m_rb_tree_t * rb_tree,
    v2m_rb_node_t * new_node)
{
    v2m_rb_node_t ** root_node_ptr = &(rb_tree->root_node);
    v2m_rb_node_t * z = new_node;
    v2m_rb_node_t * y = rb_tree->leaf;
    v2m_rb_node_t * x = *root_node_ptr;
    while (rb_tree->leaf != x) {
        y = x;
        if (rb_key_less(z->key, x->key)) {
            x = x->left;
        }
        else {
            x = x->right;
        }
    }
    z->p = y;
    if (rb_tree->leaf == y) {
        *root_node_ptr = z;
    }
    else if (rb_key_less(z->key, y->key)) {
        y->left = z;
    }
    else {
        y->right = z;
    }
    z->left = rb_tree->leaf;
    z->right = rb_tree->leaf;
    z->color = red;
    rb_tree_insert_fixup(rb_tree, new_node);
}

/**
* Search a red black tree.
*
* @param[in] rb_tree not NULL
* @param[in] key
* @return the node or NULL
*/
static v2m_rb_node_t *
rb_tree_find_rb_node(
    v2m_rb_tree_t * rb_tree,
    rb_key_t key)
{
    v2m_rb_node_t * root_node = rb_tree->root_node;
    while (rb_tree->leaf != root_node && !rb_key_in(key, root_node->key)) {
        if (rb_key_less(key, root_node->key)) {
            root_node = root_node->left;
        }
        else {
            root_node = root_node->right;
        }
    }
    if (rb_key_in(key, root_node->key))
        return root_node;
    else
        return rb_tree->leaf;
}

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
static void
rb_tree_insert_v2p_pairs(
    v2m_rb_tree_t * rb_tree,
    v2m_rb_node_t ** current_rb_node_ptr,
    m2p_mapping_clue_chunk_t *m2p_chunk_list_ptr,
    m2p_mapping_clue_chunk_t *m2p_chunk_head_ptr,
    addr_t start_vaddr,
    addr_t end_vaddr,
    addr_t start_paddr,
    addr_t end_paddr)
{
    v2m_rb_node_t ** root_rb_node_ptr = &(rb_tree->root_node);
#ifdef RB_PRINT_M2P_BLOCK
    // v2p block
    printf("RB: v2pva: 0x%lx ~ 0x%lx, pa: 0x%lx ~ 0x%lx, size: %ld KB\n",
        start_vaddr, end_vaddr,start_paddr,  end_paddr, (end_paddr +1 - start_paddr)>>10);
#endif
    // the first v2m rb node
    if (rb_tree->leaf == *root_rb_node_ptr) {
        v2m_rb_node_t * new_node = rb_node_create(start_vaddr, end_vaddr, rb_tree->leaf);
        rb_tree_insert_rb_node(rb_tree, new_node);
        *current_rb_node_ptr = new_node;
/*
        *root_rb_node_ptr = rb_node_create(start_vaddr, end_vaddr, leaf);
        (*root_rb_node_ptr)->color = black;
        *current_rb_node_ptr = *root_rb_node_ptr;*/
        *m2p_chunk_list_ptr = (*current_rb_node_ptr)->m2p_chunks;
        *m2p_chunk_head_ptr = (*current_rb_node_ptr)->m2p_chunks;

        // the first m2p chunk
        m2p_chunk_list_add_v2p_pairs(m2p_chunk_list_ptr, m2p_chunk_head_ptr, start_vaddr,
            end_vaddr, start_paddr, end_paddr);
        (*current_rb_node_ptr)->m2p_chunks = *m2p_chunk_list_ptr;
    } else {
        if (start_vaddr == (*current_rb_node_ptr)->key.end_addr + 1) {
            // continuous vaddr
            //  1. insert p2m chunk.
            m2p_chunk_list_add_v2p_pairs(m2p_chunk_list_ptr,
                m2p_chunk_head_ptr, start_vaddr, end_vaddr,
                start_paddr, end_paddr);
            //  2. expand v2m chunk
            (*current_rb_node_ptr)->key.end_addr = end_vaddr;
        } else {
#ifdef RB_PRINT_V2M_BLOCK
            // v2m block
            printf("RB: v2mva: 0x%lx ~ 0x%lx, size: %ld KB\n",
                (*current_rb_node_ptr)->key.start_addr, (*current_rb_node_ptr)->key.end_addr,
                ((*current_rb_node_ptr)->key.end_addr + 1 - (*current_rb_node_ptr)->key.start_addr)>>10);
#endif

            // incontinuous vaddr, so new v2m chunk
            v2m_rb_node_t * new_node = rb_node_create(start_vaddr, end_vaddr, rb_tree->leaf);
            rb_tree_insert_rb_node(rb_tree, new_node);
            *current_rb_node_ptr = new_node;

            *m2p_chunk_list_ptr = (*current_rb_node_ptr)->m2p_chunks;
            *m2p_chunk_head_ptr = (*current_rb_node_ptr)->m2p_chunks;

            // the first p2m chunk
            m2p_chunk_list_add_v2p_pairs(m2p_chunk_list_ptr, m2p_chunk_head_ptr, start_vaddr,
                end_vaddr, start_paddr, end_paddr);
            (*current_rb_node_ptr)->m2p_chunks = *m2p_chunk_list_ptr;
        }
    }
}

static void
rb_tree_fill_nodes_by_walking_pagetable_nopae(
    vmi_instance_t vmi,
    addr_t dtb,
    v2m_rb_tree_t * rb_tree)
{
    v2m_rb_node_t * root_rb_node  = rb_tree->root_node;
    v2m_rb_node_t * current_rb_node = NULL;
    m2p_mapping_clue_chunk_t rb_m2p_chunk_list = NULL;
    m2p_mapping_clue_chunk_t rb_m2p_chunk_head = NULL;

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
                    rb_tree_insert_v2p_pairs(rb_tree, &current_rb_node,
                        &rb_m2p_chunk_list, &rb_m2p_chunk_head,
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
                            rb_tree_insert_v2p_pairs(rb_tree, &current_rb_node,
                                  &rb_m2p_chunk_list, &rb_m2p_chunk_head,
                                  start_vaddr, end_vaddr, start_paddr, end_paddr);
                        }
                    }
                }
            }
        }
    }
    rb_tree->root_node = root_rb_node;
}

static void
rb_tree_fill_nodes_by_walking_pagetable_pae(
    vmi_instance_t vmi,
    addr_t dtb,
    v2m_rb_tree_t * rb_tree)
{
    v2m_rb_node_t * root_rb_node  = rb_tree->root_node;
    v2m_rb_node_t * current_rb_node = NULL;
    m2p_mapping_clue_chunk_t rb_m2p_chunk_list = NULL;
    m2p_mapping_clue_chunk_t rb_m2p_chunk_head = NULL;

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
                            rb_tree_insert_v2p_pairs(rb_tree, &current_rb_node,
                                &rb_m2p_chunk_list, &rb_m2p_chunk_head,
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
                                    rb_tree_insert_v2p_pairs(rb_tree, &current_rb_node,
                                        &rb_m2p_chunk_list, &rb_m2p_chunk_head,
                                        start_vaddr, end_vaddr, start_paddr, end_paddr);
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    rb_tree->root_node = root_rb_node;
}

static void
rb_tree_fill_nodes_by_walking_pagetable_ia32e(
    vmi_instance_t vmi,
    addr_t dtb,
    v2m_rb_tree_t * rb_tree)
{
    //v2m_rb_node_t * root_rb_node  = rb_tree->root_node;
    v2m_rb_node_t * current_rb_node = NULL;
    m2p_mapping_clue_chunk_t rb_m2p_chunk_list = NULL;
    m2p_mapping_clue_chunk_t rb_m2p_chunk_head = NULL;

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
                            rb_tree_insert_v2p_pairs(rb_tree, &current_rb_node,
                                &rb_m2p_chunk_list, &rb_m2p_chunk_head,
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
                                        rb_tree_insert_v2p_pairs(rb_tree, &current_rb_node,
                                            &rb_m2p_chunk_list, &rb_m2p_chunk_head,
                                            start_vaddr, end_vaddr, start_paddr, end_paddr);
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
                                                rb_tree_insert_v2p_pairs(
                                                    rb_tree, &current_rb_node,
                                                    &rb_m2p_chunk_list, &rb_m2p_chunk_head,
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
    //rb_tree->root_node = root_rb_node;
}

static void
tree_list_add_rb_tree(
    v2m_rb_tree_t * rb_tree,
    v2m_rb_tree_t ** tree_list_ptr)
{
    // the first tree of the list
    if (NULL == *tree_list_ptr) {
        *tree_list_ptr = rb_tree;
        return;
    }

    // append
    v2m_rb_tree_t * tree = *tree_list_ptr;
    while (NULL != tree->next) {
        tree = tree->next;
    }
    tree->next = rb_tree;
    return;
}

/**
 * The tree still exists after this function.
 * tree_prev must be serious, or it is unexpectable.
 */
static void
tree_list_remove_rb_tree(
    v2m_rb_tree_t * tree,
    v2m_rb_tree_t * tree_prev,
    v2m_rb_tree_t ** tree_list_ptr)
{
    if (NULL == tree_prev) {
        *tree_list_ptr = tree->next;
    }
    else {
        tree_prev->next = tree->next;
    }
}
// If the target is the first tree of the list, prev is NULL
/**
 * @param[output] target_prev can be NULL
 */
static v2m_rb_tree_t *
tree_list_find_rb_tree(
    v2m_rb_tree_t *tree_list,
    pid_t pid,
    v2m_rb_tree_t ** target_prev)
{
    v2m_rb_tree_t * tree = tree_list;
    v2m_rb_tree_t * hit = NULL;
    v2m_rb_tree_t * prev = NULL;
    while (NULL != tree) {
        if (pid == tree->pid) {
            hit = tree;
            break;
        }
        prev = tree;
        tree = tree->next;
    }

    // found
    if (NULL != hit) {
        if (NULL != target_prev) {
            *target_prev = prev;
        }
        return hit;
    }
    else {
        dbprint("find_rb_tree_by_pid_from_list() failed because no pid "
                        "tree\n");
        return NULL;
    }
}

// don't require func() to retain the tree
static void
tree_list_traverse(
    v2m_rb_tree_t * tree_list,
    void (*func)(v2m_rb_tree_t *))
{
    v2m_rb_tree_t * next = NULL;
    while (NULL != tree_list) {
        next = tree_list->next;
        (*func)(tree_list);
        tree_list = next;
    }
}

/**
 * Create a v2m red black tree of a given pid.
 * This function will walkthrough the page table of the given pid, establish
 *  the mappings of v2m and m2p, and then insert the new v2m table to a
 *  collection.
 * @param[in] vmi LibVMI instance, use to read memory page, etc.
 * @param[in] pid Pid of the virtual address space (0 for kernel)
 * @param[out] v2m_tables_ptr the renewed v2m tables
 */
static status_t
create_v2m_rb_tree(
    vmi_instance_t vmi,
    pid_t pid,
    v2m_rb_tree_t ** v2m_rb_tree_list_ptr,
    v2m_rb_tree_t ** new_tree)
{
    // 1. pid -> dtb
    addr_t dtb;
    status_t ret_p2d;
    ret_p2d = dgvma_pid_to_dtb(vmi, pid, &dtb);
    if (VMI_FAILURE == ret_p2d)
        return VMI_FAILURE;

    // 2. create an rb tree without rb nodes
    v2m_rb_tree_t * rb_tree = NULL;
    rb_tree = rb_tree_init(pid);
    //rb_tree = rb_tree_create(NULL, pid);

    // 3. fill rb nodes in tree
#ifdef RB_WALK_PT_MEASUREMENT
    struct timeval ktv_start;
    struct timeval ktv_end;
    gettimeofday(&ktv_start, 0);
#endif
    switch (vmi->page_mode) {
    case VMI_PM_LEGACY:
        rb_tree_fill_nodes_by_walking_pagetable_nopae(vmi, dtb, rb_tree);
        break;
    case VMI_PM_PAE:
        rb_tree_fill_nodes_by_walking_pagetable_pae(vmi, dtb, rb_tree);
        break;
    case VMI_PM_IA32E:
        rb_tree_fill_nodes_by_walking_pagetable_ia32e(vmi, dtb, rb_tree);
        break;
    default:
        errprint(
            "Invalid paging mode during walkthrough_shm_snapshot_pagetable\n");
        return VMI_FAILURE;
        break;
    }
#ifdef RB_WALK_PT_MEASUREMENT
    gettimeofday(&ktv_end, 0);
    print_measurement("walk page table rb", ktv_start, ktv_end);
#endif

    // 4. add rb tree to tree list
    tree_list_add_rb_tree(rb_tree, v2m_rb_tree_list_ptr);

    *new_tree = rb_tree;
    return VMI_SUCCESS;
}

/*
// @param[output] tree_list_ptr may change if destroy the first tree in the list
status_t
destroy_v2m_rb_tree(
    pid_t pid,
    v2m_rb_tree_t ** tree_list_ptr)
{
    // is a empty list, exit
    if (NULL == *tree_list_ptr) {
        errprint("early bail on destroy_v2m_rb_tree() because *tree_list_ptr "
                        "is NULL\n");
        return VMI_FAILURE;
    }

    // search for a tree of a pid from tree list
    v2m_rb_tree_t * target = NULL;
    v2m_rb_tree_t * target_prev = NULL;
    target = tree_list_find_rb_tree(*tree_list_ptr, pid, &target_prev);
    if (NULL == target) {
        errprint("early bail on destroy_v2m_rb_tree() because no pid tree\n");
        return VMI_FAILURE;
    }

    // remove it from the tree list
    tree_list_remove_rb_tree(target, target_prev, tree_list_ptr);

    // destroy
    rb_tree_destroy(target);

    return VMI_SUCCESS;
}
*/

/**
 * Search v2m red black tree for medial address corresponding with given vaddr.
 *  This function may mmap() m2p mappings for first time maddr addressing.
 *
 *  Automatically create v2m rb tree for new pid.
 * @param[in] vmi LibVMI instance, use to read memory page, etc.
 * @param[in] pid Pid of the virtual address space (0 for kernel)
 * @param[in] rb_tree v2m red black treePid of the virtual address space (0 for kernel)
 * @param[out] v2m_tables_ptr the renewed v2m tables
 * @param[in] vmi LibVMI instance, use to read memory page, etc.
 * @param[in] pid Pid of the virtual address space (0 for kernel)
 * @param[out] v2m_tables_ptr the renewed v2m tables
 * @param[out] mem_size_ptr to the maximum length of the memory area
 * @param[in] shm_snapshot_fd
 */
status_t
search_v2m_rb_tree(
    vmi_instance_t vmi,
    pid_t pid,
    v2m_rb_tree_t ** rb_tree_list_ptr,
    addr_t vaddr,
    void ** maddr_ptr,
    size_t * mem_size_ptr,
    int shm_snapshot_fd)
{
    // Get a v2m rb tree by pid from tree list
    //   try to find v2m rb tree of pid
    v2m_rb_tree_t * target_tree = NULL;
    target_tree = tree_list_find_rb_tree(*rb_tree_list_ptr, pid, NULL);
    if (NULL == target_tree) {
        // try to create v2m rb tree of pid
        dbprint("No v2m rb tree of pid, try to create new tree.\n");
        status_t ret_create;
        ret_create = create_v2m_rb_tree(vmi, pid, rb_tree_list_ptr,
            &target_tree);
        if (VMI_FAILURE == ret_create) {
            errprint("fail to create_v2m_rb_tree(), invalid pid?\n");
            goto fail_return;
        }
    }

    // search for a rb node by key from the tree
    rb_key_t key;
    key.start_addr = vaddr;
    key.end_addr = vaddr; // so get partial
    v2m_rb_node_t * target_node;
    target_node = rb_tree_find_rb_node(target_tree, key);
    if (target_tree->leaf == target_node) {
        dbprint("rb_tree_find_rb_node() not found\n");
        goto fail_return;
    }

    // hit a unmapped node, map it
    if (NULL == target_node->media_mapping_addr)
    {
#ifdef RB_PROBE_ADDR_MEASUREMENT
        struct timeval ktv_start;
        struct timeval ktv_end;
        gettimeofday(&ktv_start, 0);
#endif
        // probe v2m medial address
        rb_key_t key = target_node->key;
        size_t v2m_size = key.end_addr - key.start_addr + 1;
        void * maddr_indicator;
        status_t ret_probe = probe_mmap_base_addr(v2m_size, &maddr_indicator);
        if (VMI_FAILURE == ret_probe) {
            errprint("fail to probe medial space for va: %016lx - %016lx, "
                "size: %ldKB\n", key.start_addr, key.end_addr, v2m_size>>10);
            goto fail_return;
        }
#ifdef RB_PROBE_ADDR_MEASUREMENT
        gettimeofday(&ktv_end, 0);
        printf("mmap va:  %016lx - %016lx, size: %ldKB\n", key.start_addr,
            key.end_addr, v2m_size>>10);
        print_measurement("probe addr space", ktv_start, ktv_end);
#endif

#ifdef RB_MMAP_M2P_MEASUREMENT
        gettimeofday(&ktv_start, 0);
#endif
        // mmap m2p
        status_t ret_mmap_m2p;
        ret_mmap_m2p = m2p_chunk_list_mmap(maddr_indicator,
            target_node->m2p_chunks, shm_snapshot_fd);
        if (VMI_FAILURE == ret_mmap_m2p) {
            errprint("fail to mmap space for va: %016lx - %016lx, "
                "size: %ldKB\n", key.start_addr, key.end_addr, v2m_size>>10);
            goto fail_return;
        }
        target_node->media_mapping_addr = maddr_indicator;
#ifdef RB_MMAP_M2P_MEASUREMENT
        gettimeofday(&ktv_end, 0);
        print_measurement(" mmap addr space", ktv_start, ktv_end);
#endif

#ifdef RB_DEL_M2P_MEASUREMENT
        gettimeofday(&ktv_start, 0);
#endif
        // delete m2p chunks
        status_t ret_del_m2p;
        ret_del_m2p = m2p_chunk_list_delete(&(target_node->m2p_chunks));
        if (VMI_FAILURE == ret_del_m2p) {
            goto fail_return;
        }
#ifdef RB_DEL_M2P_MEASUREMENT
        gettimeofday(&ktv_end, 0);
        print_measurement("delete m2p chunks", ktv_start, ktv_end);
#endif
    }

    // specify return values
    addr_t vaddr_begin_offset;
    vaddr_begin_offset = vaddr - target_node->key.start_addr;
    *maddr_ptr = target_node->media_mapping_addr + vaddr_begin_offset;
    *mem_size_ptr = target_node->key.end_addr - vaddr + 1;
    return VMI_SUCCESS;

fail_return:
    if (NULL != maddr_ptr)
        *maddr_ptr = NULL;
    if (NULL != mem_size_ptr)
        *mem_size_ptr = 0;
    return VMI_FAILURE;
}

// destroy all trees
status_t
destroy_v2m_rb_tree_list(
    v2m_rb_tree_t ** tree_list_ptr)
{
    tree_list_traverse(*tree_list_ptr, &rb_tree_destroy);
    *tree_list_ptr = NULL;
    return VMI_SUCCESS;
}

#endif
