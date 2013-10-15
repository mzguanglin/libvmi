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

#include "libvmi.h"
#include "private.h"
#include "driver/kvm.h"
#include "driver/interface.h"
#include "driver/memory_cache.h"

#if ENABLE_KVM == 1
#define _GNU_SOURCE
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/un.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>
#include <glib.h>
#include <math.h>
#include <glib/gstdio.h>
#include <libvirt/libvirt.h>
#include <libvirt/virterror.h>

// request struct matches a definition in qemu source code
struct request {
    uint8_t type;   // 0 quit, 1 read, 2 write, ... rest reserved
    uint64_t address;   // address to read from OR write to
    uint64_t length;    // number of bytes to read OR write
};

//----------------------------------------------------------------------------
// Helper functions

//
// QMP Command Interactions
static char *
exec_qmp_cmd(
    kvm_instance_t *kvm,
    char *query)
{
    FILE *p;
    char *output = safe_malloc(20000);
    size_t length = 0;

    char *name = (char *) virDomainGetName(kvm->dom);
    int cmd_length = strlen(name) + strlen(query) + 29;
    char *cmd = safe_malloc(cmd_length);

    snprintf(cmd, cmd_length, "virsh qemu-monitor-command %s %s", name,
             query);
    dbprint("--qmp: %s\n", cmd);

    p = popen(cmd, "r");
    if (NULL == p) {
        dbprint("--failed to run QMP command\n");
        free(cmd);
        return NULL;
    }

    length = fread(output, 1, 20000, p);
    pclose(p);
    free(cmd);

    if (length == 0) {
        free(output);
        return NULL;
    }
    else {
        return output;
    }
}

static char *
exec_info_registers(
    kvm_instance_t *kvm)
{
    char *query =
        "'{\"execute\": \"human-monitor-command\", \"arguments\": {\"command-line\": \"info registers\"}}'";
    return exec_qmp_cmd(kvm, query);
}

static char *
exec_memory_access(
    kvm_instance_t *kvm)
{
    char *tmpfile = tempnam("/tmp", "vmi");
    char *query = (char *) safe_malloc(256);

    sprintf(query,
            "'{\"execute\": \"pmemaccess\", \"arguments\": {\"path\": \"%s\"}}'",
            tmpfile);
    kvm->ds_path = strdup(tmpfile);
    free(tmpfile);

    char *output = exec_qmp_cmd(kvm, query);

    free(query);
    return output;
}

static char *
exec_xp(
    kvm_instance_t *kvm,
    int numwords,
    addr_t paddr)
{
    char *query = (char *) safe_malloc(256);

    sprintf(query,
            "'{\"execute\": \"human-monitor-command\", \"arguments\": {\"command-line\": \"xp /%dwx 0x%x\"}}'",
            numwords, paddr);

    char *output = exec_qmp_cmd(kvm, query);

    free(query);
    return output;
}

static reg_t
parse_reg_value(
    char *regname,
    char *ir_output)
{
    if (NULL == ir_output || NULL == regname) {
        return 0;
    }

    char *ptr = strcasestr(ir_output, regname);

    if (NULL != ptr) {
        ptr += strlen(regname) + 1;
        return (reg_t) strtoll(ptr, (char **) NULL, 16);
    }
    else {
        return 0;
    }
}

status_t
exec_memory_access_success(
    char *status)
{
    if (NULL == status) {
        return VMI_FAILURE;
    }

    char *ptr = strcasestr(status, "CommandNotFound");

    if (NULL == ptr) {
        return VMI_SUCCESS;
    }
    else {
        return VMI_FAILURE;
    }
}

/**
 * note:
 * 1. "kvm_patch" here means the feature in pmemaccess patch (kvm-physmem-access_x.x.x.patch);
 * 2. In fact, the shm-snapshot patch (kvm-physmem-access-physmem-snapshot_1.6.0.patch)
 *      includes pmemaccess patch.
 */
inline status_t
test_using_kvm_patch(
	    kvm_instance_t *kvm)
{
    if (kvm->socket_fd) {
    	return VMI_SUCCESS;
    } else {
    	return VMI_FAILURE;
    }
}

//
// Domain socket interactions (for memory access from KVM-QEMU)
static status_t
init_domain_socket(
    kvm_instance_t *kvm)
{
    struct sockaddr_un address;
    int socket_fd;
    size_t address_length;

    socket_fd = socket(PF_UNIX, SOCK_STREAM, 0);
    if (socket_fd < 0) {
        dbprint("--socket() failed\n");
        return VMI_FAILURE;
    }

    address.sun_family = AF_UNIX;
    address_length =
        sizeof(address.sun_family) + sprintf(address.sun_path, "%s",
                                             kvm->ds_path);

    if (connect(socket_fd, (struct sockaddr *) &address, address_length)
        != 0) {
        dbprint("--connect() failed to %s\n", kvm->ds_path);
        return VMI_FAILURE;
    }

    kvm->socket_fd = socket_fd;
    return VMI_SUCCESS;
}

static void
destroy_domain_socket(
    kvm_instance_t *kvm)
{
    if (VMI_SUCCESS == test_using_kvm_patch(kvm)) {
        struct request req;

        req.type = 0;   // quit
        req.address = 0;
        req.length = 0;
        write(kvm->socket_fd, &req, sizeof(struct request));
    }
}

//----------------------------------------------------------------------------
// KVM-Specific Interface Functions (no direction mapping to driver_*)

static kvm_instance_t *
kvm_get_instance(
    vmi_instance_t vmi)
{
    return ((kvm_instance_t *) vmi->driver);
}

#if ENABLE_SHM_SNAPSHOT == 1
status_t
test_using_shm_snapshot(
		kvm_instance_t *kvm)
{
	if (NULL != kvm->shm_snapshot_path && 0 != kvm->shm_snapshot_fd
        && NULL != kvm->shm_snapshot_map && NULL != kvm->shm_snapshot_cpu_regs) {
        dbprint("is using shm-snapshot\n");
        return VMI_SUCCESS;
	} else {
        dbprint("is not using shm-snapshot\n");
        return VMI_FAILURE;
	}
}

/*
 * set kvm->shm_snapshot_path;
 */
static char *
exec_shm_snapshot(
	    vmi_instance_t vmi)
{
	kvm_instance_t *kvm = kvm_get_instance(vmi);

	// get a random unique path e.g. /dev/shm/[domain name]xxxxxx.
    char *unique_shm_path = tempnam("/dev/shm", (char *) virDomainGetName(kvm->dom));

    if (NULL != unique_shm_path) {
        char *shm_filename = basename(unique_shm_path);
        char *query_template = "'{\"execute\": \"snapshot-create\", \"arguments\": {"
            " \"filename\": \"/%s\"}}'";
        char *query = (char *) safe_malloc(strlen(query_template) - strlen("%s") + NAME_MAX + 1);
        sprintf(query, query_template, shm_filename);
        kvm->shm_snapshot_path = strdup(shm_filename);
        free(unique_shm_path);
        char *output = exec_qmp_cmd(kvm, query);
        free(query);
        return output;
    }
    else {
    	return NULL;
    }
}

static status_t
exec_shm_snapshot_success(
		char* status)
{
	// successful status should like: {"return":2684354560,"id":"libvirt-812"}
	if (NULL == status) {
        return VMI_FAILURE;
    }
    char *ptr = strcasestr(status, "CommandNotFound");
    if (NULL == ptr) {
    	uint64_t shm_snapshot_size = strtoul(status + strlen("{\"return\":"), NULL, 0);
    	if (shm_snapshot_size > 0) {
    		//qmp status e.g. : {"return":2684354560,"id":"libvirt-812"}
    		dbprint("--kvm: using shm-snapshot support\n");
    		return VMI_SUCCESS;
    	} else {
    		//qmp status e.g. : {"return":0,"id":"libvirt-812"}
    		errprint ("--kvm: fail to shm-snapshot\n");
    		return VMI_FAILURE;
    	}
    }
    else {
    	//qmp status e.g. : CommandNotFound
		errprint("--kvm: didn't find shm-snapshot support\n");
        return VMI_FAILURE;
    }
}

/*
 * set kvm->shm_snapshot_fd
 * set kvm->shm_snapshot_map
 */
static status_t
link_mmap_shm_snapshot_dev(
    vmi_instance_t vmi)
{
    kvm_instance_t *kvm = kvm_get_instance(vmi);
    if ((kvm->shm_snapshot_fd = shm_open(kvm->shm_snapshot_path, O_RDONLY, NULL)) < 0) {
        errprint("fail in shm_open %s", kvm->shm_snapshot_path);
        return VMI_FAILURE;
    }
    ftruncate(kvm->shm_snapshot_fd, vmi->size);

    /* try memory mapped file I/O */
    int mmap_flags = (MAP_PRIVATE | MAP_NORESERVE | MAP_POPULATE);
#ifdef MMAP_HUGETLB // since kernel 2.6.32
    mmap_flags |= MMAP_HUGETLB;
#endif // MMAP_HUGETLB

    kvm->shm_snapshot_map = mmap(NULL,  // addr
        vmi->size,   // len
        PROT_READ,   // prot
        mmap_flags,  // flags
        kvm->shm_snapshot_fd,    // file descriptor
        (off_t) 0);  // offset
    if (MAP_FAILED == kvm->shm_snapshot_map) {
        perror("Failed to mmap shared memory snapshot dev");
        return VMI_FAILURE;
    }
    return VMI_SUCCESS;
}

/**
 * clear kvm->shm_snapshot_map
 * clear kvm->shm_snapshot_fd
 * clear kvm->shm_snapshot_path
 */
static status_t
munmap_unlink_shm_snapshot_dev(
		kvm_instance_t *kvm, uint64_t mem_size)
{
    if (kvm->shm_snapshot_map) {
        (void) munmap(kvm->shm_snapshot_map, mem_size);
        kvm->shm_snapshot_map = 0;
    }
    if (kvm->shm_snapshot_fd) {
    	shm_unlink(kvm->shm_snapshot_path);
    	free(kvm->shm_snapshot_path);
        kvm->shm_snapshot_path = NULL;
        kvm->shm_snapshot_fd = 0;
    }
    return VMI_SUCCESS;
}

/**
 * Throw v2p consecutive mapping range to this m2p chunk creator.
 * @param[out] m2p_chunk_list_ptr
 * @param[out] m2p_chunk_head_ptr
 * @param[in] start_vaddr
 * @param[in] end_vaddr
 * @param[in] start_paddr
 * @param[in] end_paddr
 */
void insert_v2p_page_pair_to_m2p_chunk_list(
    m2p_mapping_clue_chunk_t *m2p_chunk_list_ptr,
    m2p_mapping_clue_chunk_t *m2p_chunk_head_ptr,
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
void insert_v2p_page_pair_to_v2m_chunk_list(
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
        insert_v2p_page_pair_to_m2p_chunk_list(m2p_chunk_list_ptr, m2p_chunk_head_ptr, start_vaddr,
            end_vaddr, start_paddr, end_paddr);
        (*v2m_chunk_head_ptr)->m2p_chunks = *m2p_chunk_list_ptr;
    } else {
        if (start_vaddr == (*v2m_chunk_head_ptr)->vaddr_end + 1) {
            // continuous vaddr
            //  1. insert p2m chunk.
            insert_v2p_page_pair_to_m2p_chunk_list(m2p_chunk_list_ptr, m2p_chunk_head_ptr, start_vaddr,
                end_vaddr, start_paddr, end_paddr);
            //  2. expand v2m chunk
            (*v2m_chunk_head_ptr)->vaddr_end = end_vaddr;
        } else {
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
            insert_v2p_page_pair_to_m2p_chunk_list(m2p_chunk_list_ptr, m2p_chunk_head_ptr, start_vaddr,
                end_vaddr, start_paddr, end_paddr);
            (*v2m_chunk_head_ptr)->m2p_chunks = *m2p_chunk_list_ptr;
        }
    }
}

status_t
walkthrough_shm_snapshot_pagetable_nopae(
    vmi_instance_t vmi,
    addr_t dtb,
    v2m_chunk_t* v2m_chunk_list_ptr,
    v2m_chunk_t* v2m_chunk_head_ptr)
{
    v2m_chunk_t v2m_chunk_list = *v2m_chunk_list_ptr;
    v2m_chunk_t v2m_chunk_head = *v2m_chunk_head_ptr;
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
    *v2m_chunk_head_ptr = v2m_chunk_head;
    return VMI_SUCCESS;
}

status_t
walkthrough_shm_snapshot_pagetable_pae(
    vmi_instance_t vmi,
    addr_t dtb,
    v2m_chunk_t* v2m_chunk_list_ptr,
    v2m_chunk_t* v2m_chunk_head_ptr)
{
    v2m_chunk_t v2m_chunk_list = *v2m_chunk_list_ptr;
    v2m_chunk_t v2m_chunk_head = *v2m_chunk_head_ptr;
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
    *v2m_chunk_head_ptr = v2m_chunk_head;
    return VMI_SUCCESS;
}

status_t
walkthrough_shm_snapshot_pagetable_ia32e(
    vmi_instance_t vmi,
    addr_t dtb,
    v2m_chunk_t* v2m_chunk_list_ptr,
    v2m_chunk_t* v2m_chunk_head_ptr)
{
    v2m_chunk_t v2m_chunk_list = *v2m_chunk_list_ptr;
    v2m_chunk_t v2m_chunk_head = *v2m_chunk_head_ptr;
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
    *v2m_chunk_head_ptr = v2m_chunk_head;
    return VMI_SUCCESS;
}

/**
 * Walk through the page table to gather v2m chunks.
 * @param[in] vmi LibVMI instance
 * @param[in] dtb
 * @param[out] v2m_chunk_list_ptr
 * @param[out] v2m_chunk_head_ptr
 */
status_t
walkthrough_shm_snapshot_pagetable(
    vmi_instance_t vmi,
    addr_t dtb,
    v2m_chunk_t* v2m_chunk_list_ptr,
    v2m_chunk_t* v2m_chunk_head_ptr)
{
    if (vmi->page_mode == VMI_PM_LEGACY) {
        return walkthrough_shm_snapshot_pagetable_nopae(vmi, dtb,
            v2m_chunk_list_ptr, v2m_chunk_head_ptr);
    }
    else if (vmi->page_mode == VMI_PM_PAE) {
        return  walkthrough_shm_snapshot_pagetable_pae(vmi, dtb,
            v2m_chunk_list_ptr, v2m_chunk_head_ptr);
    }
    else if (vmi->page_mode == VMI_PM_IA32E) {
        return  walkthrough_shm_snapshot_pagetable_ia32e(vmi, dtb,
            v2m_chunk_list_ptr, v2m_chunk_head_ptr);
    }
    else {
        errprint(
            "Invalid paging mode during walkthrough_shm_snapshot_pagetable\n");
        return VMI_FAILURE;
    }
}

/**
 * As we must ensure consecutive v2m mappings which are usually constituted by
 *  many m2p chunks, we should probe a large enough medial address range (i.e.
 *  LibVMI virtual address) to place those m2p mappings together.
 * @param[in] vmi LibVMI instance
 * @param[in] v2m_chunk
 * @param[out] maddr_indicator_export
 */
status_t probe_v2m_medial_addr(
    vmi_instance_t vmi,
    v2m_chunk_t v2m_chunk,
    void** maddr_indicator_export)
{
    if (NULL != v2m_chunk) {
        dbprint("probe medial space for va: %016llx - %016llx, size: %dKB\n",
            v2m_chunk->vaddr_begin, v2m_chunk->vaddr_end,
            (v2m_chunk->vaddr_end - v2m_chunk->vaddr_begin+1)>>10);

        // find a large enough vaddr base
        size_t size = v2m_chunk->vaddr_end - v2m_chunk->vaddr_begin;
        void *map = mmap(NULL,  // addr
            (long long unsigned int)size,   // vaddr space
            PROT_READ,   // prot
            MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE,  // flags
            0,    // file descriptor
            0);  // offset
        if (MAP_FAILED != map) {
            *maddr_indicator_export = map;
            (void) munmap(map, size);
        } else {
            errprint("Failed to find large enough medial address space,"
                " size:"PRIu64" MB\n", size>>20);
            perror("");
            return VMI_FAILURE;
        }
    }
    return VMI_SUCCESS;
}

/**
 * mmap m2p indicated by a list of m2p mappping clue chunks and a medial address.
 * @param[in] vmi LibVMI instance
 * @param[in] medial_addr_indicator the start address
 * @param[in] m2p_chunk_list
 */
status_t mmap_m2p_chunks(
    vmi_instance_t vmi,
    void* medial_addr_indicator,
    m2p_mapping_clue_chunk_t m2p_chunk_list)
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
             kvm_get_instance(vmi)->shm_snapshot_fd,    // file descriptor
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
 * delete m2p chunks in a collection.
 * @param[in] vmi LibVMI instance
 * @param[in] medial_addr_indicator the start address
 * @param[out] m2p_chunk_list_ptr
 */
status_t delete_m2p_chunks(
    vmi_instance_t vmi,
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
 * Insert a v2m table to the collection
 * @param[in] vmi LibVMI instance
 * @param[in] entry v2m table
 */
status_t
insert_v2m_table(
    vmi_instance_t vmi,
    v2m_table_t entry)
{
    kvm_instance_t *kvm = kvm_get_instance(vmi);

    // the first v2m table
    if (kvm->shm_snapshot_v2m_tables == NULL) {
        kvm->shm_snapshot_v2m_tables = entry;
        return VMI_SUCCESS;
    }
    else {
        // append to the existed v2m table link list
        v2m_table_t head = kvm->shm_snapshot_v2m_tables;
        while (NULL != head->next) {
            head = head->next;
        }
        head->next = entry;
        return VMI_SUCCESS;
    }
}

/**
 * Setup a v2m table of a given pid and dtb.
 * @param[in] vmi LibVMI instance
 * @param[in] pid
 * @param[in] dtb correspond to the pid
 * @param[out] v2m_table_pt the generated v2m table
 */
status_t
setup_v2m_table(
    vmi_instance_t vmi,
    pid_t pid,
    addr_t dtb,
    v2m_table_t* v2m_table_pt)
{
    v2m_chunk_t v2m_chunk_list = NULL;
    v2m_chunk_t v2m_chunk_head = NULL;

    if (VMI_SUCCESS ==
        walkthrough_shm_snapshot_pagetable(vmi, dtb, &v2m_chunk_list, &v2m_chunk_head))
    {
        v2m_chunk_t v2m_chunk_tmp = v2m_chunk_list;
        while (NULL != v2m_chunk_tmp) {
            // probe v2m medial address
            void* maddr_indicator;
            if (VMI_SUCCESS != probe_v2m_medial_addr(vmi, v2m_chunk_tmp, &maddr_indicator)) {
                return VMI_FAILURE;
            }

            // mmap each m2p memory chunk
            if (VMI_SUCCESS !=
                mmap_m2p_chunks(vmi, maddr_indicator, v2m_chunk_tmp->m2p_chunks)) {
                return VMI_FAILURE;
            }

            // delete m2p chunks
            if (VMI_SUCCESS !=
                delete_m2p_chunks(vmi, &v2m_chunk_tmp->m2p_chunks)) {
                return VMI_FAILURE;
            }

            // assign valid maddr
            v2m_chunk_tmp->medial_mapping_addr = maddr_indicator;

            v2m_chunk_tmp = v2m_chunk_tmp->next;
        }

        v2m_table_t v2m_table_tmp = malloc(sizeof(v2m_table));
        v2m_table_tmp->pid = pid;
        v2m_table_tmp->v2m_chunks = v2m_chunk_list;
        v2m_table_tmp->next = NULL;

        *v2m_table_pt = v2m_table_tmp;
        return insert_v2m_table(vmi, v2m_table_tmp);
    }
    return VMI_FAILURE;
}

/**
 * Create a v2m table of a given pid.
 * This function will walkthrough the page table of the given pid, establish
 *  the mappings of v2m and m2p, and then insert the new v2m table to a
 *  collection.
 * @param[in] vmi LibVMI instance
 * @param[in] pid Pid of the virtual address space (0 for kernel)
 * @param[out] the generated v2m table.
 */
status_t
create_v2m_table(
    vmi_instance_t vmi,
    pid_t pid,
    v2m_table_t* v2m_table_pt)
{
    addr_t dtb = 0;
    if (VMI_SUCCESS == test_using_shm_snapshot(kvm_get_instance(vmi))) {
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
                dbprint("--early bail on TEVAT create because cr3 is zero\n");
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
                dbprint("--early bail on TEVAT create because dtb is zero\n");
                return VMI_FAILURE;
            }
        }
        return setup_v2m_table(vmi, pid, dtb, v2m_table_pt);
    }
    else {
        errprint("can't create TEVAT because shm-snapshot is not using.\n");
        return VMI_FAILURE;
    }
}

/**
 * Search the collection of v2m tables by a pid.
 * @param[in] vmi LibVMI instance
 * @param[in] pid Pid of the virtual address space (0 for kernel)
 */
v2m_table_t
get_v2m_table(
    vmi_instance_t vmi,
    pid_t pid)
{
    kvm_instance_t *kvm = kvm_get_instance(vmi);

    if (NULL != kvm->shm_snapshot_v2m_tables) {
        v2m_table_t tmp = kvm->shm_snapshot_v2m_tables;
        while (NULL != tmp) {
            if (pid == tmp->pid)
                return tmp;
            tmp = tmp->next;
        }
    }
    return NULL;
}

/**
 * Search the medial address of a given virtual address.
 * @param[in] vmi LibVMI instance
 * @param[in] v2m_chunk_list
 * @param[in] vaddr the virtual address
 * @param[out] medial_vaddr_ptr the corresponded medial address
 */
size_t
lookup_v2m_table(
    vmi_instance_t vmi,
    v2m_chunk_t v2m_chunk_list,
    addr_t vaddr,
    void** medial_vaddr_ptr)
{
    if (NULL != v2m_chunk_list) {
        v2m_chunk_t tmp = v2m_chunk_list;
        while (NULL != tmp) {
            if (vaddr >= tmp->vaddr_begin && vaddr <= tmp->vaddr_end) {
                size_t size = tmp->vaddr_end - vaddr + 1;
                *medial_vaddr_ptr = tmp->medial_mapping_addr + vaddr - tmp->vaddr_begin;
                return size;
            }
            tmp = tmp->next;
        }
    }
    return 0;
}

/**
 * munmap many m2p mappings in a same v2m chunk.
 * @param[in] v2m_chunk_list
 */
status_t
munmap_m2p_chunks(
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
 * delete a given v2m table structure
 * @param[in] vmi LibVMI instance
 * @param[in] v2m_table the table to delete
 */
status_t
delete_v2m_table(
    vmi_instance_t vmi,
    v2m_table_t v2m_table)
{
    kvm_instance_t *kvm = kvm_get_instance(vmi);

    // the 1st entry matches
    if (NULL != kvm->shm_snapshot_v2m_tables
        && v2m_table == kvm->shm_snapshot_v2m_tables) {
        v2m_table_t tmp = kvm->shm_snapshot_v2m_tables;
        kvm->shm_snapshot_v2m_tables = tmp->next;
        free(tmp);
        return VMI_SUCCESS;
    }
    // there are two or more entries
    else if (NULL != kvm->shm_snapshot_v2m_tables
        && NULL != kvm->shm_snapshot_v2m_tables->next) {
        v2m_table_t tmp[2];
        tmp[0] = kvm->shm_snapshot_v2m_tables;
        tmp[1] = kvm->shm_snapshot_v2m_tables->next;
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

/**
 * Destroy v2m mappings.
 *  1. munmap many m2p mappings in a v2m;
 *  2. delete v2m table.
 * @param[in] vmi LibVMI instance
 */
status_t
destroy_v2m(
    vmi_instance_t vmi)
{
    kvm_instance_t *kvm = kvm_get_instance(vmi);

    v2m_table_t tail = kvm->shm_snapshot_v2m_tables;
    if (NULL != tail) {
        do {
            v2m_table_t tmp = tail->next;

            if (VMI_SUCCESS
                != munmap_m2p_chunks(tail->v2m_chunks)) {
                errprint("fail to free_chunks_of_tevat_mapping_table_entry\n");
                return VMI_FAILURE;
            }

            tail->v2m_chunks = NULL;

            if (VMI_SUCCESS != delete_v2m_table(vmi, tail)) {
                errprint("fail to delete_tevat_mapping_table_entry\n");
                return VMI_FAILURE;
            }
            tail = tmp;
        } while (NULL != tail);
        kvm->shm_snapshot_v2m_tables = NULL;
    }
    return VMI_SUCCESS;
}

/**
 * kvm_get_memory_shm_snapshot
 *
 *  kvm shm-snapshot driver need not memcpy(), just return valid mapped address.
 */
void *
kvm_get_memory_shm_snapshot(
    vmi_instance_t vmi,
    addr_t paddr,
    uint32_t length)
{
    if (paddr + length > vmi->size) {
        dbprint
            ("--%s: request for PA range [0x%.16"PRIx64"-0x%.16"PRIx64"] reads past end of shm-snapshot\n",
             __FUNCTION__, paddr, paddr + length);
        goto error_noprint;
    }

    kvm_instance_t *kvm = kvm_get_instance(vmi);
    return kvm->shm_snapshot_map + paddr;

error_print:
    dbprint("%s: failed to read %d bytes at "
            "PA (offset) 0x%.16"PRIx64" [VM size 0x%.16"PRIx64"]\n", __FUNCTION__,
            length, paddr, vmi->size);
error_noprint:
    return NULL;
}

/**
 * kvm_release_memory_shm_snapshot
 *
 *  Since kvm_get_memory_shm_snapshot() didn't copy memory contents to a temporary buffer,
 *	shm-snapshot need not free memory.
 *	However, this dummy function is still required as memory_cache.c need release_data_callback() to
 *	free entries and it never checks if the callback is not NULL, which must cause segmentation fault.
 */
void
kvm_release_memory_shm_snapshot(
    void *memory,
    size_t length)
{
}

status_t
kvm_setup_shm_snapshot_mode(
	    vmi_instance_t vmi)
{
	char *shm_snapshot_status = exec_shm_snapshot(vmi);
	if (VMI_SUCCESS == exec_shm_snapshot_success(shm_snapshot_status)) {

		// dump cpu registers
		char *cpu_regs = exec_info_registers(kvm_get_instance(vmi));
		kvm_get_instance(vmi)->shm_snapshot_cpu_regs = strdup(cpu_regs);
		free(cpu_regs);


	                    pid_cache_flush(vmi);
	                    sym_cache_flush(vmi);
	                    rva_cache_flush(vmi);
	                    v2p_cache_flush(vmi);
		memory_cache_destroy(vmi);
		memory_cache_init(vmi, kvm_get_memory_shm_snapshot, kvm_release_memory_shm_snapshot,
							  1);

		if (shm_snapshot_status)
			free (shm_snapshot_status);
		return link_mmap_shm_snapshot_dev(vmi);
	} else {
		if (shm_snapshot_status)
			free (shm_snapshot_status);
		return VMI_FAILURE;
	}
}

status_t
kvm_teardown_shm_snapshot_mode(
		vmi_instance_t vmi)
{
    kvm_instance_t *kvm = kvm_get_instance(vmi);

    if (VMI_SUCCESS == test_using_shm_snapshot(kvm)) {
    	dbprint("--kvm: teardown KVM shm-snapshot\n");
    	munmap_unlink_shm_snapshot_dev(kvm, vmi->size);
    	if (kvm->shm_snapshot_cpu_regs != NULL) {
    		free(kvm->shm_snapshot_cpu_regs);
    		kvm->shm_snapshot_cpu_regs = NULL;
    	}

    	    pid_cache_flush(vmi);
    	    sym_cache_flush(vmi);
    	    rva_cache_flush(vmi);
    	    v2p_cache_flush(vmi);
        memory_cache_destroy(vmi);
    }
    return VMI_SUCCESS;
}
#endif

void *
kvm_get_memory_patch(
    vmi_instance_t vmi,
    addr_t paddr,
    uint32_t length)
{
    char *buf = safe_malloc(length + 1);
    struct request req;

    req.type = 1;   // read request
    req.address = (uint64_t) paddr;
    req.length = (uint64_t) length;

    int nbytes =
        write(kvm_get_instance(vmi)->socket_fd, &req,
              sizeof(struct request));
    if (nbytes != sizeof(struct request)) {
        goto error_exit;
    }
    else {
        // get the data from kvm
        nbytes =
            read(kvm_get_instance(vmi)->socket_fd, buf, length + 1);
        if (nbytes != (length + 1)) {
            goto error_exit;
        }

        // check that kvm thinks everything is ok by looking at the last byte
        // of the buffer, 0 is failure and 1 is success
        if (buf[length]) {
            // success, return pointer to buf
            return buf;
        }
    }

    // default failure
error_exit:
    if (buf)
        free(buf);
    return NULL;
}

void *
kvm_get_memory_native(
    vmi_instance_t vmi,
    addr_t paddr,
    uint32_t length)
{
    int numwords = ceil(length / 4);
    char *buf = safe_malloc(numwords * 4);
    char *bufstr = exec_xp(kvm_get_instance(vmi), numwords, paddr);

    char *paddrstr = safe_malloc(32);

    sprintf(paddrstr, "%.16x", paddr);

    char *ptr = strcasestr(bufstr, paddrstr);
    int i = 0, j = 0;

    while (i < numwords && NULL != ptr) {
        ptr += strlen(paddrstr) + 2;

        for (j = 0; j < 4; ++j) {
            uint32_t value = strtol(ptr, (char **) NULL, 16);

            memcpy(buf + i * 4, &value, 4);
            ptr += 11;
            i++;
        }

        sprintf(paddrstr, "%.16x", paddr + i * 4);
        ptr = strcasestr(ptr, paddrstr);
    }
    if (bufstr)
        free(bufstr);
    if (paddrstr)
        free(paddrstr);
    return buf;
}

void
kvm_release_memory(
    void *memory,
    size_t length)
{
    if (memory)
        free(memory);
}

status_t
kvm_put_memory(
    vmi_instance_t vmi,
    addr_t paddr,
    uint32_t length,
    void *buf)
{
    struct request req;

    req.type = 2;   // write request
    req.address = (uint64_t) paddr;
    req.length = (uint64_t) length;

    int nbytes =
        write(kvm_get_instance(vmi)->socket_fd, &req,
              sizeof(struct request));
    if (nbytes != sizeof(struct request)) {
        goto error_exit;
    }
    else {
        uint8_t status = 0;

        write(kvm_get_instance(vmi)->socket_fd, buf, length);
        read(kvm_get_instance(vmi)->socket_fd, &status, 1);
        if (0 == status) {
            goto error_exit;
        }
    }

    return VMI_SUCCESS;
error_exit:
    return VMI_FAILURE;
}

/**
 * Setup KVM live (i.e. KVM patch or KVM native) mode.
 * If KVM patch has been setup before, resume it.
 * If KVM patch hasn't been setup but is available, setup
 * KVM patch, otherwise setup KVM native.
 */
status_t
kvm_setup_live_mode(
	    vmi_instance_t vmi)
{
    kvm_instance_t *kvm = kvm_get_instance(vmi);

    if (VMI_SUCCESS == test_using_kvm_patch(kvm)) {
        dbprint("--kvm: resume custom patch for fast memory access\n");

        pid_cache_flush(vmi);
        sym_cache_flush(vmi);
        rva_cache_flush(vmi);
        v2p_cache_flush(vmi);
        memory_cache_destroy(vmi);
        memory_cache_init(vmi, kvm_get_memory_patch, kvm_release_memory,
                          1);
        return VMI_SUCCESS;
    }

    char *status = exec_memory_access(kvm_get_instance(vmi));
    if (VMI_SUCCESS == exec_memory_access_success(status)) {
        dbprint("--kvm: using custom patch for fast memory access\n");
        memory_cache_destroy(vmi);
        memory_cache_init(vmi, kvm_get_memory_patch, kvm_release_memory,
                          1);
        if (status)
            free(status);
        return init_domain_socket(kvm_get_instance(vmi));
    }
    else {
        dbprint
            ("--kvm: didn't find patch, falling back to slower native access\n");
        memory_cache_destroy(vmi);
        memory_cache_init(vmi, kvm_get_memory_native,
                          kvm_release_memory, 1);
        if (status)
            free(status);
        return VMI_SUCCESS;
    }
}

//----------------------------------------------------------------------------
// General Interface Functions (1-1 mapping to driver_* function)

status_t
kvm_init(
    vmi_instance_t vmi)
{
    virConnectPtr conn = NULL;
    virDomainPtr dom = NULL;
    virDomainInfo info;

    conn =
        virConnectOpenAuth("qemu:///system", virConnectAuthPtrDefault,
                           0);
    if (NULL == conn) {
        dbprint("--no connection to kvm hypervisor\n");
        return VMI_FAILURE;
    }

    dom = virDomainLookupByID(conn, kvm_get_instance(vmi)->id);
    if (NULL == dom) {
        dbprint("--failed to find kvm domain\n");
        return VMI_FAILURE;
    }

    // get the libvirt version
    unsigned long libVer = 0;

    if (virConnectGetLibVersion(conn, &libVer) != 0) {
        dbprint("--failed to get libvirt version\n");
        return VMI_FAILURE;
    }
    dbprint("--libvirt version %lu\n", libVer);

    kvm_get_instance(vmi)->conn = conn;
    kvm_get_instance(vmi)->dom = dom;
    kvm_get_instance(vmi)->socket_fd = 0;
    vmi->hvm = 1;

    //get the VCPU count from virDomainInfo structure
    if (-1 == virDomainGetInfo(kvm_get_instance(vmi)->dom, &info)) {
        dbprint("--failed to get vm info\n");
        return VMI_FAILURE;
    }
    vmi->num_vcpus = info.nrVirtCpu;

#if ENABLE_SHM_SNAPSHOT == 1
    /* get the memory size in advance for
     *  link_mmap_shm_snapshot() */
    if (driver_get_memsize(vmi, &vmi->size) == VMI_FAILURE) {
        errprint("Failed to get memory size.\n");
        return VMI_FAILURE;
    }
    dbprint("**set size = %"PRIu64" [0x%"PRIx64"]\n", vmi->size,
            vmi->size);


    if (vmi->flags & VMI_INIT_SHM_SNAPSHOT) {
    	return kvm_create_shm_snapshot(vmi);
    } else
#endif
    {
    	return kvm_setup_live_mode(vmi);
    }
}

void
kvm_destroy(
    vmi_instance_t vmi)
{
    kvm_instance_t *kvm = kvm_get_instance(vmi);

    destroy_domain_socket(kvm_get_instance(vmi));

#if ENABLE_SHM_SNAPSHOT == 1
    if (vmi->flags & VMI_INIT_SHM_SNAPSHOT) {
    	kvm_teardown_shm_snapshot_mode(vmi);
    }
#endif

    if (kvm_get_instance(vmi)->dom) {
        virDomainFree(kvm_get_instance(vmi)->dom);
    }
    if (kvm_get_instance(vmi)->conn) {
        virConnectClose(kvm_get_instance(vmi)->conn);
    }
}

unsigned long
kvm_get_id_from_name(
    vmi_instance_t vmi,
    char *name)
{
    virConnectPtr conn = NULL;
    virDomainPtr dom = NULL;
    unsigned long id;

    conn =
        virConnectOpenAuth("qemu:///system", virConnectAuthPtrDefault,
                           0);
    if (NULL == conn) {
        dbprint("--no connection to kvm hypervisor\n");
        return -1;
    }

    dom = virDomainLookupByName(conn, name);
    if (NULL == dom) {
        dbprint("--failed to find kvm domain\n");
        return -1;
    }

    id = (unsigned long) virDomainGetID(dom);

    if (dom)
        virDomainFree(dom);
    if (conn)
        virConnectClose(conn);

    return id;
}

status_t
kvm_get_name_from_id(
    vmi_instance_t vmi,
    unsigned long domid,
    char **name)
{
    virConnectPtr conn = NULL;
    virDomainPtr dom = NULL;

    conn =
        virConnectOpenAuth("qemu:///system", virConnectAuthPtrDefault,
                           0);
    if (NULL == conn) {
        dbprint("--no connection to kvm hypervisor\n");
        return VMI_FAILURE;
    }

    dom = virDomainLookupByID(conn, domid);
    if (NULL == dom) {
        dbprint("--failed to find kvm domain\n");
        return VMI_FAILURE;
    }

    *name = virDomainGetName(dom);

    if (dom)
        virDomainFree(dom);
    if (conn)
        virConnectClose(conn);

    return VMI_SUCCESS;
}

unsigned long
kvm_get_id(
    vmi_instance_t vmi)
{
    return kvm_get_instance(vmi)->id;
}

void
kvm_set_id(
    vmi_instance_t vmi,
    unsigned long id)
{
    kvm_get_instance(vmi)->id = id;
}

status_t
kvm_check_id(
    vmi_instance_t vmi,
    unsigned long id)
{
    virConnectPtr conn = NULL;
    virDomainPtr dom = NULL;

    conn =
        virConnectOpenAuth("qemu:///system", virConnectAuthPtrDefault,
                           0);
    if (NULL == conn) {
        dbprint("--no connection to kvm hypervisor\n");
        return VMI_FAILURE;
    }

    dom = virDomainLookupByID(conn, id);
    if (NULL == dom) {
        dbprint("--failed to find kvm domain\n");
        return VMI_FAILURE;
    }

    if (dom)
        virDomainFree(dom);
    if (conn)
        virConnectClose(conn);

    return VMI_SUCCESS;
}

status_t
kvm_get_name(
    vmi_instance_t vmi,
    char **name)
{
    const char *tmpname = virDomainGetName(kvm_get_instance(vmi)->dom);

    // don't need to deallocate the name, it will go away with the domain object

    if (NULL != tmpname) {
        *name = strdup(tmpname);
        return VMI_SUCCESS;
    }
    else {
        return VMI_FAILURE;
    }
}

void
kvm_set_name(
    vmi_instance_t vmi,
    char *name)
{
    kvm_get_instance(vmi)->name = strndup(name, 500);
}

status_t
kvm_get_memsize(
    vmi_instance_t vmi,
    unsigned long *size)
{
    virDomainInfo info;

    if (-1 == virDomainGetInfo(kvm_get_instance(vmi)->dom, &info)) {
        dbprint("--failed to get vm info\n");
        goto error_exit;
    }
    *size = info.maxMem * 1024; // convert KBytes to bytes

    return VMI_SUCCESS;
error_exit:
    return VMI_FAILURE;
}

status_t
kvm_get_vcpureg(
    vmi_instance_t vmi,
    reg_t *value,
    registers_t reg,
    unsigned long vcpu)
{
	char *regs = NULL;

#if ENABLE_SHM_SNAPSHOT == 1
	// if we have shm-snapshot configuration, then read from the loaded string.
	if (kvm_get_instance(vmi)->shm_snapshot_cpu_regs != NULL) {
		regs = strdup(kvm_get_instance(vmi)->shm_snapshot_cpu_regs);
		dbprint("read cpu regs from shm-snapshot\n");
	}
#endif

	if (NULL == regs)
		regs = exec_info_registers(kvm_get_instance(vmi));

    status_t ret = VMI_SUCCESS;

    if (VMI_PM_IA32E == vmi->page_mode) {
        switch (reg) {
        case RAX:
            *value = parse_reg_value("RAX", regs);
            break;
        case RBX:
            *value = parse_reg_value("RBX", regs);
            break;
        case RCX:
            *value = parse_reg_value("RCX", regs);
            break;
        case RDX:
            *value = parse_reg_value("RDX", regs);
            break;
        case RBP:
            *value = parse_reg_value("RBP", regs);
            break;
        case RSI:
            *value = parse_reg_value("RSI", regs);
            break;
        case RDI:
            *value = parse_reg_value("RDI", regs);
            break;
        case RSP:
            *value = parse_reg_value("RSP", regs);
            break;
        case R8:
            *value = parse_reg_value("R8", regs);
            break;
        case R9:
            *value = parse_reg_value("R9", regs);
            break;
        case R10:
            *value = parse_reg_value("R10", regs);
            break;
        case R11:
            *value = parse_reg_value("R11", regs);
            break;
        case R12:
            *value = parse_reg_value("R12", regs);
            break;
        case R13:
            *value = parse_reg_value("R13", regs);
            break;
        case R14:
            *value = parse_reg_value("R14", regs);
            break;
        case R15:
            *value = parse_reg_value("R15", regs);
            break;
        case RIP:
            *value = parse_reg_value("RIP", regs);
            break;
        case RFLAGS:
            *value = parse_reg_value("RFL", regs);
            break;
        case CR0:
            *value = parse_reg_value("CR0", regs);
            break;
        case CR2:
            *value = parse_reg_value("CR2", regs);
            break;
        case CR3:
            *value = parse_reg_value("CR3", regs);
            break;
        case CR4:
            *value = parse_reg_value("CR4", regs);
            break;
        case DR0:
            *value = parse_reg_value("DR0", regs);
            break;
        case DR1:
            *value = parse_reg_value("DR1", regs);
            break;
        case DR2:
            *value = parse_reg_value("DR2", regs);
            break;
        case DR3:
            *value = parse_reg_value("DR3", regs);
            break;
        case DR6:
            *value = parse_reg_value("DR6", regs);
            break;
        case DR7:
            *value = parse_reg_value("DR7", regs);
            break;
        case MSR_EFER:
            *value = parse_reg_value("EFER", regs);
            break;
        default:
            ret = VMI_FAILURE;
            break;
        }
    }
    else {
        switch (reg) {
        case RAX:
            *value = parse_reg_value("EAX", regs);
            break;
        case RBX:
            *value = parse_reg_value("EBX", regs);
            break;
        case RCX:
            *value = parse_reg_value("ECX", regs);
            break;
        case RDX:
            *value = parse_reg_value("EDX", regs);
            break;
        case RBP:
            *value = parse_reg_value("EBP", regs);
            break;
        case RSI:
            *value = parse_reg_value("ESI", regs);
            break;
        case RDI:
            *value = parse_reg_value("EDI", regs);
            break;
        case RSP:
            *value = parse_reg_value("ESP", regs);
            break;
        case RIP:
            *value = parse_reg_value("EIP", regs);
            break;
        case RFLAGS:
            *value = parse_reg_value("EFL", regs);
            break;
        case CR0:
            *value = parse_reg_value("CR0", regs);
            break;
        case CR2:
            *value = parse_reg_value("CR2", regs);
            break;
        case CR3:
            *value = parse_reg_value("CR3", regs);
            break;
        case CR4:
            *value = parse_reg_value("CR4", regs);
            break;
        case DR0:
            *value = parse_reg_value("DR0", regs);
            break;
        case DR1:
            *value = parse_reg_value("DR1", regs);
            break;
        case DR2:
            *value = parse_reg_value("DR2", regs);
            break;
        case DR3:
            *value = parse_reg_value("DR3", regs);
            break;
        case DR6:
            *value = parse_reg_value("DR6", regs);
            break;
        case DR7:
            *value = parse_reg_value("DR7", regs);
            break;
        case MSR_EFER:
            *value = parse_reg_value("EFER", regs);
            break;
        default:
            ret = VMI_FAILURE;
            break;
        }
    }

    if (regs)
        free(regs);
    return ret;
}

void *
kvm_read_page(
    vmi_instance_t vmi,
    addr_t page)
{
    addr_t paddr = page << vmi->page_shift;

    return memory_cache_insert(vmi, paddr);
}

status_t
kvm_write(
    vmi_instance_t vmi,
    addr_t paddr,
    void *buf,
    uint32_t length)
{
    return kvm_put_memory(vmi, paddr, length, buf);
}

int
kvm_is_pv(
    vmi_instance_t vmi)
{
    return 0;
}

status_t
kvm_test(
    unsigned long id,
    char *name)
{
    virConnectPtr conn = NULL;
    virDomainPtr dom = NULL;

    conn =
        virConnectOpenAuth("qemu:///system", virConnectAuthPtrDefault,
                           0);
    if (NULL == conn) {
        dbprint("--no connection to kvm hypervisor\n");
        return VMI_FAILURE;
    }

    if (conn)
        virConnectClose(conn);
    return VMI_SUCCESS;
}

status_t
kvm_pause_vm(
    vmi_instance_t vmi)
{
    if (-1 == virDomainSuspend(kvm_get_instance(vmi)->dom)) {
        return VMI_FAILURE;
    }
    return VMI_SUCCESS;
}

status_t
kvm_resume_vm(
    vmi_instance_t vmi)
{
    if (-1 == virDomainResume(kvm_get_instance(vmi)->dom)) {
        return VMI_FAILURE;
    }
    return VMI_SUCCESS;
}

#if ENABLE_SHM_SNAPSHOT == 1
status_t
kvm_create_shm_snapshot(
    vmi_instance_t vmi)
{
	// teardown the old shm-snapshot if existed.
    if (VMI_SUCCESS == test_using_shm_snapshot(kvm_get_instance(vmi))) {
    	kvm_teardown_shm_snapshot_mode(vmi);
    }

    return kvm_setup_shm_snapshot_mode(vmi);
}

status_t
kvm_destroy_shm_snapshot(
    vmi_instance_t vmi)
{
    destroy_v2m(vmi);
    kvm_teardown_shm_snapshot_mode(vmi);

    return kvm_setup_live_mode(vmi);
}


/**
 * A similar memory read semantic to vmi_read_pa() but a non-copy direct access.
 * As there is only one mapping of both p2m and m2p, we don't search any v2m table.
 * Note that it is only capable for shm-snapshot.
 * @param[in] vmi LibVMI instance
 * @param[in] paddr
 * @param[out] medial_addr_ptr
 * @param[in] count the expected count of bytes
 * @return the actual count that less or equal than count[in]
 */
size_t kvm_get_dgpma(
    vmi_instance_t vmi,
    addr_t paddr,
    void** medial_addr_ptr,
    size_t count) {

    *medial_addr_ptr = kvm_get_instance(vmi)->shm_snapshot_map + paddr;
    size_t max_size = vmi->size - (paddr - 0);
    return max_size>count?count:max_size;
}

/**
 * A similar memory read semantic to vmi_read_va() but a non-copy direct access.
 * Note that it is only capable for shm-snapshot.
 * @param[in] vmi LibVMI instance
 * @param[in] vaddr
 * @param[in] pid
 * @param[out] medial_addr_ptr
 * @param[in] count the expected count of bytes
 * @return the actual count that less or equal than count[in]
 */
size_t
kvm_get_dgvma(
    vmi_instance_t vmi,
    addr_t vaddr,
    pid_t pid,
    void** medial_addr_ptr,
    size_t count)
{
    // check if entry exists in the cache
    addr_t maddr;
    uint64_t length;
    if (VMI_SUCCESS == v2m_cache_get(vmi, vaddr, pid, &maddr, &length)) {
        *medial_addr_ptr = (void*)maddr;
        return length>count?count:length;
    }

    // get v2m table of a pid
    v2m_table_t v2m = get_v2m_table(vmi, pid);
    // v2m table is not existed
    if (NULL == v2m) {
        // create v2m table
        if (VMI_SUCCESS != create_v2m_table(vmi, pid, &v2m)) {
            return 0; // cannot create new v2m mapping
        }
    }

    // get medial addr
    size_t v2m_size = lookup_v2m_table(vmi,v2m->v2m_chunks, vaddr,
        medial_addr_ptr);

    // add this to the cache
    if (*medial_addr_ptr) {
        v2m_cache_set(vmi, vaddr, pid, (addr_t)*medial_addr_ptr, v2m_size);
    }

    return v2m_size>count?count:v2m_size;
}

#endif

//////////////////////////////////////////////////////////////////////
#else

status_t
kvm_init(
    vmi_instance_t vmi)
{
    return VMI_FAILURE;
}

void
kvm_destroy(
    vmi_instance_t vmi)
{
    return;
}

unsigned long
kvm_get_id_from_name(
    vmi_instance_t vmi,
    char *name)
{
    return 0;
}

status_t
kvm_get_name_from_id(
    vmi_instance_t vmi,
    unsigned long domid,
    char **name)
{
    return VMI_FAILURE;
}

unsigned long
kvm_get_id(
    vmi_instance_t vmi)
{
    return 0;
}

void
kvm_set_id(
    vmi_instance_t vmi,
    unsigned long id)
{
    return;
}

status_t
kvm_check_id(
    vmi_instance_t vmi,
    unsigned long id)
{
    return VMI_FAILURE;
}

status_t
kvm_get_name(
    vmi_instance_t vmi,
    char **name)
{
    return VMI_FAILURE;
}

void
kvm_set_name(
    vmi_instance_t vmi,
    char *name)
{
    return;
}

status_t
kvm_get_memsize(
    vmi_instance_t vmi,
    unsigned long *size)
{
    return VMI_FAILURE;
}

status_t
kvm_get_vcpureg(
    vmi_instance_t vmi,
    reg_t *value,
    registers_t reg,
    unsigned long vcpu)
{
    return VMI_FAILURE;
}

void *
kvm_read_page(
    vmi_instance_t vmi,
    addr_t page)
{
    return NULL;
}

status_t
kvm_write(
    vmi_instance_t vmi,
    addr_t paddr,
    void *buf,
    uint32_t length)
{
    return VMI_FAILURE;
}

int
kvm_is_pv(
    vmi_instance_t vmi)
{
    return 0;
}

status_t
kvm_test(
    unsigned long id,
    char *name)
{
    return VMI_FAILURE;
}

status_t
kvm_pause_vm(
    vmi_instance_t vmi)
{
    return VMI_FAILURE;
}

status_t
kvm_resume_vm(
    vmi_instance_t vmi)
{
    return VMI_FAILURE;
}

#if ENABLE_SHM_SNAPSHOT == 1
status_t
kvm_create_shm_snapshot(
    vmi_instance_t vmi)
{
    return VMI_FAILURE;
}

status_t
kvm_destroy_shm_snapshot(
    vmi_instance_t vmi)
{
    return VMI_FAILURE;
}

size_t
kvm_get_dgpma(
    vmi_instance_t vmi,
    addr_t paddr,
    void** medial_addr_ptr,
    size_t count)
{
    return NULL;
}

size_t
kvm_get_dgvma(
    vmi_instance_t vmi,
    addr_t vaddr,
    pid_t pid,
    void** guest_mapping_vaddr,
    size_t count)
{
    return NULL;
}

#endif

#endif /* ENABLE_KVM */
