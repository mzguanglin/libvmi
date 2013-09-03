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

#if ENABLE_SNAPSHOT == 1
status_t
test_using_snapshot(
		kvm_instance_t *kvm)
{
	if (NULL != kvm->shared_memory_snapshot_path && NULL != kvm->shared_memory_snapshot_fd
        && NULL != kvm->shared_memory_snapshot_map && NULL != kvm->shared_memory_snapshot_cpu_regs) {
        dbprint("is using snapshot\n");
        return VMI_SUCCESS;
	} else {
        dbprint("is not using snapshot\n");
        return VMI_FAILURE;
	}
}

/*
 * set kvm->shared_memory_snapshot_path;
 */
static char *
exec_shared_memory_snapshot(
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
        kvm->shared_memory_snapshot_path = strdup(shm_filename);
        free(unique_shm_path);
    #ifdef MEASUREMENT
        struct timeval ktv_start;
        struct timeval ktv_end;
        long int diff;
        gettimeofday(&ktv_start, 0);
    #endif
        char *output = exec_qmp_cmd(kvm, query);
    #ifdef MEASUREMENT
        gettimeofday(&ktv_end, 0);
        print_measurement(ktv_start, ktv_end, &diff);
        printf("QMP snapshot measurement: %ld\n", diff);
    #endif
        free(query);
        return output;
    }
    else {
    	return NULL;
    }
}

static status_t
exec_shared_memory_snapshot_success(
		char* status)
{
	// successful status should like: {"return":2684354560,"id":"libvirt-812"}
	if (NULL == status) {
        return VMI_FAILURE;
    }
    char *ptr = strcasestr(status, "CommandNotFound");
    if (NULL == ptr) {
    	uint64_t snapshot_size = strtoul(status + strlen("{\"return\":"), NULL, 0);
    	if (snapshot_size > 0) {
    		//qmp status e.g. : {"return":2684354560,"id":"libvirt-812"}
    		dbprint("--kvm: using shared memory snapshot support\n");
    		return VMI_SUCCESS;
    	} else {
    		//qmp status e.g. : {"return":0,"id":"libvirt-812"}
    		errprint ("--kvm: fail to snapshot\n");
    		return VMI_FAILURE;
    	}
    }
    else {
    	//qmp status e.g. : CommandNotFound
		errprint("--kvm: didn't find shared memory snapshot support\n");
        return VMI_FAILURE;
    }
}

/*
 * set kvm->shared_memory_snapshot_fd
 * set kvm->shared_memory_snapshot_map
 */
static status_t
link_mmap_shared_memory_snapshot_dev(
    vmi_instance_t vmi)
{
    kvm_instance_t *kvm = kvm_get_instance(vmi);
    if ((kvm->shared_memory_snapshot_fd = shm_open(kvm->shared_memory_snapshot_path, O_RDONLY, NULL)) < 0) {
        errprint("fail in shm_open %s", kvm->shared_memory_snapshot_path);
        return VMI_FAILURE;
    }
    ftruncate(kvm->shared_memory_snapshot_fd, vmi->size);

    /* try memory mapped file I/O */
    int mmap_flags = (MAP_PRIVATE | MAP_NORESERVE | MAP_POPULATE);
#ifdef MMAP_HUGETLB // since kernel 2.6.32
    mmap_flags |= MMAP_HUGETLB;
#endif // MMAP_HUGETLB

#ifdef MEASUREMENT
    struct timeval ktv_start;
    struct timeval ktv_end;
    long int diff;
    gettimeofday(&ktv_start, 0);
#endif
    kvm->shared_memory_snapshot_map = mmap(NULL,  // addr
        vmi->size,   // len
        PROT_READ,   // prot
        mmap_flags,  // flags
        kvm->shared_memory_snapshot_fd,    // file descriptor
        (off_t) 0);  // offset
    if (MAP_FAILED == kvm->shared_memory_snapshot_map) {
        perror("Failed to mmap shared memory snapshot dev");
        return VMI_FAILURE;
    }
#ifdef MEASUREMENT
    gettimeofday(&ktv_end, 0);
    print_measurement(ktv_start, ktv_end, &diff);
    printf("mmap measurement: %ld\n", diff);
#endif
    return VMI_SUCCESS;
}

/**
 * clear kvm->shared_memory_snapshot_map
 * clear kvm->shared_memory_snapshot_fd
 * clear kvm->shared_memory_snapshot_path
 */
static status_t
munmap_unlink_shared_memory_snapshot_dev(
		kvm_instance_t *kvm, uint64_t mem_size)
{
    if (kvm->shared_memory_snapshot_map) {
        (void) munmap(kvm->shared_memory_snapshot_map, mem_size);
        kvm->shared_memory_snapshot_map = 0;
    }
    if (kvm->shared_memory_snapshot_fd) {
    	shm_unlink(kvm->shared_memory_snapshot_path);
    	free(kvm->shared_memory_snapshot_path);
        kvm->shared_memory_snapshot_path = NULL;
        kvm->shared_memory_snapshot_fd = 0;
    }
    return VMI_SUCCESS;
}

/**
 * kvm_get_memory_shared_memory_snapshot
 *
 *  kvm shared memory snapshot driver need not memcpy(), just return valid mapped address.
 */
void *
kvm_get_memory_shared_memory_snapshot(
    vmi_instance_t vmi,
    addr_t paddr,
    uint32_t length)
{
    if (paddr + length > vmi->size) {
        dbprint
            ("--%s: request for PA range [0x%.16"PRIx64"-0x%.16"PRIx64"] reads past end of shared memory snapshot\n",
             __FUNCTION__, paddr, paddr + length);
        goto error_noprint;
    }

    kvm_instance_t *kvm = kvm_get_instance(vmi);
    return kvm->shared_memory_snapshot_map + paddr;

error_print:
    dbprint("%s: failed to read %d bytes at "
            "PA (offset) 0x%.16"PRIx64" [VM size 0x%.16"PRIx64"]\n", __FUNCTION__,
            length, paddr, vmi->size);
error_noprint:
    return NULL;
}

/**
 * kvm_release_memory_shared_memory_snapshot
 *
 *  Since kvm_get_memory_shared_memory_snapshot() didn't copy memory contents to a temporary buffer,
 *	shared snapshot need not free memory.
 *	However, this dummy function is still required as memory_cache.c need release_data_callback() to
 *	free entries and it never checks if the callback is not NULL, which must cause segmentation fault.
 */
void
kvm_release_memory_shared_memory_snapshot(
    void *memory,
    size_t length)
{
}

status_t
kvm_setup_snapshot_mode(
	    vmi_instance_t vmi)
{
	char *snapshot_status = exec_shared_memory_snapshot(vmi);
	if (VMI_SUCCESS == exec_shared_memory_snapshot_success(snapshot_status)) {

		// dump cpu registers
		char *cpu_regs = exec_info_registers(kvm_get_instance(vmi));
		kvm_get_instance(vmi)->shared_memory_snapshot_cpu_regs = strdup(cpu_regs);
		free(cpu_regs);

		memory_cache_destroy(vmi);
		memory_cache_init(vmi, kvm_get_memory_shared_memory_snapshot, kvm_release_memory_shared_memory_snapshot,
							  1);

		if (snapshot_status)
			free (snapshot_status);
		return link_mmap_shared_memory_snapshot_dev(vmi);
	} else {
		if (snapshot_status)
			free (snapshot_status);
		return VMI_FAILURE;
	}
}

status_t
kvm_teardown_snapshot_mode(
		vmi_instance_t vmi)
{
    kvm_instance_t *kvm = kvm_get_instance(vmi);

    if (VMI_SUCCESS == test_using_snapshot(kvm)) {
    	dbprint("--kvm: teardown KVM shared memory snapshot\n");
    	munmap_unlink_shared_memory_snapshot_dev(kvm, vmi->size);
    	if (kvm->shared_memory_snapshot_cpu_regs != NULL) {
    		free(kvm->shared_memory_snapshot_cpu_regs);
    		kvm->shared_memory_snapshot_cpu_regs = NULL;
    	}

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

#if ENABLE_SNAPSHOT == 1
    /* get the memory size in advance for
     *  link_mmap_shared_memory_snapshot() */
    if (driver_get_memsize(vmi, &vmi->size) == VMI_FAILURE) {
        errprint("Failed to get memory size.\n");
        return VMI_FAILURE;
    }
    dbprint("**set size = %"PRIu64" [0x%"PRIx64"]\n", vmi->size,
            vmi->size);


    if (vmi->flags & VMI_INIT_SNAPSHOT) {
    	return kvm_create_snapshot(vmi);
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

#if ENABLE_SNAPSHOT == 1
    if (vmi->flags & VMI_INIT_SNAPSHOT) {
    	kvm_teardown_snapshot_mode(vmi);
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

#if ENABLE_SNAPSHOT == 1
	// if we have snapshot configuration, then read from the loaded string.
	if (kvm_get_instance(vmi)->shared_memory_snapshot_cpu_regs != NULL) {
		regs = strdup(kvm_get_instance(vmi)->shared_memory_snapshot_cpu_regs);
		dbprint("read cpu regs from snapshot\n");
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

#if ENABLE_SNAPSHOT == 1
status_t
kvm_create_snapshot(
    vmi_instance_t vmi)
{
	// teardown the old snapshot if existed.
    if (VMI_SUCCESS == test_using_snapshot(kvm_get_instance(vmi))) {
    	kvm_teardown_snapshot_mode(vmi);
    }
    return kvm_setup_snapshot_mode(vmi);
}

status_t
kvm_destroy_snapshot(
    vmi_instance_t vmi)
{
	kvm_teardown_snapshot_mode(vmi);

	return kvm_setup_live_mode(vmi);
}


status_t map_page_table(
	    vmi_instance_t vmi,page_chrunk_t page_list, page_chrunk_t page_head) {

	// size
	addr_t size = page_head->vaddr_end - page_list->vaddr_begin;

	// find a proper vaddr base
    void *map = mmap(NULL,  // addr
    	size,   // 4gb vaddr space
        PROT_READ,   // prot
        MAP_PRIVATE | MAP_ANONYMOUS|MAP_NORESERVE,  // flags
        NULL,    // file descriptor
        NULL);  // offset
    if (MAP_FAILED != map) {
    	kvm_get_instance(vmi)->shared_memory_snapshot_kernel_vaddr_base = map;
        (void) munmap(map, size);
    } else {
        perror("Failed to mmap anonymous memory");
        return VMI_FAILURE;
    }

    int i=0;
	if (NULL != page_list) {
		do {
			/*printf("%d, va: 0x%llx - 0x%llx, pa: 0x%llx - 0x%llx, size: %dKB\n", i++,
					page_list->vaddr_begin, page_list->vaddr_end,
					page_list->paddr_begin, page_list->paddr_end,
					(page_list->vaddr_end - page_list->vaddr_begin+1)/1024);*/
			dbprint("%d, va: %lldM - %lldM, pa: %lldM - %lldM, size: %dKB\n", i++,
					page_list->vaddr_begin>>20, page_list->vaddr_end>>20,
					page_list->paddr_begin>>20, page_list->paddr_end>>20,
					(page_list->vaddr_end - page_list->vaddr_begin+1)>>10);

		      void *map = mmap(kvm_get_instance(vmi)->shared_memory_snapshot_kernel_vaddr_base + page_list->vaddr_begin,  // addr
		    		      (page_list->vaddr_end - page_list->vaddr_begin+1),   // len
				          PROT_READ,   // prot
				          MAP_PRIVATE | MAP_NORESERVE | MAP_POPULATE | MAP_FIXED,  // flags
				          kvm_get_instance(vmi)->shared_memory_snapshot_fd,    // file descriptor
				          page_list->paddr_begin);  // offset
		        if (MAP_FAILED != map) {
				    //test
				    /*void* vBuf = malloc((page_list->vaddr_end - page_list->vaddr_begin+1));
				    void* pBuf = malloc(page_list->vaddr_end - page_list->vaddr_begin+1);
				    vmi_read_va(vmi, page_list->vaddr_begin, 0, vBuf, (page_list->vaddr_end - page_list->vaddr_begin+1));
				    vmi_read_pa(vmi, page_list->paddr_begin, pBuf, (page_list->vaddr_end - page_list->vaddr_begin+1));
			    	if (0 != memcmp(vBuf, pBuf, (page_list->vaddr_end - page_list->vaddr_begin+1))) {
			    		printf("inconsistent vaddr %llx paddr %llx\n", page_list->vaddr_begin, page_list->paddr_begin);
		    			printf("vaddr %x %x %x\n", *((int*)vBuf + 0),*((int*)vBuf + 1),*((int*)vBuf + 2) );
		    			printf("paddr %x %x %x\n", *((int*)pBuf + 0),*((int*)pBuf + 1),*((int*)pBuf + 2) );
			    	}
			    	else {
			    		dbprint("consistent vaddr %llx paddr %llx\n", page_list->vaddr_begin, page_list->paddr_begin);
			    		dbprint("vaddr %x %x %x\n", *((int*)vBuf + 0),*((int*)vBuf + 1),
	    					*((int*)vBuf + 2) );
			    		dbprint("paddr %x %x %x\n", *((int*)pBuf + 0),*((int*)pBuf + 1),*((int*)pBuf + 2) );
			    	}
			    	free(vBuf);
			    	free(pBuf);*/

		        } else {
		            perror("Failed to mmap page");
		            return VMI_FAILURE;
		        }
			page_list = page_list->next;
		} while (NULL!= page_list);
	}
	return VMI_SUCCESS;
}

void print_page_entry(page_chrunk_t page_list) {
	int i=0;
	if (NULL != page_list) {
		do {
			dbprint("%d, va: 0x%llx - 0x%llx, pa: 0x%llx - 0x%llx, size: %dKB\n", i++,
					page_list->vaddr_begin, page_list->vaddr_end,
					page_list->paddr_begin, page_list->paddr_end,
					(page_list->vaddr_end - page_list->vaddr_begin+1)/1024);

			//if (i==0)
			//	printf("1st vaddr = 0x%x\n", page_list->vaddr_begin);
			page_list = page_list->next;
		} while (NULL!= page_list);
	}
}

static int page_count = 0;

void add_page_entry_to_list(page_chrunk_t *page_list, page_chrunk_t *head,
		addr_t start_vaddr, addr_t end_vaddr, addr_t start_paddr, addr_t end_paddr)
{
	dbprint("page_count:%d, vaddr: 0x%llx - 0x%llx, paddr: 0x%llx - 0x%llx, size:%dKB\n", page_count++, start_vaddr, end_vaddr,
			start_paddr, end_paddr, (end_vaddr-start_vaddr+1)>>10);
	// add to list
	if (NULL == *page_list) {
		*page_list = malloc(sizeof(page_chrunk));
		memset(*page_list, 0, sizeof(page_chrunk));
		(*page_list)->vaddr_begin = start_vaddr;
		(*page_list)->vaddr_end = end_vaddr;
		(*page_list)->paddr_begin = start_paddr;
		(*page_list)->paddr_end = end_paddr;
		(*head) = *page_list;
	} else {
		if (start_vaddr == (*head)->vaddr_end + 1 && start_paddr == (*head)->paddr_end + 1) {
			// merge
			(*head)->vaddr_end = end_vaddr;
			(*head)->paddr_end = end_paddr;
		} else {
			// new entry
			page_chrunk_t new_page = malloc(sizeof(page_chrunk));
			memset(new_page, 0, sizeof(page_chrunk));
			new_page->vaddr_begin = start_vaddr;
			new_page->vaddr_end = end_vaddr;
			new_page->paddr_begin = start_paddr;
			new_page->paddr_end = end_paddr;
			(*head)->next = new_page;
			(*head) = new_page;
		}
	}
}



status_t
walkthrough_kernel_pagetable_nopae(
    vmi_instance_t vmi,
    addr_t dtb)
{
	page_chrunk_t page_list = NULL;
	page_chrunk_t page_head = NULL;

	//read page directory page
    unsigned char *page_directory = NULL;
    addr_t pfn = 0;
    pfn = dtb >> vmi->page_shift;
    page_directory = vmi_read_page(vmi, pfn);

    // walk through page directory entries
    addr_t i;
    for (i=0; i<1024; i++) {
    	uint32_t page_directory_entry = *(uint32_t*)(page_directory + sizeof(uint32_t) * i);
    	if (entry_present(vmi->os_type, page_directory_entry)) //valid
    	{
    		dbprint("page_frame_number =0x%x, U%d, P%d, Cw%d, GI%d, L%d,"
    			" D%d, A%d, Cd%d, Wt%d, O%d, W%d, V%d\n", (page_directory_entry>>12) & 0xFFFFF000,
    			(page_directory_entry>>11)&1, (page_directory_entry>>10)&1,(page_directory_entry>>9)&1,
    			(page_directory_entry>>8)&1,(page_directory_entry>>7)&1,
    			(page_directory_entry>>6)&1, (page_directory_entry>>5)&1,
    			(page_directory_entry>>4)&1,(page_directory_entry>>3)&1,
    			(page_directory_entry>>2)&1,(page_directory_entry>>1)&1,
    			page_directory_entry&1);

            if (page_size_flag(page_directory_entry)) {
            	// large page (4mb)
            	addr_t start_vaddr = i << 22;  // left 10 bits
            	addr_t end_vaddr =   start_vaddr | 0x3FFFFF; // begin + 4mb
            	addr_t start_paddr = page_directory_entry & 0xFFC00000; // left 10 bits
            	addr_t end_paddr = start_paddr | 0x3FFFFF; // begin + 4mb
            	if (start_paddr < vmi->size) {
					add_page_entry_to_list(&page_list, &page_head,  start_vaddr,  end_vaddr, start_paddr, end_paddr);
            	}
            }
            else {
            	 // page table entry
            	 unsigned char *page_table = NULL;
            	 pfn = ptba_base_nopae(page_directory_entry) >> vmi->page_shift;
            	 page_table = vmi_read_page(vmi, pfn);

            	 addr_t j;
            	 for (j=0; j<1024; j++) {
            	    	uint32_t page_table_entry = *(uint32_t*)(page_table + sizeof(uint32_t) * j);
            	    	if (entry_present(vmi->os_type, page_table_entry)) //valid
            	    	{
            	    		dbprint("valid page table entry %d, %8x:\n", i, page_table_entry);
            	    		// 4kb page
                        	addr_t start_vaddr = i << 22 | j << 12;  // left 20 bits
                        	addr_t end_vaddr =   start_vaddr | 0xFFF; // begin + 4kb
                        	addr_t start_paddr = (page_table_entry & 0xFFFFF000); // left 20 bits
                        	addr_t end_paddr = start_paddr | 0xFFF; // begin + 4kb
                        	if (start_paddr < vmi->size) {
                				add_page_entry_to_list(&page_list, &page_head,  start_vaddr,  end_vaddr, start_paddr, end_paddr);
                        	}
            	    	}
            	 }
            }
    	}
    }

    kvm_instance_t *kvm = kvm_get_instance(vmi);
    kvm ->shared_memory_snapshot_kernel_page_list = page_list;
    kvm-> shared_memory_snapshot_kernel_page_head = page_head;

	return VMI_SUCCESS;
}

status_t
walkthrough_kernel_pagetable(
    vmi_instance_t vmi,
    addr_t dtb)
{
    if (vmi->page_mode == VMI_PM_LEGACY) {
        return walkthrough_kernel_pagetable_nopae(vmi, dtb);
    }
    else if (vmi->page_mode == VMI_PM_PAE) {
    	dbprint("VMI_PM_PAE unsupported during walkthrough_kernel_pagetable\n");
        return VMI_FAILURE;
    }
    else if (vmi->page_mode == VMI_PM_IA32E) {
    	dbprint("VMI_PM_IA32E unsupported during walkthrough_kernel_pagetable\n");
        return VMI_FAILURE;
    }
    else {
        errprint("Invalid paging mode during walkthrough_kernel_pagetable\n");
        return VMI_FAILURE;
    }
}

status_t
kvm_replicate_snapshot_kernel_pagetable(
    vmi_instance_t vmi)
{
	reg_t cr3 = 0;

    if (vmi->kpgd) {
        cr3 = vmi->kpgd;
    }
    else {
        driver_get_vcpureg(vmi, &cr3, CR3, 0);
    }
    if (!cr3) {
        dbprint("--early bail on v2p lookup because cr3 is zero\n");
        return 0;
    }
    else {
        if (VMI_SUCCESS ==  walkthrough_kernel_pagetable(vmi, cr3)) {
            kvm_instance_t *kvm = kvm_get_instance(vmi);
            return map_page_table(vmi, kvm ->shared_memory_snapshot_kernel_page_list,  kvm-> shared_memory_snapshot_kernel_page_head);
        }
        return VMI_FAILURE;

    }
}

void*
kvm_get_snapshot_kernel_vaddr_base(
	vmi_instance_t vmi)
{
	return kvm_get_instance(vmi)->shared_memory_snapshot_kernel_vaddr_base;
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

#if ENABLE_SNAPSHOT == 1
status_t
kvm_create_snapshot(
    vmi_instance_t vmi)
{
    return VMI_FAILURE;
}

status_t
kvm_destroy_snapshot(
    vmi_instance_t vmi)
{
    return VMI_FAILURE;
}

status_t
kvm_replicate_snapshot_kernel_pagetable(
    vmi_instance_t vmi)
{
	return VMI_FAILURE;
}

void*
kvm_get_snapshot_kernel_vaddr_base(
	vmi_instance_t vmi)
{
    return NULL;
}

#endif

#endif /* ENABLE_KVM */
