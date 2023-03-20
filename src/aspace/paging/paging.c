/* 
 * This file is part of the Nautilus AeroKernel developed
 * by the Hobbes and V3VEE Projects with funding from the 
 * United States National  Science Foundation and the Department of Energy.  
 *
 * The V3VEE Project is a joint project between Northwestern University
 * and the University of New Mexico.  The Hobbes Project is a collaboration
 * led by Sandia National Laboratories that includes several national 
 * laboratories and universities. You can find out more at:
 * http://www.v3vee.org  and
 * http://xstack.sandia.gov/hobbes
 *
 * Copyright (c) 2019, Hongyi Chen
 * Copyright (c) 2019, Peter Dinda
 * Copyright (c) 2019, The V3VEE Project  <http://www.v3vee.org> 
 *                     The Hobbes Project <http://xstack.sandia.gov/hobbes>
 * All rights reserved.
 *
 * Authors: Hongyi Chen
 *          Peter Dinda <pdinda@northwestern.edu>
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "LICENSE.txt".
 */


//
// This is a template for the CS343 paging lab at
// Northwestern University
//
// Please also look at the paging_helpers files!
//
//
//
//

#include <nautilus/nautilus.h>
#include <nautilus/spinlock.h>
#include <nautilus/paging.h>
#include <nautilus/thread.h>
#include <nautilus/shell.h>
#include <nautilus/cpu.h>

#include <nautilus/aspace.h>

#include "paging_helpers.h"


//
// Add debugging and other optional output to this subsytem
//
#ifndef NAUT_CONFIG_DEBUG_ASPACE_PAGING
#undef DEBUG_PRINT
#define DEBUG_PRINT(fmt, args...) 
#endif

#define ERROR(fmt, args...) ERROR_PRINT("aspace-paging: " fmt, ##args)
#define DEBUG(fmt, args...) DEBUG_PRINT("aspace-paging: " fmt, ##args)
#define INFO(fmt, args...)   INFO_PRINT("aspace-paging: " fmt, ##args)


// Some macros to hide the details of doing locking for
// a paging address space
#define ASPACE_LOCK_CONF uint8_t _aspace_lock_flags
#define ASPACE_LOCK(a) _aspace_lock_flags = spin_lock_irq_save(&(a)->lock)
#define ASPACE_TRY_LOCK(a) spin_try_lock_irq_save(&(a)->lock,&_aspace_lock_flags)
#define ASPACE_UNLOCK(a) spin_unlock_irq_restore(&(a)->lock, _aspace_lock_flags);
#define ASPACE_UNIRQ(a) irq_enable_restore(_aspace_lock_flags);


// graceful printouts of names
#define ASPACE_NAME(a) ((a)?(a)->aspace->name : "default")
#define THREAD_NAME(t) ((!(t)) ? "(none)" : (t)->is_idle ? "(idle)" : (t)->name[0] ? (t)->name : "(noname)")

// You probably want some sort of data structure that will let you
// keep track of the set of regions you are asked to add/remove/change
typedef struct region_node {
    nk_aspace_region_t region;
    struct region_node *next;
} region_node_t;

// You will want some data structure to represent the state
// of a paging address space
typedef struct nk_aspace_paging {
    // pointer to the abstract aspace that the
    // rest of the kernel uses when dealing with this
    // address space
    nk_aspace_t *aspace;
    
    // perhaps you will want to do concurrency control?
    spinlock_t   lock;

    // Here you probably will want your region set data structure 
    // What should it be...
    region_node_t *region_nodes;
    
    // Your characteristics
    nk_aspace_characteristics_t chars;

    // The cr3 register contents that reflect
    // the root of your page table hierarchy
    ph_cr3e_t     cr3;

    // The cr4 register contents used by the HW to interpret
    // your page table hierarchy.   We only care about a few bits
#define CR4_MASK 0xb0ULL // bits 4,5,7
    uint64_t      cr4;

} nk_aspace_paging_t;


// -------------- Task2: add, remove, change, lookup regions ------------------

typedef ulong_t RegionPropertyMatch;
#define VA_IDENTICAL 1 // actually, va and len identical
#define PA_IDENTICAL 2
#define PROT_IDENTICAL 4
#define VA_PA_IDENTICAL (VA_IDENTICAL + PA_IDENTICAL)
#define VA_PROT_IDENTICAL (VA_IDENTICAL + PROT_IDENTICAL)
#define PA_PROT_IDENTICAL (PA_IDENTICAL + PROT_IDENTICAL)
#define ALL_IDENTICAL (VA_IDENTICAL + PA_IDENTICAL + PROT_IDENTICAL)


#define REGION_FORMAT "(VA=(0x%lx - 0x%lx) -> PA=0x%p, len=%lx, prot=%lx)"
#define REGION(r) (r)->va_start, (r)->va_start + (r)->len_bytes - 1, (r)->pa_start, (r)->len_bytes, (r)->protect.flags


static int addRegion(nk_aspace_paging_t *p, nk_aspace_region_t *region) {
    // the "region" field in "region_node" is a nk_aspace_region_t instance instead of a pointer
    region_node_t *region_node = p->region_nodes;

    while (region_node) {
        addr_t existing_va_start = (addr_t) region_node->region.va_start;
        addr_t existing_va_end = existing_va_start + region_node->region.len_bytes - 1;
        addr_t new_va_start = (addr_t) region->va_start;
        addr_t new_va_end = new_va_start + region->len_bytes - 1;

        if ((new_va_end < existing_va_start) || (new_va_start > existing_va_end)) {
            region_node = region_node->next;
        } else {
            ERROR("The new region overlaps with existing region(s)");
            return -1;
        }
    }

    region_node_t* new_region_node = malloc(sizeof(region_node_t));
    new_region_node->region = *region;
    new_region_node->next = p->region_nodes;
    p->region_nodes = new_region_node;

    return 0;
}

static int lookupRegionByAddr (nk_aspace_paging_t *p, addr_t virtaddr, nk_aspace_region_t **result) {
    region_node_t *region_node = p->region_nodes;
    while (region_node) {
        addr_t existing_va_start = (addr_t) region_node->region.va_start;
        addr_t existing_va_end = existing_va_start + region_node->region.len_bytes - 1;
        if ((virtaddr >= existing_va_start) && (virtaddr <= existing_va_end)) {
            *result = &region_node->region;
            return 0;
        } else {
            region_node = region_node->next;
        }
    }
    return -1;
}


static int lookupRegionByRegion(nk_aspace_paging_t *p, nk_aspace_region_t *region, RegionPropertyMatch matchInfo,
                                nk_aspace_region_t **target_region) {
    // the "region" field in "current_node" is a nk_aspace_region_t instance instead of a pointer

    addr_t new_va_start = (addr_t) region->va_start;
    addr_t new_pa_start = (addr_t) region->pa_start;
    uint64_t new_len_bytes = region->len_bytes;
    nk_aspace_protection_t new_protect = region->protect;

    region_node_t *current_node = p->region_nodes;
    while (current_node) {
        addr_t existing_va_start = (addr_t) current_node->region.va_start;
        addr_t existing_pa_start = (addr_t) current_node->region.pa_start;
        uint64_t existing_len_bytes = current_node->region.len_bytes;
        nk_aspace_protection_t existing_protect = current_node->region.protect;

        if ((matchInfo & VA_IDENTICAL) && ((existing_va_start != new_va_start) || (existing_len_bytes != new_len_bytes)) ) {
            current_node = current_node->next;
            continue;
        }
        if ((matchInfo & PA_IDENTICAL) && (existing_pa_start != new_pa_start) ) {
            current_node = current_node->next;
            continue;
        }
        if ((matchInfo & PROT_IDENTICAL) && (existing_protect.flags != new_protect.flags)) {
            current_node = current_node->next;
            continue;
        }

        *target_region = &current_node->region;
        return 0;
    }
    return -1;
}


static int removeRegionNode(nk_aspace_paging_t *p, nk_aspace_region_t *region) {
    // the "region" field in "current_node" is a nk_aspace_region_t instance instead of a pointer
    addr_t new_va_start = (addr_t) region->va_start;
    addr_t new_pa_start = (addr_t) region->pa_start;
    uint64_t new_len_bytes = region->len_bytes;
    nk_aspace_protection_t new_protect = region->protect;

    region_node_t *current_node = p->region_nodes;
    region_node_t *previous_node = NULL;
    while (current_node) {
        addr_t existing_va_start = (addr_t) current_node->region.va_start;
        addr_t existing_pa_start = (addr_t) current_node->region.pa_start;
        uint64_t existing_len_bytes = current_node->region.len_bytes;
        nk_aspace_protection_t existing_protect = current_node->region.protect;

        if ((existing_va_start != new_va_start) || (existing_len_bytes != new_len_bytes)) {
            previous_node = current_node;
            current_node = current_node->next;
            continue;
        }
        if (existing_protect.flags != new_protect.flags) {
            previous_node = current_node;
            current_node = current_node->next;
            continue;
        }
        if (current_node->region.protect.flags & NK_ASPACE_PIN) {
            return -1;
        } else {
            if (previous_node) {
                previous_node->next = current_node->next;
            } else {
                p->region_nodes = current_node->next;
            }
            free(current_node);
            return 0;
        }
    }
    return -1;
}

static ph_pf_access_t getAccessFromProtection(nk_aspace_protection_t protect) {
    ph_pf_access_t access;
    access.write = ((protect.flags & NK_ASPACE_WRITE) != 0) ? 1 : 0;
    access.user = 1; // 1 means user mode, nautilus has no user mode
    access.ifetch = ((protect.flags & NK_ASPACE_EXEC) != 0) ? 1 : 0;
    return access;
}

static void markNotPresent(void *entry) {
    // present bit is always the highest bit
    ph_pte_t *entry_ptr = (ph_pte_t *) entry;
    entry_ptr->present = 0;
}

static int paging_table_set_permissions(void *entry, ph_pf_access_t a) {
    return paging_helper_set_permissions(entry, a);
}

static void updateEntryPermissions(ph_cr3e_t cr3, addr_t vaddr, ph_pf_access_t access_type) {
    ph_pml4e_t *pml4 = (ph_pml4e_t *)PAGE_NUM_TO_ADDR_4KB(cr3.pml4_base);
    ph_pml4e_t *pml4e = &pml4[ADDR_TO_PML4_INDEX(vaddr)];
    paging_table_set_permissions(pml4e, access_type);
    if (pml4e->present) {
        ph_pdpe_t *pdp = (ph_pdpe_t *)PAGE_NUM_TO_ADDR_4KB(pml4e->pdp_base);
        ph_pdpe_t *pdpe = &pdp[ADDR_TO_PDP_INDEX(vaddr)];
        paging_table_set_permissions(pdpe, access_type);
        if (pdpe->present) {
            ph_pde_t *pd = (ph_pde_t *)PAGE_NUM_TO_ADDR_4KB(pdpe->pd_base);
            ph_pde_t *pde = &pd[ADDR_TO_PD_INDEX(vaddr)];
            paging_table_set_permissions(pde, access_type);
            if (pde->present) {
                ph_pte_t *pt = (ph_pte_t *)PAGE_NUM_TO_ADDR_4KB(pde->pt_base);
                ph_pte_t *pte = &pt[ADDR_TO_PT_INDEX(vaddr)];
                paging_table_set_permissions(pte, access_type);
            }
        }
    }
}

// ----------------------------------------------------------------------------





// The function the aspace abstraction will call when it
// wants to destroy your address space
static  int destroy(void *state)
{
    // the pointer it hands you is for the state you supplied
    // when you registered the address space
    nk_aspace_paging_t *p = (nk_aspace_paging_t *)state;

    DEBUG("destroying address space %s\n", ASPACE_NAME(p));

    ASPACE_LOCK_CONF;

    // lets do that with a lock, perhaps? 
    ASPACE_LOCK(p);
    //
    // WRITEME!!    actually do the work
    // 
    ASPACE_UNLOCK(p);

    return 0;
}

// The function the aspace abstraction will call when it
// is adding a thread to your address space
// do you care? 
static int add_thread(void *state)
{
    nk_aspace_paging_t *p = (nk_aspace_paging_t *)state;
    struct nk_thread *t = get_cur_thread();
    
    DEBUG("adding thread %d (%s) to address space %s\n", t->tid,THREAD_NAME(t), ASPACE_NAME(p));
    
    return 0;
}
    
    
// The function the aspace abstraction will call when it
// is removing from your address space
// do you care? 
static int remove_thread(void *state)
{
    nk_aspace_paging_t *p = (nk_aspace_paging_t *)state;
    struct nk_thread *t = get_cur_thread();
    
    DEBUG("removing thread %d (%s) from address space %s\n", t->tid, THREAD_NAME(t), ASPACE_NAME(p));
    
    return 0;
}

// The function the aspace abstraction will call when it
// is adding a region to your address space
static int add_region(void *state, nk_aspace_region_t *region)
{
    // add the new node into region_list
    nk_aspace_paging_t *p = (nk_aspace_paging_t *)state;

    DEBUG("adding region (va=%016lx pa=%016lx len=%lx) to address space %s\n", region->va_start, region->pa_start, region->len_bytes,ASPACE_NAME(p));

    ASPACE_LOCK_CONF;

    ASPACE_LOCK(p);

    // WRITE ME!!
    
    // first you should sanity check the region to be sure it doesn't overlap
    // an existing region, and then place it into your region data structure

    // NOTE: you MUST create a new nk_aspace_region_t to store in your data structure
    // and you MAY NOT store the region pointer in your data structure. There is no
    // promise that data at the region pointer will not be modified after this function
    // returns
    if (addRegion(p, region) != 0) {
        ASPACE_UNLOCK(p);
        return -1;
    }

    if (region->protect.flags & NK_ASPACE_EAGER) {
	
	// an eager region means that we need to build all the corresponding
	// page table entries right now, before we return

	// DRILL THE PAGE TABLES HERE
        ph_pf_access_t access = getAccessFromProtection(region->protect);
        addr_t va_start = (addr_t)region->va_start;
        addr_t pa_start = (addr_t)region->pa_start;
        for (addr_t offset = 0; offset < region->len_bytes; offset += PAGE_SIZE_4KB) {
            paging_helper_drill(p->cr3, va_start + offset, pa_start + offset, access);
        }
    }


    // if we are editing the current address space of this cpu, then we
    // might need to flush the TLB here.   We can do that with a cr3 write
    // like: write_cr3(p->cr3.val);
    
    write_cr3(p->cr3.val);


    // if this aspace is active on a different cpu, we might need to do
    // a TLB shootdown here (out of scope of class)
    // a TLB shootdown is an interrupt to a remote CPU whose handler
    // flushes the TLB

    ASPACE_UNLOCK(p);

    return 0;
}

// The function the aspace abstraction will call when it
// is removing a region from your address space
static int remove_region(void *state, nk_aspace_region_t *region)
{
    nk_aspace_paging_t *p = (nk_aspace_paging_t *)state;

    DEBUG("removing region (va=%016lx pa=%016lx len=%lx) from address space %s\n", region->va_start, region->pa_start, region->len_bytes,ASPACE_NAME(p));

    ASPACE_LOCK_CONF;

    ASPACE_LOCK(p);

    // WRITE ME!
    
    // first, find the region in your data structure
    // it had better exist and be identical.
    nk_aspace_region_t** target_region_pt = NULL;
    if (lookupRegionByRegion(p, region, VA_PROT_IDENTICAL,  target_region_pt) != 0) {
        ASPACE_UNLOCK(p);
        return -1;
    }
    nk_aspace_region_t *target_region = *target_region_pt;

    // next, remove the region from your data structure
    nk_aspace_region_t target_region_backup = *target_region;
    if (removeRegionNode(p, target_region) != 0) {
        ASPACE_UNLOCK(p);
        return -1;
    }

    // next, remove all corresponding page table entries that exist
    
    // next, if we are editing the current address space of this cpu,
    // we need to either invalidate individual pages using invlpg()
    // or do a full TLB flush with a write to cr3.
    uint64_t **entry = NULL;
    addr_t va_start = (addr_t)target_region_backup.va_start;
    ph_pf_access_t access = getAccessFromProtection(target_region_backup.protect);
    for (addr_t offset = 0; offset < target_region_backup.len_bytes; offset += PAGE_SIZE_4KB) {
        paging_helper_walk(p->cr3, va_start + offset, access, entry);
        uint64_t *page_table_entry = *entry;
        if (page_table_entry != NULL) {
            markNotPresent(page_table_entry);
        }
        invlpg((addr_t)target_region->va_start + offset);
    }


    ASPACE_UNLOCK(p);

    return 0;

}
   
// The function the aspace abstraction will call when it
// is changing the protections of an existing region
static int protect_region(void *state, nk_aspace_region_t *region, nk_aspace_protection_t *prot)
{
    nk_aspace_paging_t *p = (nk_aspace_paging_t *)state;

    DEBUG("protecting region (va=%016lx pa=%016lx len=%lx) from address space %s\n", region->va_start, region->pa_start, region->len_bytes,ASPACE_NAME(p));

    ASPACE_LOCK_CONF;

    ASPACE_LOCK(p);

    // WRITE ME!
    
    // first, find the region in your data structure
    // it had better exist and be identical except for protections
    nk_aspace_region_t** target_region_pt = NULL;
    if (lookupRegionByRegion(p, region, VA_PA_IDENTICAL, target_region_pt) != 0) {
        ASPACE_UNLOCK(p);
        return -1;
    }
    nk_aspace_region_t *target_region = *target_region_pt;

    // next, update the region protections from your data structure
    ph_pf_access_t access = getAccessFromProtection(target_region->protect);
    ph_pf_access_t new_access = getAccessFromProtection(*prot);
    target_region->protect = *prot;

    // next, update all corresponding page table entries that exist
    addr_t va_start = (addr_t)target_region->va_start;
    for (addr_t offset = 0; offset < target_region->len_bytes; offset += PAGE_SIZE_4KB) {
        updateEntryPermissions(p->cr3, va_start + offset, new_access);
    }

    // next, if we are editing the current address space of this cpu,
    // we need to either invalidate individual pages using invlpg()
    // or do a full TLB flush with a write to cr3.

    write_cr3(p->cr3.val);

    ASPACE_UNLOCK(p);

    return 0;
}

static int move_region(void *state, nk_aspace_region_t *cur_region, nk_aspace_region_t *new_region)
{
    nk_aspace_paging_t *p = (nk_aspace_paging_t *)state;

    DEBUG("moving region (va=%016lx pa=%016lx len=%lx) in address space %s to (va=%016lx pa=%016lx len=%lx)\n", cur_region->va_start, cur_region->pa_start, cur_region->len_bytes,ASPACE_NAME(p),new_region->va_start,new_region->pa_start,new_region->len_bytes);

    ASPACE_LOCK_CONF;

    ASPACE_LOCK(p);

    // WRITE ME!
    
    // first, find the region in your data structure
    // it had better exist and be identical except for the physical addresses
    nk_aspace_region_t** target_region_pt = NULL;
    if (lookupRegionByRegion(p, cur_region, VA_PROT_IDENTICAL, target_region_pt) != 0) {
        ASPACE_UNLOCK(p);
        return -1;
    }
    nk_aspace_region_t *target_region = *target_region_pt;

    // next, update the region in your data structure
    if (target_region->protect.flags & NK_ASPACE_PIN) {
        ASPACE_UNLOCK(p);
        return -1;
    }
    target_region->pa_start = new_region->pa_start;

    // you can assume that the caller has done the work of copying the memory
    // contents to the new physical memory

    // next, update all corresponding page table entries that exist
    addr_t va_start = (addr_t)target_region->va_start;
    addr_t pa_start = (addr_t)target_region->pa_start;
    ph_pf_access_t access = getAccessFromProtection(target_region->protect);
    for (addr_t offset = 0; offset < target_region->len_bytes; offset += PAGE_SIZE_4KB) {
        paging_helper_drill(p->cr3, va_start + offset, pa_start + offset, access);
    }

    // next, if we are editing the current address space of this cpu,
    // we need to either invalidate individual pages using invlpg()
    // or do a full TLB flush with a write to cr3.

    write_cr3(p->cr3.val);
    

    // OPTIONAL ADVANCED VERSION: allow for splitting the region - if cur_region
    // is a subset of some region, then split that region, and only move
    // the affected addresses.   The granularity of this is that reported
    // in the aspace characteristics (i.e., page granularity here).

    ASPACE_UNLOCK(p);

    return 0;
}


// called by the address space abstraction when it is switching away from
// the noted address space.   This is part of the thread context switch.
// do you care?
static int switch_from(void *state)
{
    struct nk_aspace_paging *p = (struct nk_aspace_paging *)state;
    struct nk_thread *thread = get_cur_thread();
    
    DEBUG("switching out address space %s from thread %d (%s)\n",ASPACE_NAME(p), thread->tid, THREAD_NAME(thread));
    
    return 0;
}

// called by the address space abstraction when it is switching to the
// noted address space.  This is part of the thread context switch.
static int switch_to(void *state)
{
    nk_aspace_paging_t *p = (nk_aspace_paging_t *)state;
    struct nk_thread *thread = get_cur_thread();
    
    DEBUG("switching in address space %s from thread %d (%s)\n", ASPACE_NAME(p),thread->tid,THREAD_NAME(thread));
    
    // Here you will need to install your page table hierarchy
    // first point CR3 to it
    write_cr3(p->cr3.val);

    // next make sure the interpretation bits are set in cr4
    uint64_t cr4 = read_cr4();
    cr4 &= ~CR4_MASK;
    cr4 |= p->cr4;
    write_cr4(cr4);
    
    return 0;
}

// called by the address space abstraction when a page fault or a
// general protection fault is encountered in the context of the
// current thread
//
// exp points to the hardware interrupt frame on the stack
// vec indicates which vector happened
//
static int exception(void *state, excp_entry_t *exp, excp_vec_t vec)
{
    nk_aspace_paging_t *p = (nk_aspace_paging_t *)state;
    struct nk_thread *thread = get_cur_thread();
    
    DEBUG("exception 0x%x for address space %s in context of thread %d (%s)\n",vec,ASPACE_NAME(p),thread->tid,THREAD_NAME(thread));
    
    if (vec==GP_EXCP) {
	ERROR("general protection fault encountered.... uh...\n");
	ERROR("i have seen things that you people would not believe.\n");
	panic("general protection fault delivered to paging subsystem\n");
	return -1; // will never happen
    }

    if (vec!=PF_EXCP) {
	ERROR("Unknown exception %d delivered to paging subsystem\n",vec);
	panic("Unknown exception delivered to paging subsystem\n");
	return -1; // will never happen
    }
    
    // It must be a page fault

    // find out what the fault address and the fault reason
    uint64_t virtaddr = read_cr2();
    ph_pf_error_t  error;
    error.val = exp->error_code;
    
    
    ASPACE_LOCK_CONF;
    
    ASPACE_LOCK(p);

    //
    // WRITE ME!
    //
    
    // Now find the region corresponding to this address

    // if there is no such region, this is an unfixable fault
    //   (if this is a user thread, we now would signal it or kill it, but there are no user threads in Nautilus)
    //   if it's a kernel thread, the kernel should panic
    //   if it's within an interrupt handler, the kernel should panic

    nk_aspace_region_t** target_region_pt = NULL;
    if (lookupRegionByAddr(p, virtaddr, target_region_pt) != 0) {
        ERROR("No aspace region found for address %p\n", virtaddr);
        panic("No aspace region found, unfixable fault\n");
        return -1;
    }
    nk_aspace_region_t *target_region = *target_region_pt;

    // Is the problem that the page table entry is not present?
    // if so, drill the entry and then return from the function
    // so the faulting instruction can try agai
    //    This is the lazy construction of the page table entries
    uint64_t **entry = NULL;
    addr_t va_start = (addr_t)target_region->va_start;
    addr_t pa_start = (addr_t)target_region->pa_start;
    ph_pf_access_t access = getAccessFromProtection(target_region->protect);
    bool_t page_fault = 0;

    for (addr_t offset = 0; offset < target_region->len_bytes; offset += PAGE_SIZE_4KB) {
        if (paging_helper_walk(p->cr3, va_start + offset, access, entry) != 0) {
            paging_helper_drill(p->cr3, va_start + offset, pa_start + offset, access);
            page_fault = 1;
        }
    }

    if (page_fault == 1) {
        ASPACE_UNLOCK(p);
        return 0;
    }

    // Assuming the page table entry is present, check the region's
    // protections and compare to the error code

    // if the region has insufficient permissions for the request,
    // then this is an unfixable fault
    //   (if this is a user thread, we now would signal it or kill it, but there are no user threads in Nautilus)
    //   if it's a kernel thread, the kernel should panic
    //   if it's within an interrupt handler, the kernel should panic

    bool_t writePermissionOK = (target_region->protect.flags & NK_ASPACE_WRITE) >= error.write;
    bool_t userPermissionOK = true; // nautilus has no user mode
    bool_t execPermissionOK = (target_region->protect.flags & NK_ASPACE_EXEC) >= error.ifetch;
    if ( !(writePermissionOK && userPermissionOK && execPermissionOK) ) {
        ASPACE_UNLOCK(p);
        ERROR("Insufficient region permissions: address %p\n", virtaddr);
        panic("Insufficient region permissions, unfixable fault\n");
        return -1;
    }

    ASPACE_UNLOCK(p);
    
    return 0;
}
    
// called by the address space abstraction when it wants you
// to print out info about the address space.  detailed is
// nonzero if it wants a detailed output.  Use the nk_vc_printf()
// function to print here
static int print(void *state, int detailed)
{
    nk_aspace_paging_t *p = (nk_aspace_paging_t *)state;
    struct nk_thread *thread = get_cur_thread();
    

    // basic info
    nk_vc_printf("%s: paging address space [granularity 0x%lx alignment 0x%lx]\n"
		 "   CR3:    %016lx  CR4m: %016lx\n",
		 ASPACE_NAME(p), p->chars.granularity, p->chars.alignment, p->cr3.val, p->cr4);

    if (detailed) {
	// print region set data structure here

	// perhaps print out all the page tables here...
    }

    return 0;
}    

//
// This structure binds together your interface functions
// with the interface definition of the address space abstraction
// it will be used later in registering an address space
//
static nk_aspace_interface_t paging_interface = {
    .destroy = destroy,
    .add_thread = add_thread,
    .remove_thread = remove_thread,
    .add_region = add_region,
    .remove_region = remove_region,
    .protect_region = protect_region,
    .move_region = move_region,
    .switch_from = switch_from,
    .switch_to = switch_to,
    .exception = exception,
    .print = print
};


//
// The address space abstraction invokes this function when
// someone asks about your implementations characterstics
//
static int   get_characteristics(nk_aspace_characteristics_t *c)
{
    // you must support 4KB page granularity and alignment
    c->granularity = c->alignment = PAGE_SIZE_4KB;
    
    return 0;
}


//
// The address space abstraction invokes this function when
// someone wants to create a new paging address space with the given
// name and characteristics
//
static struct nk_aspace * create(char *name, nk_aspace_characteristics_t *c)
{
    struct naut_info *info = nk_get_nautilus_info();
    nk_aspace_paging_t *p;
    
    p = malloc(sizeof(*p));
    
    if (!p) {
	ERROR("cannot allocate paging aspace %s\n",name);
	return 0;
    }
  
    memset(p,0,sizeof(*p));
    
    spinlock_init(&p->lock);

    // initialize your region set data structure here!


    // create an initial top-level page table (PML4)
    if(paging_helper_create(&(p->cr3)) == -1){
	ERROR("unable create aspace cr3 in address space %s\n", name);
    }

    // note also the cr4 bits you should maintain
    p->cr4 = nk_paging_default_cr4() & CR4_MASK;


    // if we supported address spaces other than long mode
    // we would also manage the EFER register here

    // Register your new paging address space with the address space
    // space abstraction
    // the registration process returns a pointer to the abstract
    // address space that the rest of the system will use
    p->aspace = nk_aspace_register(name,
				   // we want both page faults and general protection faults
				   NK_ASPACE_HOOK_PF | NK_ASPACE_HOOK_GPF,
				   // our interface functions (see above)
				   &paging_interface,
				   // our state, which will be passed back
				   // whenever any of our interface functiosn are used
				   p);
    
    if (!p->aspace) {
	ERROR("Unable to register paging address space %s\n",name);
	return 0;
    }
    
    DEBUG("paging address space %s configured and initialized (returning %p)\n", name, p->aspace);
    
    // you are returning
    return p->aspace; 
}

//
// This structure binds together the interface functions of our
// implementation with the relevant interface definition
static nk_aspace_impl_t paging = {
				.impl_name = "paging",
				.get_characteristics = get_characteristics,
				.create = create,
};


// this does linker magic to populate a table of address space
// implementations by including this implementation
nk_aspace_register_impl(paging);


