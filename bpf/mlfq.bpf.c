#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "scx_common.bpf.h"

char LICENSE[] SEC("license") = "GPL";

#define DSQ_HIGEST 0
#define DSQ_HIGH 1
#define DSQ_MED 2 
#define DSQ_LOW 3 
#define NUM_DSQ 4 

const volatile u64 SLICE_NS[NUM_DSQ] = {
    1 * 1000 * 1000,
    2 * 1000 * 1000,
    4 * 1000 * 1000,
    8 * 1000 * 1000
};

//Slice tracking
/*
    Track remaining progress time 
*/
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u32);           // pid
    __type(value, u64);         // remaining slice ns
} task_slice SEC(".maps");

// Current queue tracking
/*
   Track the current priority of each process 
*/  
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u32);           // pid
    __type(value, u32);         // queue level
} task_queue SEC(".maps");

// Enable Callback: 
/*
    Load new task into queue
*/
void BPF_STRUCT_OPS(mlfq_enable, struct task_struct *p, struct scx_enable_args *args)
{
    pbf_printk("Task %s enabled in MLFQ",p->comm); 
    u32 pid = p->pid; 
    u64 slice = SLICE_NS[DSQ_HIGHEST]

    bpf_map_update_elem(&task_slice, &pid, &slice, BPF_ANY);
    u32 level = DSQ_HIGEST;
    bpf_map_update_elem(&task_queue, &pid, &level, PBF_ANY);  
}

// Enqueue Callback:
/*
    Lookup queue/slice of tasks in map 
*/
void BPF_STRUCT_OPS(mlfq_enqueue, struct task_struct *p, u64 enq_flag)
{
    u32 pid = p->pid; 
    u32 *level = bpf_map_lookup_elem(&task_queue, &pid); 
    u64 *slice = bpf_map_lookup_elem(&task_slice, &pid); 
    // when no have task in map now, init task to top queue
    if(!level ||!slice){
        u32 l = DSQ_HIGEST;
        bpf_map_update_elem(&task_queue, &pid, &l, BPF_ANY);
        u64 s = SLICE_NS[l]; 
        bpf_map_update_elem(&task_slice, &pid, &s, BPF_ANY); 
        level = &l;
        slice = &s; 
    }

    scx_bpf_dsq_insert(p, *level, *slice, emq_flags);   //Insert a task into DSQ (Dispatch Queue)
}
// Dispatch callback
/*
    Dispatch Queue from high to low
*/
void BPF_STRUCT_OPS(mlfq_dispatch, s32 cpu, struct task_struct *prev){
     for(int lvl = 0; lvl <NUM_DSQ; lvl++){
        if(scx_bpf_dsq_move_to_local(lvl))
            return; 
     }
}


struct sched_ext_ops mlfq_ops = {
    .enable   = (void *)mlfq_enable,
    .enqueue  = (void *)mlfq_enqueue,
    .dispatch = (void *)mlfq_dispatch,
    .running  = (void *)mlfq_running,
    .stopping = (void *)mlfq_stopping,
    .name     = "mlfq",
};