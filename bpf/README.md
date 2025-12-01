Giải thích code: 

1. Include các thư viên:

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "scx_common.bpf.h" 

- Các Include có sẵn trong kernel, khi build nạp vào PI chạy. 
- vmlinux.h sẽ build trên lệnh sh 

- vmlinux.h:
Đây là file auto-generated từ kernel với BTF (BPF Type Format).
Chứa định nghĩa tất cả các struct kernel mà BPF cần truy cập, ví dụ: struct task_struct.
Giúp chương trình eBPF có thể truy cập trực tiếp các field của task.

- bpf_helpers.h & bpf_tracing.h:
Chứa các hàm helper chuẩn của BPF như bpf_map_update_elem, bpf_printk, bpf_get_smp_processor_id, v.v.

- scx_common.bpf.h:
Helper riêng cho SCX sched_ext.
Ví dụ: scx_bpf_dsq_insert(), scx_bpf_dsq_move_to_local().

- mlfq.h:
Header bạn định nghĩa riêng, chứa các hằng số/struct MLFQ.

- License GPL:
Bắt buộc để kernel load BPF program.
2. Các queue:

#define DSQ_HIGEST 0
#define DSQ_HIGH 1
#define DSQ_MED 2 
#define DSQ_LOW 3 
#define NUM_DSQ 4 

Có 4 queue theo thứ tự priority

3. Time slice cho các queue:

const volatile u64 SLICE_NS[NUM_DSQ] = {
    1 * 1000 * 1000,
    2 * 1000 * 1000,
    4 * 1000 * 1000,
    8 * 1000 * 1000
};

4. Slice Tracking: 

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u32);           // pid
    __type(value, u64);         // remaining slice ns
} task_slice SEC(".maps");

- struct { ... } task_slice SEC(".maps"): Khai báo một cấu trúc ẩn danh mà trình biên dịch eBPF sẽ ánh xạ thành BPF Map trong kernel. task_slice là tên của map. SEC(".maps") là một chỉ thị để đặt cấu trúc này vào phần đặc biệt, báo hiệu cho công cụ eBPF biết đây là định nghĩa của một map.

- __uint(type, BPF_MAP_TYPE_HASH): Chỉ định rằng đây là một map thuộc loại BPF_MAP_TYPE_HASH. Đây là loại map phổ biến nhất, hoạt động như một bảng băm (hash table) để tra cứu nhanh.

- __uint(max_entries, 1024): Xác định rằng map này có thể lưu trữ tối đa 1024 cặp khóa-giá trị (key-value). Nếu số lượng tiến trình vượt quá giới hạn này, việc thêm mới sẽ không thành công.

- __type(key, u32): Khóa được sử dụng để tra cứu phần tử có kiểu là u32 (một số nguyên không dấu 32-bit). Trong ngữ cảnh lập lịch này, khóa (key) là PID (Process ID) của tiến trình.

- __type(value, u64): Giá trị được lưu trữ có kiểu là u64 (một số nguyên không dấu 64-bit). Giá trị này đại diện cho lát cắt thời gian còn lại (remaining slice), thường được tính bằng nanosecond (ns).

5.  bpf_map_update_elem:

- Là một hàm trong môi trường eBPF được sử dụng để thao tác với các BPF Map. 

int bpf_map_update_elem(void *map, const void *key, const void *value, __u64 flags);
    - Helper Function (Trong Chương trình eBPF) 💻
    - Vị trí: Nó là một "helper function" (hàm trợ giúp) mà bạn có thể gọi từ bên trong một chương trình eBPF đang chạy trong nhân (kernel) Linux.
    - Chức năng: Được sử dụng bởi chương trình eBPF để tạo mới (insert) hoặc cập nhật (update) một phần tử (cặp key/value) trong một BPF Map.

int bpf_map_update_elem(int fd, const void *key, const void *value, __u64 flags);
    - Userspace Library Function (Trong Userspace) 🖥️
    - Vị trí: Nó là một hàm nằm trong thư viện libbpf (hoặc một số thư viện eBPF userspace khác).
    - Chức năng: Được sử dụng bởi một ứng dụng userspace để tương tác với BPF Map thông qua syscall bpf() của Linux. Cụ thể, nó là một wrapper cấp thấp cho lệnh BPF_MAP_UPDATE_ELEM của syscall bpf.