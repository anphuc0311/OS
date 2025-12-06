1.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, u32);   /* pid */
    __type(value, u64); /* remaining slice ns */
} task_slice SEC(".maps");
Nhiệm vụ: Map lưu trữ thời gian còn lại của một tiến trình được phục vụ. 
Giải thích chi tiết: 
    BPF_MAP_TYPE_HASH: Map dựa trên tìm kiểu dữ liệu kiểm hàm băm. 
    max_entries, 4096: Có tối đa 4096 task. 
    key: Khóa pid trên map của các tiến trình. 
    value: Giá trị biểu thị thời gian còn lại của tiến trình. 
Vai trò: Sử dụng trong mlfq_running để tính toán thời gian chạy để quyết định có demote tiến trình hay không. 

2. 
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, u32);   /* pid */
    __type(value, u32); /* queue level */
} task_queue SEC(".maps");
Nhiệm vụ: Lưu trữ các queue level mà các tác vụ được gán, xác định mức ưu tiên của nó. 
    value: Giá trị biểu thị mức ưu tiên của queue. 
Vai trò: Sử dụng trong mlfq_running để promote/demote cho các tác vụ 
         Trong các hàm điều phối dispatch, enqueue để biết các tác vụ thuộc hàng đợi nào? 

3.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, u32);   /* pid */
    __type(value, u64); /* start time ns */
} task_start_ns SEC(".maps");
Nhiệm vụ: Lưu trữ thời gian khi một tác vụ bắt đầu chạy trên CPU. 
    value: Thời gian hệ thống khi các tác vụ thực thi. 
Vai trò: Tính toán lượng thời gian các tác vụ chạy giữa 2 điểm thời gian. 

4. 
void BPF_STRUCT_OPS(mlfq_enable, struct task_struct *p,
                    struct scx_enable_args *args)
{
    bpf_printk("Task %s enabled in MLFQ", p->comm);
    u32 pid = p->pid;
    u64 slice = SLICE_NS[DSQ_HIGH];

    bpf_map_update_elem(&task_slice, &pid, &slice, BPF_ANY);
    u32 level = DSQ_HIGH;
    bpf_map_update_elem(&task_queue, &pid, &level, BPF_ANY);
}
Nhiệm vụ: Khởi tạo trạng thái ban đầu cho một tác vụ khi nó được thêm vào. 
Mục tiêu: Đảm bảo rằng mọi tác vụ mới được quản lý bởi MLFQ đều bắt đầu ở mức ưu tiên cao nhất
Giải thích chi tiết: 
    BPF_STRUCT_OPS: Là một Macro được sử dụng trong lập trình eBPF (extended Berkeley Packet Filter)
                    Chức năng: Khai báo và định nghĩa 1 hàm callaback cụ thể trong 1 tập hợp các hoạt động cấu trúc.
                    Struct Ops là một cơ chế trong Nhân Linux cho phép các module (ở đây là chương trình BPF) cung cấp các hàm thay thế (overridden functions) cho các thao tác chuẩn của hệ thống.            
    1. void BPF_STRUCT_OPS(mlfq_enable, struct task_struct *p,
       struct scx_enable_args *args): Khai báo hàm callback enable. Hàm này được  gọi khi hệ thống quyết định 1 tác vụ nên được chuyển sang quản lý bởi bộ lập lịch BPF này.
    u32 pid = p->pid: Lấy pid của tác vụ được thêm vào. 
    u64 slice = SLICE_NS[DSQ_HIGH]: Thiết lập giá trị thời gian slice ban đầu (mức priority cao nhất)
    bpf_map_update_elem(&task_slice, &pid, &slice, BPF_ANY): Lưu trữ thời gian slice  

1. 
void BPF_STRUCT_OPS(mlfq_dispatch, s32 cpu, struct task_struct *prev){
     for(int lvl = 0; lvl < NUM_DSQ; lvl++){
        if(scx_bpf_dsq_move_to_local(lvl))
            return; 
     }
}
Nhiệm vụ: Chạy điều phối hàng đợi MLFQ trong môi trường eBPF sử dụng MARCO BPF_STRUCT_OPS.
Mục tiêu: Đảm bảo CPU rảnh rỗi luôn tìm được tác vụ có mức ưu tiên cao nhất để chạy. 
Cơ chế hoạt động: 
- Kích hoạt callback dispatch:
    Gọi mlgq_dispatch.
- Duyệt qua các hàng đợi ưu tiên:
    for(int lvl = 0; lvl < NUM_DSQ; lvl++).
- Di chuyển các tác vụ: 
    if (scx_bpf_dsq_move_to_local(lvl))
    return;
        Nó cố gắng lấy tác vụ đầu tiên từ Hàng đợi Điều phối tùy chỉnh có ID là lvl.
        Nó di chuyển tác vụ đó đến Hàng đợi Điều phối Cục bộ (SCX_DSQ_LOCAL) của CPU đang gọi (tức là CPU cpu).
        Hàm này trả về true nếu việc di chuyển thành công (tức là tìm thấy và di chuyển được ít nhất một tác vụ).
Giải thích chi tiết: 
+ Khi một tác vụ trong hàng đợi thứ lvl tồn tại, scx_bpf_dsq_move_to_local sẽ chuyển tác vụ 
đầu tiên trên queue mức đó vào hàng đợi cục bộ của CPU (Chưa chọn hàng đợi cục bộ của CPU).
+ Nếu không có tác vụ nào trong queue thì return thoát ra hàm. 
