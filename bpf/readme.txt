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