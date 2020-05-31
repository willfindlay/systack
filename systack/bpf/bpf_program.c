#define STACK_LIMIT 102400

BPF_PERF_OUTPUT(on_syscall);

BPF_STACK_TRACE(user_stack, STACK_LIMIT);

struct event {
    int syscall;
    int trace_id;
};

TRACEPOINT_PROBE(raw_syscalls, sys_enter) {
    u32 pid = bpf_get_current_pid_tgid();
    if (pid != PID)
        return 0;

    struct event event = {};
    event.syscall = args->id;
    //event.trace_id = user_stack.get_stackid((void *)args, BPF_F_USER_STACK | BPF_F_REUSE_STACKID);
    event.trace_id = user_stack.get_stackid((void *)args, BPF_F_USER_STACK);

    on_syscall.perf_submit((void *)args, &event, sizeof(event));

    return 0;
}
