#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

extern crate perf;
extern crate libc;
use std::ffi::CString;

fn init() {
    unsafe {
        let attr = perf::ffi::perf_event_attr {
            sample_type: perf::ffi::perf_event_sample_format::PERF_SAMPLE_RAW,
            type_: perf::ffi::perf_type_id::PERF_TYPE_SOFTWARE,
            config1: perf::ffi::perf_sw_id::PERF_COUNT_SW_BPF_OUTPUT,
            wakeup: {wakeup_events: 1},
        };
    }
}

fn main() {
    unsafe {
        let filename = CString::new("../../bpf/bpf_perf_kern.o").expect("CString::new failed");
        load_bpf_file(filename.as_ptr() as *mut std::os::raw::c_char);
        
        let cgrp_name = CString::new("/tmp/cgroupv2/foo").expect("CString::new failed");
        let cg_fd = libc::open(cgrp_name.as_ptr() as *mut std::os::raw::c_char, libc::O_DIRECTORY, libc::O_RDONLY);

        bpf_prog_attach(prog_fd[0], cg_fd, bpf_attach_type_BPF_CGROUP_SOCK_OPS, 0);


    }
}
