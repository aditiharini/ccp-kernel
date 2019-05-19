#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

extern crate libc;
extern crate ioctls; 

use std::ffi::CString;
use std::mem;


static mut perf_fds: [libc::c_int; 4] = [0; 4];

unsafe extern "C" fn print_output(data: *mut libc::c_void, size: libc::c_int) -> bpf_perf_event_ret {
    struct Data {
        delivered: i32,
        rtt_us: i32,
        losses: i32,
        acked_sacked: u32,
    };
    let data_s = data as *mut Data;
    println!("delivered: {}", (*data_s).delivered);
    println!("rtt_us: {}", (*data_s).rtt_us);
    println!("losses: {}", (*data_s).losses);
    println!("acked_sacked: {}", (*data_s).acked_sacked);
    return bpf_perf_event_ret_LIBBPF_PERF_EVENT_CONT;
   
}

fn init() {
    unsafe {
        let _attr = perf_event_attr {
            type_: perf_type_id_PERF_TYPE_SOFTWARE,
            size: 0,
            config: perf_sw_ids_PERF_COUNT_SW_BPF_OUTPUT as u64,
            __bindgen_anon_1: perf_event_attr__bindgen_ty_1 {
                sample_period: 0
            },
            sample_type: perf_event_sample_format_PERF_SAMPLE_RAW as u64,
            read_format: 0,
            _bitfield_1: __BindgenBitfieldUnit::new([0, 0, 0, 0, 0, 0, 0, 0]),
            __bindgen_anon_2: perf_event_attr__bindgen_ty_2 {
                wakeup_events: 1 
            },
            bp_type: 0,
            __bindgen_anon_3: perf_event_attr__bindgen_ty_3 {
                bp_addr: 0
            },
            __bindgen_anon_4: perf_event_attr__bindgen_ty_4 {
                 bp_len: 0
            },
            branch_sample_type: 0,
            sample_regs_user: 0, 
            sample_stack_user: 0, 
            clockid: 0,
            sample_regs_intr: 0,
            aux_watermark: 0,
            sample_max_stack: 0,
            __reserved_2: 0,
        };
        for i in 0..4 {
            perf_fds[i] = libc::syscall(libc::SYS_perf_event_open, &_attr, -1, i, -1, 0) as libc::c_int;
            if perf_fds[i] < 0 {
                print!("fd init issue");
            }
            if bpf_map_update_elem(map_fd[0], &i as *const _ as *const _, &perf_fds[i] as *const _ as *const _, BPF_ANY as u64) != 0 {
                print!("map init issue");
            }
            ioctls::perf_event_ioc_enable(perf_fds[i]);
        }

    }
}

fn main() {
    unsafe {
        let filename = CString::new("../bpf/bpf_perf_kern.o").expect("CString::new failed");
        if load_bpf_file(filename.as_ptr() as *mut std::os::raw::c_char) != 0 {
            print!("couldn't load bpf file"); 
            return;
        }
        
        let cgrp_name = CString::new("/tmp/cgroupv2/foo").expect("CString::new failed");
        let cg_fd = libc::open(cgrp_name.as_ptr() as *mut std::os::raw::c_char, libc::O_DIRECTORY, libc::O_RDONLY);
        if cg_fd < 0 {
            print!("error init cgroup");
            return;
        }

        if bpf_prog_attach(prog_fd[0], cg_fd, bpf_attach_type_BPF_CGROUP_SOCK_OPS, 0) !=  0 {
            print!("prog attach failed"); 
            return;
        }
        
        init();

        let mut headers: [*mut perf_event_mmap_page; 4] = mem::uninitialized(); 

        println!("got to mmap");

        for i in 0..4 {
            if perf_event_mmap_header(perf_fds[i], &mut headers[i]) < 0 {
                print!("mmap error");
                return;
            }
        }

        println!("got to poll");
        perf_event_poller_multi(perf_fds.as_mut_ptr(), headers.as_mut_ptr(), 4, Option::from(print_output as unsafe extern "C" fn(*mut libc::c_void, i32) -> i32));


    }
}
