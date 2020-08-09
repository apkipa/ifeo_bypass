//! This program can bypass image hijacks defined in Image File Execution Options.
//! It need not alter the system registry, with the NtCreateUserProcess hook.
//! Adapted from https://github.com/darfink/detour-rs/blob/master/examples/messageboxw_detour.rs
//! Requires Rust nightly.

extern crate winapi;
extern crate kernel32;
extern crate detour;

use detour::static_detour;
use kernel32::{GetModuleHandleW, GetProcAddress};
use std::error::Error;
use std::{ffi::CString, iter, mem};
use winapi::shared::minwindef::TRUE;
use winapi::um::winnt::ACCESS_MASK;
use winapi::shared::ntdef::{PHANDLE, POBJECT_ATTRIBUTES, ULONG, PVOID, NTSTATUS};
use ntapi::ntpsapi::{PPS_CREATE_INFO, PPS_ATTRIBUTE_LIST, PsCreateInitialState};

static_detour! {
  static NtCreateUserProcessHook: unsafe extern "system" fn(
    PHANDLE, PHANDLE,
    ACCESS_MASK, ACCESS_MASK,
    POBJECT_ATTRIBUTES, POBJECT_ATTRIBUTES,
    ULONG, ULONG,
    PVOID,
    PPS_CREATE_INFO,
    PPS_ATTRIBUTE_LIST
  ) -> NTSTATUS;
}

type FnNtCreateUserProcess = unsafe extern "system" fn(
  PHANDLE, PHANDLE,
  ACCESS_MASK, ACCESS_MASK,
  POBJECT_ATTRIBUTES, POBJECT_ATTRIBUTES,
  ULONG, ULONG,
  PVOID,
  PPS_CREATE_INFO,
  PPS_ATTRIBUTE_LIST
) -> NTSTATUS;

fn main() -> Result<(), Box<dyn Error>> {
  unsafe {
    let address = get_module_symbol_address("ntdll.dll", "NtCreateUserProcess")
      .expect("could not find 'NtCreateUserProcess' address");
    let target: FnNtCreateUserProcess = mem::transmute(address);

    NtCreateUserProcessHook
      .initialize(target, ntcreateuserprocess_detour)?
      .enable()?;
  }

  let args: Vec<String> = std::env::args().collect();

  let mut iterator = args.iter();
  iterator.next();
  iterator.next();

  std::process::Command::new(&args[1])
                        .args(iterator)
                        .spawn()
                        .unwrap();

  Ok(())
}

#[allow(non_snake_case)]
fn ntcreateuserprocess_detour(
  ProcessHandle: PHANDLE, 
  ThreadHandle: PHANDLE, 
  ProcessDesiredAccess: ACCESS_MASK, 
  ThreadDesiredAccess: ACCESS_MASK, 
  ProcessObjectAttributes: POBJECT_ATTRIBUTES, 
  ThreadObjectAttributes: POBJECT_ATTRIBUTES, 
  ProcessFlags: ULONG, 
  ThreadFlags: ULONG, 
  ProcessParameters: PVOID, 
  CreateInfo: PPS_CREATE_INFO, 
  AttributeList: PPS_ATTRIBUTE_LIST
) -> NTSTATUS {
  unsafe {
    if (*CreateInfo).State == PsCreateInitialState {
      (*CreateInfo).u.InitState.set_IFEOSkipDebugger(TRUE as ULONG);
    }

    NtCreateUserProcessHook.call(
      ProcessHandle,
      ThreadHandle,
      ProcessDesiredAccess,
      ThreadDesiredAccess,
      ProcessObjectAttributes,
      ThreadObjectAttributes,
      ProcessFlags,
      ThreadFlags,
      ProcessParameters,
      CreateInfo,
      AttributeList
    )
  }
}

/// Returns a module symbol's absolute address.
fn get_module_symbol_address(module: &str, symbol: &str) -> Option<usize> {
  let module = module
    .encode_utf16()
    .chain(iter::once(0))
    .collect::<Vec<u16>>();
  let symbol = CString::new(symbol).unwrap();
  unsafe {
    let handle = GetModuleHandleW(module.as_ptr());
    match GetProcAddress(handle, symbol.as_ptr()) as usize {
      0 => None,
      n => Some(n),
    }
  }
}
