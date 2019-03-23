#ifndef TAINT_INTERFACE_H
#define TAINT_INTERFACE_H

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/select.h>
#include "pin.H"
#include "taint.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef uint32_t option_t;
typedef uint8_t taintvalue_t;

#define MAX_NUM_OPTIONS 2147483648
#define MAX_TAINT_VALUE 1

#define TAINTSIGN void PIN_FAST_ANALYSIS_CALL
#define TAINTINT  int  PIN_FAST_ANALYSIS_CALL

#define REP_TYPE    0
#define REP_TYPE_E  1
#define REP_TYPE_NE 2

#define SPECIAL_VAL_NO_REP 99

/* Creates a new taint for a memory input */
taint_t create_and_taint_option (u_long mem_addr);

/* Get the taint value for an option in the taint structure t */
taintvalue_t get_taint_value (taint_t t, option_t option);

taintvalue_t get_max_taint_value(void);
int is_taint_zero(taint_t src);

/* Translate a register from the Pin representation
 *  E.g. translates AH to EAX
 * */
int translate_reg(int reg);

/* Init all structures required to for tainting.
 * Call this first before calling any taint function
 * */
void init_taint_structures(char* group_dir, const char* check_filename);

/* Any sort of cleanup goes here */
void taint_fini(void);

void finish_and_print_taint_stats(FILE* fp);
u_long get_num_merges();
u_long get_num_merges_saved();
taint_t* get_reg_taints(int reg);

/* Clear size bytes of the register. (starts from the LSB) */
void clear_reg (int reg, int size);
void set_syscall_retval_reg_value(int offset, taint_t value);

/* Set the taint of a memory address */
void taint_mem (u_long mem_loc, taint_t t);

/* Returns the taints for continuous series of memory addresses */
taint_t* get_mem_taints(u_long mem_loc, uint32_t size);
uint32_t get_cmem_taints(u_long mem_loc, uint32_t size, taint_t**);
void clear_mem_taints(u_long mem_loc, uint32_t size);
void move_mem_taints (u_long new_address, u_long new_size, u_long old_address, u_long old_size);
TAINTSIGN clear_flag_taint (uint32_t mask);

/* shift the taints of the bytes of a reg by shift num of bytes */
void shift_reg_taint_right(int reg, int shift);
#define TAINT_BASE_INDEX_ARGS uint32_t base_reg_off, uint32_t base_reg_size, uint32_t index_reg_off, uint32_t index_reg_size
// interface for different taint transfers
TAINTSIGN taint_mem2reg_offset(u_long mem_loc, uint32_t reg_off, uint32_t size, uint32_t base_reg_off, uint32_t base_reg_size, uint32_t index_reg_off, uint32_t index_reg_size);
TAINTSIGN taint_mem2reg_ext_offset(u_long mem_loc, uint32_t reg_off, uint32_t size, uint32_t base_reg_off, uint32_t base_reg_size, uint32_t index_reg_off, uint32_t index_reg_size);

TAINTSIGN taint_regreg2flag_offset (uint32_t dst_reg_off, uint32_t dst_reg_size, uint32_t src_reg_off, uint32_t src_reg_size, uint32_t set_flags, uint32_t clear_flags);

TAINTSIGN taint_regmem2flag (u_long mem_loc, uint32_t size_mem, uint32_t reg_off, uint32_t size_reg, uint32_t set_flags, uint32_t clear_flags);
TAINTSIGN taint_regmem2flag_pcmpxstri (uint32_t reg, u_long mem_loc2, uint32_t reg2, uint32_t size_reg, uint32_t size2, uint32_t implicit);
TAINTSIGN taint_memmem2flag (u_long mem_loc1, u_long mem_loc2, uint32_t mask, uint32_t size);
TAINTSIGN taint_mem2flag (u_long mem_loc, uint32_t size, uint32_t set_flags, uint32_t clear_flags, uint32_t base_reg_off, uint32_t base_reg_size, uint32_t index_reg_off, uint32_t index_reg_size);
TAINTSIGN taint_reg2flag_offset (uint32_t reg_off, uint32_t size, uint32_t set_flags, uint32_t clear_flags);
TAINTSIGN taint_flag2mem (u_long mem_loc, uint32_t mask, uint32_t size);
TAINTSIGN taint_flag2reg (uint32_t reg, uint32_t mask, uint32_t size);
TAINTSIGN taint_flag2regflags (uint32_t reg, uint32_t inmask, uint32_t size, uint32_t outmask);
TAINTSIGN taint_regflag2regflags (uint32_t reg, uint32_t inmask, uint32_t size, uint32_t outmask);
TAINTSIGN taint_regflag2reg (uint32_t mask, uint32_t dst_reg, uint32_t src_reg, uint32_t size);
TAINTSIGN taint_memflag2reg (uint32_t mask, uint32_t dst_reg, u_long mem_loc, uint32_t size);
TAINTSIGN taint_merge_reg2reg (int dst_reg, int src_reg, uint32_t size);
 
TAINTSIGN taint_regflag2mem (uint32_t mask, u_long mem_loc, uint32_t src_reg, uint32_t size);
TAINTSIGN taint_jump (ADDRINT eflag, uint32_t flags, ADDRINT ip);
TAINTSIGN taint_jump_ecx (ADDRINT regvalue, uint32_t size, ADDRINT ip);
TAINTSIGN taint_cmpxchg_reg (ADDRINT cmp_value, UINT32 dst_value, int dst_reg, int src_reg, uint32_t size);
TAINTSIGN taint_cmpxchg_mem (ADDRINT cmp_value, u_long mem_loc, int src_reg, uint32_t size);
TAINTSIGN debug_print_instr (ADDRINT ip, char* str);
extern struct thread_data* current_thread;

#define BASE_INDEX_ARGS int base_reg, uint32_t base_reg_size, uint32_t base_reg_value, uint32_t base_reg_u8, int index_reg, uint32_t index_reg_size, uint32_t index_reg_value, uint32_t index_reg_u8
#define BASE_INDEX_PARAMS base_reg,base_reg_size,base_reg_value,base_reg_u8,index_reg,index_reg_size,index_reg_value,index_reg_u8
TAINTSIGN ctrl_flow_print_inst_dest_mem (ADDRINT ip, u_long mem_loc, uint32_t size, BASE_INDEX_ARGS);
TAINTSIGN ctrl_flow_print_inst_dest_reg (ADDRINT ip, int reg, PIN_REGISTER* regvalue);
  TAINTSIGN monitor_merge_point (ADDRINT ip, char* ins_str, BOOL taken, const CONTEXT* ctx);
TAINTSIGN monitor_control_flow_tail (ADDRINT ip, char* str, BOOL taken, const CONTEXT* ctx);

int fw_slice_print_header (u_long recheck_group, struct thread_data* tdata, bool is_first_thread);
  void fw_slice_print_footer (struct thread_data* tdata, int is_ckpt_thread, long rc);


TAINTSIGN fw_slice_reg (ADDRINT ip, char* ins_str, int reg, uint32_t size, const PIN_REGISTER* regvalue, uint32_t reg_u8);
TAINTSIGN fw_slice_reg2mem (ADDRINT ip, char* ins_str, int reg, uint32_t size, const PIN_REGISTER* regvalue, uint32_t reg_u8, u_long mem_loc, uint32_t mem_size, BASE_INDEX_ARGS);
TAINTSIGN fw_slice_regreg (ADDRINT ip, char* ins_str, int dst_reg, uint32_t dst_regsize, const PIN_REGISTER* dst_regvalue, uint32_t dst_reg_u8, int src_reg, uint32_t src_regsize, const PIN_REGISTER* src_regvalue, uint32_t src_reg_u8);
TAINTSIGN fw_slice_regflag (ADDRINT ip, char* ins_str, int reg, uint32_t regsize, const PIN_REGISTER* regvalue, uint32_t reg_u8, uint32_t mask, uint32_t eflags);
TAINTSIGN fw_slice_regregflag (ADDRINT ip, char* ins_str, int dst_reg, uint32_t dst_regsize, const PIN_REGISTER* dst_regvalue, uint32_t dst_reg_u8, int src_reg, uint32_t src_regsize, const PIN_REGISTER* src_regvalue, uint32_t src_reg_u8, uint32_t mask, uint32_t eflags);
TAINTSIGN fw_slice_push_reg (ADDRINT ip, int reg, const PIN_REGISTER* regvalue, uint32_t reg_u8, u_long mem_loc, uint32_t size);
TAINTSIGN fw_slice_push_mem (ADDRINT ip, u_long src_mem_loc, u_long dst_mem_loc, uint32_t size, BASE_INDEX_ARGS);
TAINTSIGN fw_slice_pop_mem (ADDRINT ip, char* ins_str, u_long src_mem_loc, u_long dst_mem_loc, uint32_t mem_size, BASE_INDEX_ARGS);
TAINTSIGN fw_slice_pop_reg (ADDRINT ip, uint32_t reg, u_long mem_loc, uint32_t mem_size); 
TAINTSIGN fw_slice_mem (ADDRINT ip, char* ins_str, u_long mem_loc, uint32_t mem_size, BASE_INDEX_ARGS);
TAINTSIGN fw_slice_selfmem (ADDRINT ip, char* ins_str, u_long mem_loc, uint32_t mem_size, BASE_INDEX_ARGS);
TAINTSIGN fw_slice_memflag (ADDRINT ip, char* ins_str, u_long mem_loc, uint32_t mem_size, BASE_INDEX_ARGS, uint32_t mask, uint32_t eflags);
TAINTSIGN fw_slice_2mem (ADDRINT ip, char* ins_str, u_long mem_loc, uint32_t mem_size, BASE_INDEX_ARGS);
TAINTSIGN fw_slice_mem2mem (ADDRINT ip, char* ins_str, u_long mem_loc, uint32_t size, u_long dst_mem_loc, uint32_t dst_size, BASE_INDEX_ARGS);
TAINTSIGN fw_slice_memreg (ADDRINT ip, char* ins_str, int orig_reg, uint32_t reg_size, const PIN_REGISTER* reg_value, uint32_t reg_u8, u_long mem_loc, uint32_t mem_size, BASE_INDEX_ARGS);
TAINTSIGN fw_slice_memregreg (ADDRINT ip, char* ins_str, int reg1, uint32_t reg1_size, const PIN_REGISTER* reg1_value, uint32_t reg1_u8, 
			      int reg2, uint32_t reg2_size, const PIN_REGISTER* reg2_value, uint32_t reg2_u8, u_long mem_loc, uint32_t mem_size, BASE_INDEX_ARGS);
TAINTSIGN fw_slice_jmp_reg (ADDRINT ip, char* ins_str, uint32_t reg, uint32_t reg_size, uint32_t is_upper8, ADDRINT target);
TAINTSIGN fw_slice_jmp_mem (ADDRINT ip, char* ins_str, uint32_t mem_addr, uint32_t mem_size, ADDRINT target);
TAINTSIGN fw_slice_condjump (ADDRINT ip, char* ins_str, uint32_t mask, BOOL taken, ADDRINT target, const CONTEXT* ctx);
TAINTSIGN fw_slice_condregjump (ADDRINT ip, char* ins_str, int reg, uint32_t regsize, BOOL taken, ADDRINT target, const CONTEXT* ctx);
TAINTSIGN fw_slice_flag (ADDRINT ip, char* ins_str, uint32_t mask);
TAINTSIGN fw_slice_flag2mem (ADDRINT ip, char* ins_str, uint32_t mask, u_long mem_loc, uint32_t mem_size, BASE_INDEX_ARGS);
TAINTSIGN fw_slice_regregreg (ADDRINT ip, char* ins_str, int dst_reg, int src_reg, int count_reg, uint32_t dst_regsize, uint32_t src_regsize, uint32_t count_regsize, const PIN_REGISTER* dst_regvalue,
			      const PIN_REGISTER* src_regvalue, const PIN_REGISTER* count_regvalue, uint32_t dst_reg_u8, uint32_t src_reg_u8, uint32_t count_reg_u8);
TAINTINT fw_slice_pcmpistri_reg_reg (ADDRINT ip, char* ins_str, uint32_t reg1, uint32_t reg2, uint32_t reg1_size, uint32_t reg2_size, char* reg1_val, char* reg2_val);
TAINTINT fw_slice_pcmpistri_reg_mem (ADDRINT ip, char* ins_str, uint32_t reg1, u_long mem_loc2, uint32_t reg1_size, uint32_t mem_size, char* reg1_val);
TAINTSIGN fw_slice_regregflag_cmov (ADDRINT ip, char* ins_str, int dst_reg, uint32_t size, const PIN_REGISTER* dest_reg_value, uint32_t dest_reg_u8, int src_reg, const PIN_REGISTER* src_reg_value,
				    uint32_t src_reg_u8, uint32_t flag, BOOL executed);
TAINTSIGN fw_slice_regmemflag_cmov (ADDRINT ip, char* ins_str, int dest_reg, uint32_t dest_reg_size, PIN_REGISTER* dest_reg_value, uint32_t dest_reg_u8, u_long mem_loc, uint32_t mem_size, uint32_t flag, 
				    BOOL executed, BASE_INDEX_ARGS);
TAINTSIGN fw_slice_mem2fpu(ADDRINT ip, char* ins_str, u_long mem_loc, uint32_t mem_size, BASE_INDEX_ARGS);

TAINTSIGN taint_wregwreg2wreg (int dst_reg, int base_reg, int index_reg);

TAINTSIGN taint_mix_cwde ();
TAINTSIGN taint_mix_reg_offset (int reg_off, uint32_t size, uint32_t set_flags, uint32_t clear_flags);
TAINTSIGN taint_mix_reg2reg_offset (int dst_off, uint32_t dst_size, int src_off, uint32_t src_size, uint32_t set_flags, uint32_t clear_flags);
TAINTSIGN taint_mixmov_reg2reg_offset (int dst_off, uint32_t dst_size, int src_off, uint32_t src_size, uint32_t set_flags, uint32_t clear_flags);
TAINTSIGN taint_mix_regreg2reg_offset (int dst_off, uint32_t dst_size, int src1_off, uint32_t src1_size, int src2_off, uint32_t src2_size, 
				       uint32_t set_flags, uint32_t clear_flags);
TAINTSIGN taint_mix_mem (u_long mem_loc, uint32_t size, uint32_t set_flags, uint32_t clear_flags, uint32_t base_reg_off, uint32_t base_reg_size, uint32_t index_reg_off, uint32_t index_reg_size);
TAINTSIGN taint_mix_mem2reg (u_long mem_loc, uint32_t size, int dst_reg_off, uint32_t dst_size, uint32_t set_flags, uint32_t clear_flags, uint32_t base_reg_off, uint32_t base_reg_size, uint32_t index_reg_off, uint32_t index_reg_size);
TAINTSIGN taint_mix_reg2mem_offset (u_long mem_loc, uint32_t memsize, int reg_off, uint32_t reg_size, uint32_t set_flags, uint32_t clear_flags);

TAINTSIGN taint_bswap_offset (int reg_off);

// mem2reg add
TAINTSIGN taint_add_mem2reg_offset (u_long mem_loc, int reg_off, uint32_t size, uint32_t set_flags, uint32_t clear_flags, uint32_t base_reg_off, uint32_t base_reg_size, uint32_t index_reg_off, uint32_t index_reg_size);

TAINTSIGN taint_xchg_memreg (u_long mem_loc, uint32_t reg_off, uint32_t size);

// reg2mem
TAINTSIGN taint_reg2mem_offset (u_long mem_loc, uint32_t reg_off, uint32_t size);
TAINTSIGN taint_reg2mem_ext_offset (u_long mem_loc, uint32_t mem_size, uint32_t reg_off, uint32_t reg_size);

// reg2mem add
TAINTSIGN taint_add_reg2mem_offset (u_long mem_loc, int reg_off, uint32_t size, uint32_t set_flags, uint32_t clear_flags);

// reg2reg
TAINTSIGN taint_reg2reg_offset (int dst_reg_off, int src_reg_off, uint32_t size);
TAINTSIGN taint_reg2reg_ext_offset (int dst_reg_off, int src_reg_off, uint32_t size);

// reg2reg add
TAINTSIGN taint_add_reg2reg_offset (int dst_reg_off, int src_reg_off, uint32_t size, uint32_t set_flags, uint32_t clear_flags);
TAINTSIGN taint_add_reg2esp (ADDRINT ip, int src_reg, uint32_t src_size, uint32_t src_value, uint32_t src_u8, uint32_t set_flags, uint32_t clear_flags);
TAINTSIGN taint_add_regflag2reg_offset (int dst_reg_off, int src_reg_off, uint32_t size, uint32_t mask, uint32_t set_flags, uint32_t clear_flags);

// reg2reg xchg
TAINTSIGN taint_xchg_reg2reg_offset (int dst_reg_off, int src_reg_off, uint32_t size);

TAINTSIGN taint_mask_reg2reg (int dst_reg, int src_reg);

// mem2mem
TAINTSIGN taint_mem2mem (u_long src_loc, u_long dst_loc, uint32_t size);

TAINTSIGN taint_memflag2memflags (u_long mem_loc, uint32_t size, uint32_t mask, uint32_t set_flags, uint32_t clear_flags, uint32_t base_reg_off, uint32_t base_reg_size, uint32_t index_reg_off, uint32_t index_reg_size);

// 3-way operations (for supporting instructions like mul and div)
TAINTSIGN taint_add2_bmemlbreg_hwreg (u_long mem_loc, int src_reg, int dst_reg);
TAINTSIGN taint_add2_hwmemhwreg_2hwreg (u_long mem_loc, int src_reg,
                                    int dst_reg1, int dst_reg2);
TAINTSIGN taint_add2_wmemwreg_2wreg (u_long mem_loc, int src_reg,
                                    int dst_reg1, int dst_reg2);
TAINTSIGN taint_add2_lbreglbreg_hwreg (int src_reg1, int src_reg2, int dst_reg);
TAINTSIGN taint_add2_hwreghwreg_2hwreg (int src_reg1, int src_reg2,
                                    int dst_reg1, int dst_reg2);
TAINTSIGN taint_add2_wregwreg_2wreg (int src_reg1, int src_reg2,
                                    int dst_reg1, int dst_reg2);


TAINTSIGN taint_add2_hwmemhwreg_2breg (u_long mem_loc,
                                    int src_reg, int dst_reg1, int dst_reg2);
TAINTSIGN taint_add3_mem2reg_2reg (u_long mem_loc, int src_reg1, int src_reg2, int dst_reg1, int dst_reg2, int size);

TAINTSIGN taint_add2_hwregbreg_2breg (int src_reg1, int src_reg2,
				      int dst_reg1, int dst_reg2);
TAINTSIGN taint_add2_2hwreg_2breg (int src_reg1, int src_reg2,
                                int dst_reg1, int dst_reg2);
TAINTSIGN taint_add3_2hwreg_2hwreg (int src_reg1, int src_reg2, int src_reg3,
                                    int dst_reg1, int dst_reg2);
TAINTSIGN taint_add3_2wreg_2wreg (int src_reg1, int src_reg2, int src_reg3,
                                    int dst_reg1, int dst_reg2);
TAINTSIGN taint_immval2mem (ADDRINT ip, u_long mem_loc, uint32_t size, int base_reg_off, uint32_t base_reg_size, int index_reg_off, uint32_t index_reg_size);
TAINTSIGN taint_clear_reg_offset (int offset, int size, uint32_t set_flags, uint32_t clear_flags);

// call
TAINTSIGN taint_call_near (u_long esp);
TAINTSIGN taint_call_far (u_long esp);

// TODO need to do transfers to and from flags
TAINTSIGN taint_immval2flag();

// Ugh, weird XMM instructions that we need to support
TAINTSIGN taint_palignr_mem2dwreg(int reg, u_long mem_loc, int imm);
TAINTSIGN taint_palignr_mem2qwreg(int reg, u_long mem_loc, int imm);
TAINTSIGN taint_palignr_dwreg2dwreg(int dst_reg, int src_reg, int imm);
TAINTSIGN taint_palignr_qwreg2qwreg(int dst_reg, int src_reg, int imm);

TAINTSIGN taint_popfd (u_long mem_loc, uint32_t size);
TAINTSIGN taint_pushfd (u_long mem_loc, uint32_t size);

TAINTSIGN taint_cmov_mem2reg (uint32_t mask, uint32_t dst_reg, u_long mem_loc, uint32_t size, BOOL executed);
TAINTSIGN taint_cmov_reg2reg (uint32_t mask, uint32_t dst_reg, uint32_t src_reg, uint32_t size, BOOL executed);

// JNF: Updated for partial taint and verification
TAINTSIGN fw_slice_string_move (ADDRINT ip, char* ins_str, ADDRINT src_mem_loc, ADDRINT dst_mem_loc, ADDRINT eflags, ADDRINT ecx_val, ADDRINT edi_val, ADDRINT esi_val, UINT32 op_size, uint32_t first_iter);
TAINTSIGN fw_slice_string_scan (ADDRINT ip, char* ins_str, ADDRINT mem_loc, ADDRINT eflags, ADDRINT al_val, ADDRINT ecx_val, ADDRINT edi_val, uint32_t first_iter, UINT32 rep_type);
TAINTSIGN fw_slice_string_compare (ADDRINT ip, char* ins_str, ADDRINT mem_loc1, ADDRINT mem_loc2, ADDRINT eflags, ADDRINT ecx_val, ADDRINT edi_val, ADDRINT esi_val, UINT32 op_size, uint32_t first_iter);
TAINTSIGN fw_slice_string_store (ADDRINT ip, char* ins_str, ADDRINT dst_mem_loc, ADDRINT eflags, const PIN_REGISTER* eax_val, ADDRINT ecx_val, ADDRINT edi_val, UINT32 op_size, uint32_t first_iter);
TAINTSIGN taint_string_scan (u_long mem_loc, ADDRINT al_val, ADDRINT ecx_val, uint32_t first_iter, uint32_t rep_type);
TAINTSIGN taint_string_move (u_long src_mem_loc, u_long dst_mem_loc, uint32_t op_size, ADDRINT ecx_val, uint32_t first_iter);
TAINTSIGN taint_string_compare (u_long mem_loc1, u_long mem_loc2, ADDRINT ecx_val, uint32_t first_iter);
TAINTSIGN taint_string_store (u_long dst_mem_loc, uint32_t op_size, ADDRINT ecx_val, uint32_t first_iter);

/* So that we can check if syscall args are tainted */
int is_reg_arg_tainted (int reg, uint32_t size, uint32_t is_upper8);
int is_mem_arg_tainted (u_long mem_loc, uint32_t size);
int is_flag_tainted (uint32_t flag);
void add_modified_mem_for_final_check (u_long mem_loc, uint32_t size);
  void remove_modified_mem_for_final_check (u_long mem_loc, u_long size);

int check_is_syscall_ignored (int pid, u_long index);
int check_is_syscall_padded (int pid, u_long index, struct syscall_padding_entry*);

TAINTSIGN fw_slice_fpu_cmov (ADDRINT ip, char* ins_str, int dst_reg, uint32_t dst_regsize, int src_reg, uint32_t src_regsize, const CONTEXT* ctx, uint32_t flags, BOOL executed);
TAINTSIGN fw_slice_fpureg (ADDRINT ip, char* ins_str, int reg, uint32_t size, const CONTEXT* ctx, uint32_t reg_u8, uint32_t fp_stack_change);
TAINTSIGN fw_slice_fpuregfpureg (ADDRINT ip, char* ins_str, int dst_reg, uint32_t dst_regsize,  uint32_t dst_reg_u8, int src_reg, uint32_t src_regsize, const CONTEXT* ctx, uint32_t src_reg_u8, uint32_t fp_stack_change);
TAINTSIGN fw_slice_memfpureg (ADDRINT ip, char* ins_str, int reg, uint32_t reg_size, const CONTEXT* ctx, uint32_t reg_u8, u_long mem_loc, uint32_t mem_size, uint32_t fp_stack_change, BASE_INDEX_ARGS);
TAINTSIGN fw_slice_mem2fpureg (ADDRINT ip, char* ins_str, u_long mem_loc, uint32_t mem_size, const CONTEXT* ctx, uint32_t fp_stack_change, BASE_INDEX_ARGS) ;
TAINTSIGN fw_slice_fpureg2mem (ADDRINT ip, char* ins_str, int reg, uint32_t size, const CONTEXT* ctx, uint32_t reg_u8, u_long mem_loc, uint32_t mem_size, uint32_t fp_stack_change, BASE_INDEX_ARGS);
TAINTSIGN fw_slice_track_fp_stack_top (ADDRINT ip, const CONTEXT* ctx);
TAINTSIGN taint_fpureg2fpureg (int dst_reg, int src_reg, uint32_t size, const CONTEXT* ctx, uint32_t opcode);
TAINTSIGN taint_fpu_cmov (int dst_oreg, int src_oreg, uint32_t size, const CONTEXT* ctx, uint32_t mask, BOOL executed);
TAINTSIGN taint_mem2fpureg_offset(u_long mem_loc, uint32_t reg_off, uint32_t size, uint32_t base_reg_off, uint32_t base_reg_size, uint32_t index_reg_off, uint32_t index_reg_size, const CONTEXT* ctx);
TAINTSIGN taint_clear_fpureg_offset (int offset, int size, uint32_t set_flags, uint32_t clear_flags, const CONTEXT* ctx, uint32_t is_load);
TAINTSIGN taint_mix_fpureg (int reg, uint32_t reg_size, const CONTEXT* ctx);
TAINTSIGN taint_mix_fpureg2mem (u_long mem_loc, uint32_t mem_size, int reg, uint32_t reg_size,  const CONTEXT* ctx);
TAINTSIGN taint_mix_fpuregmem2fpureg (u_long mem_loc, uint32_t memsize, int src_reg, uint32_t src_regsize, int dst_reg, uint32_t dst_regsize, const CONTEXT* ctx, TAINT_BASE_INDEX_ARGS);
TAINTSIGN taint_mix_fpureg2fpureg (int dst_reg, uint32_t dst_size, int src_reg, uint32_t src_size, const CONTEXT* ctx);
TAINTSIGN taint_xchg_fpureg2fpureg (int dst_reg, int src_reg, uint32_t size, const CONTEXT* ctx);
TAINTSIGN taint_load_mem2fpureg_offset(u_long mem_loc, uint32_t reg_off, uint32_t size, uint32_t base_reg_off, uint32_t base_reg_size, uint32_t index_reg_off, uint32_t index_reg_size, const CONTEXT* ctx);
TAINTSIGN taint_fpuregfpureg2flag (int reg1, int reg2, uint32_t size, const CONTEXT* ctx, uint32_t set_flags, uint32_t clear_flags);
TAINTSIGN taint_ldmxcsr_check (u_long mem_loc);

int fw_slice_rotate_file (struct thread_data* tdata);
TAINTSIGN fw_slice_fpu_incstp (ADDRINT ip, char* ins_str, const CONTEXT* ctx);

// For managing reads/writes to shared memory
void add_shared_memory (u_long start, u_long size);
int count_mem_taints();

TAINTSIGN log_inst_reg1 (ADDRINT ip, int read, int reg, int regoff, int size, PIN_REGISTER* reg_value) ;
TAINTSIGN log_inst_reg2 (ADDRINT ip, int read, int reg1, int regoff1, int size1, PIN_REGISTER* reg_value1, int reg2, int regoff2, int size2, PIN_REGISTER* reg_value2) ;
TAINTSIGN log_inst_reg3 (ADDRINT ip, int read, int reg1, int regoff1, int size1, PIN_REGISTER* reg_value1, int reg2, int regoff2, int size2, PIN_REGISTER* reg_value2, int reg3, int regoff3, int size3, PIN_REGISTER* reg_value3) ;
TAINTSIGN log_inst_reg4 (ADDRINT ip, int read, int reg1, int regoff1, int size1, PIN_REGISTER* reg_value1, int reg2, int regoff2, int size2, PIN_REGISTER* reg_value2, int reg3, int regoff3,int size3,  PIN_REGISTER* reg_value3, int reg4, int regoff4, int size4, PIN_REGISTER* reg_value4) ;
TAINTSIGN log_inst_reg5 (ADDRINT ip, int read, int reg1, int regoff1, int size1, PIN_REGISTER* reg_value1, int reg2, int regoff2, int size2, PIN_REGISTER* reg_value2, int reg3, int regoff3, int size3,  PIN_REGISTER* reg_value3, int reg4, int regoff4, int size4, PIN_REGISTER* reg_value4, int reg5, int regoff5, int size5, PIN_REGISTER* reg_value5) ;
TAINTSIGN log_inst_src_mem1 (ADDRINT ip, u_long mem_loc, uint32_t size);
TAINTSIGN log_inst_src_mem2 (ADDRINT ip, u_long mem_loc1, u_long mem_loc2, uint32_t size);
TAINTSIGN log_inst_dest_mem (ADDRINT ip, u_long mem_loc, uint32_t size);
#ifdef __cplusplus
}
#endif

#endif
