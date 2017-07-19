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
void init_taint_structures(char* group_dir);

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
TAINTSIGN clear_flag_taint (uint32_t mask);

/* shift the taints of the bytes of a reg by shift num of bytes */
void shift_reg_taint_right(int reg, int shift);

// interface for different taint transfers
TAINTSIGN taint_mem2reg_offset(u_long mem_loc, int reg_off, uint32_t size);
TAINTSIGN taint_mem2reg_ext_offset(u_long mem_loc, int reg_off, uint32_t size);

TAINTSIGN taint_regreg2flag (uint32_t dst_reg, uint32_t src_reg, uint32_t mask, uint32_t size);

TAINTSIGN taint_regmem2flag (u_long mem_loc, uint32_t reg, uint32_t mask, uint32_t size);
TAINTSIGN taint_regmem2flag_pcmpxstri (uint32_t reg, u_long mem_loc2, uint32_t reg2, uint32_t size_reg, uint32_t size2, uint32_t implicit);
TAINTSIGN taint_regmem2flag_with_different_size (u_long mem_loc, uint32_t reg, uint32_t mask, uint32_t size_mem, uint32_t size_reg);
TAINTSIGN taint_memmem2flag (u_long mem_loc1, u_long mem_loc2, uint32_t mask, uint32_t size);
TAINTSIGN taint_mem2flag (u_long mem_loc, uint32_t mask, uint32_t size);
TAINTSIGN taint_reg2flag (uint32_t reg, uint32_t mask, uint32_t size, uint32_t is_upper8);
TAINTSIGN taint_flag2mem (u_long mem_loc, uint32_t mask, uint32_t size);
TAINTSIGN taint_flag2reg (uint32_t reg, uint32_t mask, uint32_t size);
TAINTSIGN taint_regflag2reg (uint32_t mask, uint32_t dst_reg, uint32_t src_reg, uint32_t size);
TAINTSIGN taint_memflag2reg (uint32_t mask, uint32_t dst_reg, u_long mem_loc, uint32_t size);
TAINTSIGN taint_merge_mem2reg (u_long mem_loc, int dst_reg, uint32_t size);
TAINTSIGN taint_merge_reg2reg (int dst_reg, int src_reg, uint32_t size);
 
TAINTSIGN taint_regflag2mem (uint32_t mask, u_long mem_loc, uint32_t src_reg, uint32_t size);
TAINTSIGN taint_jump (ADDRINT eflag, uint32_t flags, ADDRINT ip);
TAINTSIGN taint_jump_ecx (ADDRINT regvalue, uint32_t size, ADDRINT ip);
TAINTSIGN taint_rep (uint32_t flags, ADDRINT ip);
TAINTSIGN taint_string_operation (ADDRINT ip);
TAINTSIGN taint_rotate_mem (u_long mem_loc, uint32_t size, int is_count_reg);
TAINTSIGN taint_rotate_reg (int dstreg, uint32_t size, int is_count_reg);
TAINTSIGN taint_cmpxchg_reg (ADDRINT eax_value, UINT32 dst_value, int dst_reg, int src_reg, uint32_t size);
TAINTSIGN taint_cmpxchg_mem (ADDRINT eax_value, u_long mem_loc, int src_reg, uint32_t size) ;
TAINTSIGN debug_print_instr (ADDRINT ip, char* str);

#define BASE_INDEX_ARGS int base_reg, uint32_t base_reg_size, uint32_t base_reg_value, uint32_t base_reg_u8, int index_reg, uint32_t index_reg_size, uint32_t index_reg_value, uint32_t index_reg_u8

TAINTSIGN fw_slice_addressing (ADDRINT ip, 
		int base_reg, uint32_t base_reg_size, uint32_t base_reg_value, uint32_t base_reg_u8,
		int index_reg, uint32_t index_reg_size, uint32_t index_reg_value, uint32_t index_reg_u8,
		u_long mem_loc, uint32_t mem_size, uint32_t is_read);
TAINTSIGN fw_slice_addressing_repz (ADDRINT ip, uint32_t op_size);
TAINTSIGN fw_slice_addressing_check_two (ADDRINT ip, 
		int base_reg1, uint32_t base_reg_size1, uint32_t base_reg_value1, uint32_t base_reg1_u8, 
		int index_reg1, uint32_t index_reg_size1, uint32_t index_reg_value1, uint32_t index_reg1_u8, 
		u_long mem_loc1,uint32_t mem_size1, uint32_t is_read1, 
		int base_reg2, uint32_t base_reg_size2, uint32_t base_reg_value2, uint32_t base_reg2_u8, 
		int index_reg2, uint32_t index_reg_size2, uint32_t index_reg_value2, uint32_t index_reg2_u8,
		u_long mem_loc2, uint32_t mem_size2, uint32_t is_read2);
int fw_slice_check_final_mem_taint (taint_t* pregs);
TAINTINT fw_slice_reg (ADDRINT ip, char* ins_str, int reg, uint32_t size, u_long mem_loc, const CONTEXT* ctx, uint32_t reg_u8);
TAINTINT fw_slice_regreg (ADDRINT ip, char* ins_str, int orig_dst_reg, int orig_src_reg, uint32_t dst_regsize, uint32_t src_regsize, const CONTEXT* ctx,
		uint32_t dst_reg_u8, uint32_t src_reg_u8);

TAINTINT fw_slice_mem (ADDRINT ip, char* ins_str, u_long mem_loc, uint32_t size, u_long dst_mem_loc);
TAINTINT fw_slice_memmem (ADDRINT ip, char* ins_str, u_long mem_read, u_long mem_write, uint32_t mem_read_size, uint32_t mem_write_size);

TAINTINT fw_slice_memreg (ADDRINT ip, char* ins_str, int orig_reg, uint32_t reg_size, const CONTEXT* ctx, uint32_t reg_u8, u_long mem_loc, uint32_t mem_size);
TAINTINT fw_slice_memreg_imm_value (ADDRINT ip, char* ins_str, int reg, uint32_t reg_size, uint32_t regvalue, uint32_t reg_u8, u_long mem_loc, uint32_t mem_size);
TAINTINT fw_slice_memregreg (ADDRINT ip, char* ins_str, int reg1, uint32_t reg1_size, uint32_t reg1_value, uint32_t reg1_u8, 
		int reg2, uint32_t reg2_size, uint32_t reg2_value, uint32_t reg2_u8, u_long mem_loc, uint32_t mem_size);
TAINTINT fw_slice_flag (ADDRINT ip, char* ins_str, uint32_t mask, BOOL taken);
TAINTINT fw_slice_regregreg (ADDRINT ip, char* ins_str, int orig_dst_reg, int orig_src_reg, int orig_count_reg, 
		uint32_t dst_regsize, uint32_t src_regsize, uint32_t count_regsize, 
                const CONTEXT* ctx,
		uint32_t dst_reg_u8, uint32_t src_reg_u8, uint32_t count_reg_u8);
TAINTINT fw_slice_regflag (ADDRINT ip, char* ins_str, uint32_t mask, uint32_t orig_src_reg, uint32_t size, const CONTEXT* ctx, int32_t reg_u8);
TAINTINT fw_slice_pcmpistri_reg_reg (ADDRINT ip, char* ins_str, uint32_t reg1, uint32_t reg2, uint32_t reg1_size, uint32_t reg2_size, char* reg1_val, char* reg2_val);
TAINTINT fw_slice_pcmpistri_reg_mem (ADDRINT ip, char* ins_str, uint32_t reg1, u_long mem_loc2, uint32_t reg1_size, uint32_t mem_size, char* reg1_val);
TAINTSIGN fw_slice_regregflag_cmov (ADDRINT ip, char* ins_str, int orig_dest_reg, uint32_t size, const CONTEXT* ctx, uint32_t dest_reg_u8, int orig_src_reg, 
				    uint32_t src_reg_u8, uint32_t flag, BOOL executed);
TAINTSIGN fw_slice_memregregflag_cmov (ADDRINT ip, char* ins_str, int dest_reg, uint32_t dest_reg_size, PIN_REGISTER* dest_reg_value, uint32_t dest_reg_u8, BASE_INDEX_ARGS,
				       u_long mem_loc, uint32_t mem_size, uint32_t flag, BOOL executed);
TAINTSIGN fw_slice_memregreg_mov (ADDRINT ip, char* ins_str, int base_reg, uint32_t base_reg_size, uint32_t base_reg_value, uint32_t base_reg_u8,
				  int index_reg, uint32_t index_reg_size, uint32_t index_reg_value, uint32_t index_reg_u8, 
				  u_long mem_loc, uint32_t mem_size);
TAINTINT fw_slice_regregreg_mov (ADDRINT ip, char* ins_str, 
        int reg, uint32_t reg_size, PIN_REGISTER* regv_value, uint32_t reg_u8,
        int base_reg, uint32_t base_reg_size, uint32_t base_reg_value, uint32_t base_reg_u8,
        int index_reg, uint32_t index_reg_size, uint32_t index_reg_value, uint32_t index_reg_u8,
        u_long mem_loc, uint32_t mem_size);
TAINTINT fw_slice_memregregreg (ADDRINT ip, char* ins_str, int reg1, uint32_t reg1_size, uint32_t reg1_value, uint32_t reg1_u8, 
		int reg2, uint32_t reg2_size, uint32_t reg2_value, uint32_t reg2_u8,
		int reg3, uint32_t reg3_size, uint32_t reg3_value, uint32_t reg3_u8, u_long mem_loc, uint32_t mem_size);
TAINTINT fw_slice_memmemreg_imm_value (ADDRINT ip, char* ins_str, u_long mem_read, u_long mem_write, uint32_t mem_readsize, uint32_t mem_writesize, 
		int reg, uint32_t reg_size, uint32_t regvalue, uint32_t reg_u8);
TAINTSIGN fw_slice_mem2fpu(ADDRINT ip, char* ins_str, u_long mem_loc, uint32_t mem_size, BASE_INDEX_ARGS);

TAINTSIGN taint_wregwreg2wreg (int dst_reg, int base_reg, int index_reg);

TAINTSIGN taint_mix_cwde ();
TAINTSIGN taint_mix_reg_offset (int reg_off, uint32_t size, int set_flags, int clear_flags);
TAINTSIGN taint_mix_reg2reg_offset (int dst_off, uint32_t dst_size, int src_off, uint32_t src_size, int set_flags, int clear_flags);
TAINTSIGN taint_mix_regreg2reg_offset (int dst_off, uint32_t dst_size, int src1_off, uint32_t src1_size, int src2_off, uint32_t src2_size, 
				       int set_flags, int clear_flags);
TAINTSIGN taint_mix_mem (u_long mem_loc, uint32_t size, int set_flags, int clear_flags);
TAINTSIGN taint_mix_reg2mem_offset (u_long mem_loc, uint32_t memsize, int reg_off, uint32_t reg_size, int set_flags, int clear_flags);

TAINTSIGN taint_bswap_offset (int reg_off);

// mem2reg add
TAINTSIGN taint_add_mem2reg_offset (u_long mem_loc, int reg_off, uint32_t size, int set_flags, int clear_flags);
TAINTSIGN taint_add_reg2flag_offset (int reg_off, uint32_t size, uint32_t flag);

// mem2reg xchg
TAINTSIGN taint_xchg_bmem2lbreg (u_long mem_loc, int reg);
TAINTSIGN taint_xchg_bmem2ubreg (u_long mem_loc, int reg);
TAINTSIGN taint_xchg_hwmem2hwreg (u_long mem_loc, int reg);
TAINTSIGN taint_xchg_wmem2wreg (u_long mem_loc, int reg);
TAINTSIGN taint_xchg_dwmem2dwreg (u_long mem_loc, int reg);
TAINTSIGN taint_xchg_qwmem2qwreg( u_long mem_loc, int reg);

// reg2mem
TAINTSIGN taint_lbreg2mem (u_long mem_loc, int reg);
TAINTSIGN taint_ubreg2mem (u_long mem_loc, int reg);
TAINTSIGN taint_hwreg2mem (u_long mem_loc, int reg);
TAINTSIGN taint_wreg2mem (u_long mem_loc, int reg);
TAINTSIGN taint_dwreg2mem (u_long mem_loc, int reg);
TAINTSIGN taint_qwreg2mem (u_long mem_loc, int reg);

TAINTSIGN taint_lbreg2hwmem (u_long mem_loc, int reg);
TAINTSIGN taint_lbreg2wmem (u_long mem_loc, int reg);
TAINTSIGN taint_lbreg2dwmem (u_long mem_loc, int reg);
TAINTSIGN taint_lbreg2qwmem (u_long mem_loc, int reg);

TAINTSIGN taint_ubreg2hwmem (u_long mem_loc, int reg);
TAINTSIGN taint_ubreg2wmem (u_long mem_loc, int reg);
TAINTSIGN taint_ubreg2dwmem (u_long mem_loc, int reg);
TAINTSIGN taint_ubreg2qwmem (u_long mem_loc, int reg);

TAINTSIGN taint_hwreg2wmem (u_long mem_loc, int reg);
TAINTSIGN taint_hwreg2dwmem (u_long mem_loc, int reg);
TAINTSIGN taint_hwreg2qwmem (u_long mem_loc, int reg);

TAINTSIGN taint_wreg2dwmem (u_long mem_loc, int reg);
TAINTSIGN taint_wreg2qwmem (u_long mem_loc, int reg);

TAINTSIGN taint_dwreg2qwmem (u_long mem_loc, int reg);

// reg2mem extend
TAINTSIGN taintx_lbreg2hwmem (u_long mem_loc, int reg);
TAINTSIGN taintx_lbreg2wmem (u_long mem_loc, int reg);
TAINTSIGN taintx_lbreg2dwmem (u_long mem_loc, int reg);
TAINTSIGN taintx_lbreg2qwmem (u_long mem_loc, int reg);

TAINTSIGN taintx_ubreg2hwmem (u_long mem_loc, int reg);
TAINTSIGN taintx_ubreg2wmem (u_long mem_loc, int reg);
TAINTSIGN taintx_ubreg2dwmem (u_long mem_loc, int reg);
TAINTSIGN taintx_ubreg2qwmem (u_long mem_loc, int reg);

TAINTSIGN taintx_hwreg2wmem (u_long mem_loc, int reg);
TAINTSIGN taintx_hwreg2dwmem (u_long mem_loc, int reg);
TAINTSIGN taintx_hwreg2qwmem (u_long mem_loc, int reg);

TAINTSIGN taintx_wreg2dwmem (u_long mem_loc, int reg);
TAINTSIGN taintx_wreg2qwmem (u_long mem_loc, int reg);

TAINTSIGN taintx_dwreg2qwmem (u_long mem_loc, int reg);

// reg2mem add
TAINTSIGN taint_add_reg2mem_offset (u_long mem_loc, int reg_off, uint32_t size, int set_flags, int clear_flags);
void taint_rep_reg2mem (u_long mem_loc, int reg, uint32_t reg_size, uint32_t total_size);

// reg2reg
TAINTSIGN taint_reg2reg_offset (int dst_reg_off, int src_reg_off, uint32_t size);
TAINTSIGN taint_reg2reg_ext_offset (int dst_reg_off, int src_reg_off, uint32_t size);

// reg2reg extend
TAINTSIGN taintx_lbreg2wreg (int dst_reg, int src_reg);
TAINTSIGN taintx_lbreg2hwreg (int dst_reg, int src_reg);
TAINTSIGN taintx_lbreg2dwreg (int dst_reg, int src_reg);
TAINTSIGN taintx_lbreg2qwreg (int dst_reg, int src_reg);
TAINTSIGN taintx_ubreg2hwreg (int dst_reg, int src_reg);
TAINTSIGN taintx_ubreg2wreg (int dst_reg, int src_reg);
TAINTSIGN taintx_ubreg2dwreg (int dst_reg, int src_reg);
TAINTSIGN taintx_ubreg2qwreg (int dst_reg, int src_reg);
TAINTSIGN taintx_hwreg2wreg (int dst_reg, int src_reg);
TAINTSIGN taintx_hwreg2dwreg (int dst_reg, int src_reg);
TAINTSIGN taintx_hwreg2qwreg (int dst_reg, int src_reg);
TAINTSIGN taintx_wreg2dwreg (int dst_reg, int src_reg);
TAINTSIGN taintx_wreg2qwreg (int dst_reg, int src_reg);
TAINTSIGN taintx_dwreg2qwreg (int dst_reg, int src_reg);

// reg2reg add
TAINTSIGN taint_add_reg2reg_offset (int dst_reg_off, int src_reg_off, uint32_t size, int set_flags, int clear_flags);
TAINTSIGN taint_add_reg2esp (ADDRINT ip, int src_reg, uint32_t src_size, uint32_t src_value, uint32_t src_u8, int set_flags, int clear_flags);

// reg2reg xchg
TAINTSIGN taint_xchg_reg2reg_offset (int dst_reg_off, int src_reg_off, uint32_t size);

TAINTSIGN taint_mask_reg2reg (int dst_reg, int src_reg);

// mem2mem
TAINTSIGN taint_mem2mem (u_long src_loc, u_long dst_loc, uint32_t size);
TAINTSIGN taint_mem2mem_b (u_long src_loc, u_long dst_loc);
TAINTSIGN taint_mem2mem_hw (u_long src_loc, u_long dst_loc);
TAINTSIGN taint_mem2mem_w (u_long src_loc, u_long dst_loc);
TAINTSIGN taint_mem2mem_dw (u_long src_loc, u_long dst_loc);
TAINTSIGN taint_mem2mem_qw (u_long src_loc, u_long dst_loc);

// mem2mem add
TAINTSIGN taint_add_mem2mem_b (u_long src_loc, u_long dst_loc);
TAINTSIGN taint_add_mem2mem_hw (u_long src_loc, u_long dst_loc);
TAINTSIGN taint_add_mem2mem_w (u_long src_loc, u_long dst_loc);
TAINTSIGN taint_add_mem2mem_dw (u_long src_loc, u_long dst_loc);
TAINTSIGN taint_add_mem2mem_qw (u_long src_loc, u_long dst_loc);

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

// immval2mem
TAINTSIGN taint_immvalb2mem (u_long mem_loc);
TAINTSIGN taint_immvalhw2mem (u_long mem_loc);
TAINTSIGN taint_immvalw2mem (u_long mem_loc);
TAINTSIGN taint_immvaldw2mem (u_long mem_loc);
TAINTSIGN taint_immvalqw2mem (u_long mem_loc);

// immval2mem add
TAINTSIGN taint_clear_reg_offset (int offset, int size, int set_flags, int clear_flags);

// immval2reg
TAINTSIGN taint_immval2lbreg(int reg);
TAINTSIGN taint_immval2ubreg(int reg);
TAINTSIGN taint_immval2hwreg(int reg);
TAINTSIGN taint_immval2wreg(int reg);
TAINTSIGN taint_immval2dwreg(int reg);
TAINTSIGN taint_immval2qwreg(int reg);

// call
TAINTSIGN taint_call_near (u_long esp);
TAINTSIGN taint_call_far (u_long esp);

// Souce not affected, but need to update flags
TAINTSIGN taint_mem_set_clear_flags_offset (int reg_off, uint32_t size, int set_flags, int clear_flags);
TAINTSIGN taint_reg_set_clear_flags_offset (int reg_off, uint32_t size, int set_flags, int clear_flags);

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
TAINTSIGN fw_slice_string_scan (ADDRINT ip, char* ins_str, ADDRINT mem_loc, ADDRINT eflags, ADDRINT al_val, ADDRINT ecx_val, ADDRINT edi_val, uint32_t first_iter);
TAINTSIGN taint_string_scan (u_long mem_loc, uint32_t size, ADDRINT al_val, ADDRINT ecx_val, uint32_t first_iter);

// File descriptor taint-tracking
int add_taint_fd(int fd, int cloexec);
taint_t create_and_taint_fdset(int nfds, fd_set* fds);
int remove_taint_fd(int fd);
int remove_cloexec_taint_fds(void);
int is_fd_tainted(int fd);
void taint_mem2fd(u_long mem_loc, int fd);
/* Merge taints from mem_loc to mem_loc + size into one fd taint */
void taint_mem2fd_size(u_long mem_loc, uint32_t size, int fd);
void taint_reg2fd(int reg, int fd);
void taint_add_mem2fd(u_long mem_loc, int fd);
void taint_add_reg2fd(int reg, int fd);
void taint_fd2mem(u_long mem_loc, uint32_t size, int fd);
void taint_add_fd2mem(u_long mem_loc, uint32_t size, int fd);

/* So that we can check if syscall args are tainted */
int is_reg_arg_tainted (int reg, uint32_t size, uint32_t is_upper8);
int is_mem_arg_tainted (u_long mem_loc, uint32_t size);
int is_flag_tainted (uint32_t flag);
void add_modified_mem_for_final_check (u_long mem_loc, uint32_t size);

#ifdef __cplusplus
}
#endif

#endif
