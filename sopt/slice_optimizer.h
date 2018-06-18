#include <iostream>
#include <stdlib.h>
#include <vector>
#include <boost/numeric/ublas/vector.hpp>
//#include <boost/numeric/ublas/io.hpp>
#include <map>
#include <algorithm> 
#include <cctype>
#include <locale>
#include <sstream>
#include <iomanip>

#define NUM_REGS 120
#define REG_SIZE 16

// flag register (status) 
#define NUM_FLAGS 7

//These are only flags, not corresponding to the actual hardware mask
//The actual flag register taints are layed out according to these FLAGs instead of the actual hardware layouts
//powers of 2
#define CF_FLAG 0x01
#define PF_FLAG 0x02
#define AF_FLAG 0x04
#define ZF_FLAG 0x08
#define SF_FLAG 0x10
#define OF_FLAG 0x20
#define DF_FLAG 0x40
#define ALL_FLAGS 0x7f

#define CF_INDEX 0
#define PF_INDEX 1
#define AF_INDEX 2
#define ZF_INDEX 3
#define SF_INDEX 4
#define OF_INDEX 5
#define DF_INDEX 6

struct Edge;

//A Node represents an instruction, such as "mov EAX, 20" by its line number in the assembly exslice1.c file
//A Node has a vector of input Edges and a vector of output Edges
//The bool extra flag is for the 'mark and sweep' tracing garbage collection to remove unnecessary slice instructions. If the node is marked as extra, then it is extraneous and unnecessary, so we can remove the instruction from the slice.
struct Node {
	int lineNum;
	std::vector<Edge*> inEdges;
	std::vector<Edge*> outEdges;
	int extra;
};

//An Edge represents the data-flow relationship between two Nodes (asm instructions) in our graph. Each edge has a pointer to its origin Node and a pointer to its destination Node.
//We have a boolean taint flag to keep track of the tainted inputs into our instructions.
struct Edge {
	Node* start;
	Node* finish;
	int taint;
};

//The directed acyclic Graph of instructions is represented by a vector of Nodes.
struct instrGraph {
	std::vector<Node*> nodes;
	//boost::numeric::ublas::vector<Node*> nodes;
};

std::vector<Node*> shadow_reg_table(NUM_REGS * REG_SIZE);

//The memory state of our slice is represented by a map of 4byte addresses (ulongs) and the Node that most recently affected the memory location at that address.
std::map<u_long, Node*> mapMem;


//The 32-bit EFLAGS register is represented as a vector of nodes that most recently affected each byte of the EFLAGS register.
//We have an explicit way to modify certain flag bits such as the "CF, Carry Flag" that is the first 0 bit of the EFLAGS register.  
std::vector<Node*> eflags_table(NUM_FLAGS);

std::pair<int, int> checkForRegs(std::string instOperand);

std::map<std::string, std::pair<const int, const int> > regToNumSize = {
	{"edi", {3,4}},
	{"di", {3,2}},
	{"esi", {4,4}},
	{"si", {4,2}},
	{"ebp", {5,4}},
	{"bp", {5,2}},
	{"esp", {6,4}},
	{"sp", {6,2}},
	{"ebx", {7,4}},
	{"bx", {7,2}},
	{"bl", {7,1}},
	{"bh", {7,-1}},
	{"edx", {8,4}},
	{"dx", {8,2}},
	{"dl", {8,1}},
	{"dh", {8,-1}},
	{"ecx", {9,4}},
	{"cx", {9,2}},
	{"cl", {9,1}},
	{"ch", {9,-1}},
	{"eax", {10,4}},
	{"ax", {10,2}},
	{"al", {10,1}},
	{"ah", {10,-1}},
	{"eflags", {17,4}},
	{"xmm0", {54,16}},
	{"xmm1", {55,16}},
	{"xmm2", {56,16}},
	{"xmm3", {57,16}},
	{"xmm4", {58,16}},
	{"xmm5", {59,16}},
	{"xmm6", {60,16}},
	{"xmm7", {61,16}},
};

//byte = 8 bits 
//word = 2 bytes = 16 bits  
//double word = 4 bytes = 32 bits
//xmm word = 16 bytes = 144 bits
std::map<std::string, const int > strSizeToByte = {
	{"byte", 1},
	{"word", 2},
	{"dword", 4},
	{"xmmword", 16},
};

//Instructions that follow a similar dataflow to the 'add' instruction
std::set<std::string> addLikeInstr = {
	"add",
	"sub",
	"adc",
};

//map from cmov instruction mnemonic to the instr's flag srcs
std::map<std::string, std::vector<std::string> > cmovToFlags = {
	{"cmovbe", {"CF","ZF"}},
	{"cmovnbe", {"CF","ZF"}},
	{"cmovz", {"ZF"}},
	{"cmovnz", {"ZF"}},
	{"cmovb", {"CF"}},
	{"cmovnb", {"CF"}},
	{"cmovs", {"SF"}},
	{"cmovns", {"SF"}},
	{"cmovnle", {"ZF","SF", "OF"}},
	{"cmovle", {"ZF","SF", "OF"}},
	{"cmovl", {"SF","OF"}},
	{"cmovnl", {"SF","OF"}},
};

/// Enum for String values we want to switch on
enum class InstType
{
	cmovbe,
	cmovnbe,
	cmovz,
	cmovnz,
	cmovb,
	cmovnb,
	cmovs,
	cmovns,
	cmovnle,
	cmovle,
	cmovl,
	cmovnl,
	xchg,
	xadd,
	Zand,
    Zor,
    Zxor,
    add,
    sub,
    adc,
    mov,
    div,
    idiv,
    mul,
    imul,
    cmp,
    GetType
};

/// Map from strings to enum values
std::map<std::string, InstType> mapStringToInstType =
{
	{ "cmovbe", InstType::cmovbe },
	{ "cmovnbe", InstType::cmovnbe },
	{ "cmovz", InstType::cmovz },
	{ "cmovnz", InstType::cmovnz },
	{ "cmovb", InstType::cmovb },
	{ "cmovnb", InstType::cmovnb },
	{ "cmovs", InstType::cmovs },
	{ "cmovns", InstType::cmovns },
	{ "cmovnle", InstType::cmovnle },
	{ "cmovle", InstType::cmovle },
	{ "cmovl", InstType::cmovl },
	{ "cmovnl", InstType::cmovnl },
	{ "xchg", InstType::xchg },
	{ "xadd", InstType::xadd },
	{ "and", InstType::Zand },
    { "or", InstType::Zor },
    { "xor", InstType::Zxor },
    { "add", InstType::add },
    { "sub", InstType::sub },
    { "adc", InstType::adc },
    { "mov", InstType::mov },
    { "div", InstType::div },
    { "idiv", InstType::idiv },
    { "mul", InstType::mul },
    { "imul", InstType::imul },
    { "cmp", InstType::cmp },
};

/// Map from enum values to strings
std::map<InstType, std::string> mapInstTypeToString = 
{
	{InstType::cmovbe , "cmovbe"},
	{InstType::cmovnbe , "cmovnbe"},
	{InstType::cmovz , "cmovz"},
	{InstType::cmovnz , "cmovnz"},
	{InstType::cmovb , "cmovb"},
	{InstType::cmovnb , "cmovnb"},
	{InstType::cmovs , "cmovs"},
	{InstType::cmovns , "cmovns"},
	{InstType::cmovnle , "cmovnle"},
	{InstType::cmovle , "cmovle"},
	{InstType::cmovl , "cmovl"},
	{InstType::cmovnl , "cmovnl"},
	{InstType::xchg , "xchg"},
	{InstType::xadd , "xadd"},  
	{InstType::Zand , "and"}, 
    {InstType::Zor , "or"}, 
    {InstType::Zxor , "xor"},
    {InstType::add , "add"}, 
    {InstType::sub , "sub"}, 
    {InstType::adc , "adc"}, 
    {InstType::mov , "mov"},
    {InstType::div , "div"}, 
    {InstType::idiv , "idiv"}, 
    {InstType::mul , "mul"}, 
    {InstType::imul , "imul"},
    {InstType::cmp , "cmp"},  
};

void clear_reg (int reg, int size);
void set_reg (int reg, int size, Node* author);
void set_src_reg(std::pair<int, int> srcRegNumSize, Node* p_tempNode);
std::pair<int, int> checkForRegs(std::string instOperand);
std::string getStringWithinBrackets(std::string wholeInstructionString);
u_long hexStrToLong(std::string bracketStr);
int getMemSizeByte(std::string src, std::string bracketStr);
void set_src_mem(int memSizeBytes, u_long hexValue, Node* p_tempNode);
void set_src_root(Node* p_rootNode, Node* p_tempNode);
void set_src_reg(std::pair<int, int> srcRegNumSize, Node* p_tempNode);
void set_dst_mem(int memSizeBytes, u_long hexValue, Node* p_tempNode);
void set_dst_root(Node* p_rootNode, Node* p_tempNode);
void instrument_instruction (std::string mnemonic, Node* p_tempNode, Node* p_rootNode, std::string wholeInstructionString);
std::vector<std::string> getInstrPieces (std::string wholeInstructionString);
void instrument_addorsub (std::string wholeInstructionString,  uint32_t set_flags, uint32_t clear_flags, Node* p_instrNode, Node* p_rootNode);
void instrument_xchg (std::string wholeInstructionString,  uint32_t set_flags, uint32_t clear_flags, Node* p_instrNode, Node* p_rootNode);
void instrument_div (std::string wholeInstructionString,  uint32_t set_flags, uint32_t clear_flags, Node* p_instrNode, Node* p_rootNode);
void instrument_mov (std::string wholeInstructionString,  uint32_t set_flags, uint32_t clear_flags, Node* p_instrNode, Node* p_rootNode);
void instrument_mul (std::string wholeInstructionString,  uint32_t set_flags, uint32_t clear_flags, Node* p_instrNode, Node* p_rootNode);
void instrument_imul (std::string wholeInstructionString,  uint32_t set_flags, uint32_t clear_flags, Node* p_tempNode, Node* p_rootNode);
void instrument_cmp_or_test (std::string wholeInstructionString,  uint32_t set_flags, uint32_t clear_flags, Node* p_tempNode, Node* p_rootNode);
void instrument_onedst_twosrc(std::string wholeInstructionString,  uint32_t set_flags, uint32_t clear_flags, Node* p_tempNode, Node* p_rootNode);
void instrument_eflagsdst_twosrc(std::string wholeInstructionString,  uint32_t set_flags, uint32_t clear_flags, Node* p_tempNode, Node* p_rootNode);
void handle_dstRegMemImm (std::string dst, Node* p_tempNode, Node* p_rootNode);
void handle_srcRegMemImm (std::string src, Node* p_tempNode, Node* p_rootNode);
static inline std::string getMnemonic(std::string wholeInstructionString);
