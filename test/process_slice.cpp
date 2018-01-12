#include <iostream>
#include <fstream>
#include <string> 
#include <vector>
#include <sstream>
#include <cassert>
#include <map>
#include <stdlib.h>
#include <queue>
#include <list>

using namespace std;

int pushed = 0; // For aligning stack

string memSizeToPrefix(int size);
class AddrToRestore {
	private: 
		string loc;
		int isImm;
		int size;
	public:
		AddrToRestore(string loc, int isImm, int size) { 
			this->loc = loc;
			this->isImm = isImm;
			this->size = size;
		}
		void printPush() {
			if (size == 2 || size == 4) //qword and xmmword are not suported for push on 32-bit
				cout << "push " << memSizeToPrefix(size) << "[0x" << loc << "]" << endl;
			else {
				//use movsb
				cout <<"/*TODO: make sure we don't mess up with original ecs, edi and esi*/" << endl;
				cout << "sub esp, " << size << endl;
				cout << "mov ecx, " << size << endl;
				cout << "lea edi, [esp]" << endl;
				cout << "lea esi, [0x" << loc << "]" << endl;
				cout << "rep movsb" << endl;
			}
			pushed += size;
		}
		void printPop () { 
			if (size == 2 || size == 4)
				cout << "pop " << memSizeToPrefix(size) << "[0x" << loc + "]" << endl;
			else {
				//use movsb
				cout << "/*TODO: make sure we don't mess up with original ecs, edi and esi*/" << endl;
					cout << "mov ecx, " << size << endl;
					cout << "lea edi, [0x" << loc << "]" << endl;
					cout << "lea esi, [esp]" << endl;
					cout << "rep movsb" << endl;
					cout << "add esp, " << size << endl;
			}
		}
		int getSize() {
			return size;
		}
};

//register list from PIN
//Make it more complete as we need
map<string, string> regMap = {
	{"(3,4)" , "edi"},
	{"(3,2)" , "di"},
	{"(4,4)" , "esi"},
	{"(4,2)" , "si"},
	{"(5,4)", "ebp"},
	{"(5,2)", "bp"},
	{"(6,4)" , "esp"},
	{"(6,2)" , "sp"},
	{"(7,4)" , "ebx"},
	{"(7,2)" , "bx"},
	{"(7,1)" , "bl"},
	{"(7,-1)" , "bh"},
	{"(8,4)" , "edx"},
	{"(8,2)" , "dx"},
	{"(8,1)" , "dl"},
	{"(8,-1)" , "dh"},
	{"(9,4)" , "ecx"},
	{"(9,2)" , "cx"},
	{"(9,1)" , "cl"},
	{"(9,-1)" , "ch"},
	{"(10,4)" , "eax"},
	{"(10,2)" , "ax"},
	{"(10,1)" , "al"},
	{"(10,-1)" , "ah"},
	{"(17,4)" , "eflag"},
	{"(54,16)" , "xmm0"},
	{"(55,16)" , "xmm1"},
	{"(56,16)" , "xmm2"},
	{"(57,16)" , "xmm3"},
	{"(58,16)" , "xmm4"},
	{"(59,16)" , "xmm5"},
	{"(60,16)" , "xmm6"},
	{"(61,16)" , "xmm7"}
};
/*val jumpMap = Map (
  "jns" -> "js",
  "js"  -> "jns",
  "jnz" -> "jz",
  "jz" -> "jnz",
  "ja" -> "jna",
  "jae" -> "jnae",
  "jb" -> "jnb",
  "jbe" -> "jnbe",
  )*/
string jumpMap(string ins) {
	if (ins[1] == 'n')
		return "j" + ins.substr (2);
	else 
		return "jn" + ins.substr (1);
}

vector<string> split(string str, char delimiter) { 
	vector<string> ret;
	stringstream ss(str);
	string tok;

	while(getline(ss, tok, delimiter)) {
		ret.push_back (tok);
	}

	return ret;
}

string cleanupSliceLine (string s) { 
    if (s == "") return s;
    size_t index = s.find("[SLICE_INFO]");
    if (index == string::npos) {
	index = s.length();
    } 
    vector<string> strs = split (s.substr(0, index), '#');
    if (index == s.length()) {
	return strs[2] + "   /* [ORIGINAL_SLICE] " +  strs[1]  + " */";
    } else {
	return strs[2] + "   /* [ORIGINAL_SLICE] " +  strs[1]  + " " + s.substr(index) + "*/"; 
    }
}

#ifdef PRINT_DEBUG_INFO
string cleanupExtraline (string s) {
	size_t start_index = s.find("]") + 2;
	size_t end_index = s.find("//");

	return s.substr(start_index, end_index - start_index) + " /* [SLICE_EXTRA]" + s.substr(end_index) + "*/";
}

string cleanupCtrlFlowLine (string s) {
	size_t start_index = s.find("]") + 2;
	size_t end_index = s.find("//");
	return s.substr(start_index, end_index - start_index) + " /* [SLICE_CTRL_FLOW] */";
}

string cleanupVerificationLine (string s) { 
	size_t start_index = s.find("]") + 2;
	size_t end_index = s.find("//");
	return s.substr(start_index, end_index - start_index) + "/*" + s.substr (0, start_index) + s.substr(end_index) + "*/";
}
#endif

string memSizeToPrefix(int size){ 
	switch(size){
		case 1: return" byte ptr ";
		case 2: return " word ptr ";
		case 4: return" dword ptr ";
		case 8: return" qdword ptr ";
		case 16: return" xmmword ptr ";
		default:
			cerr <<"unrecognized mem size "  <<  size << endl;
			assert (0);
	}
}

string rewriteInst (string s) {
	if (s.empty()) return string();
	size_t push_pos = s.find ("#push");
	size_t pop_pos = s.find ("#pop");
	if ((push_pos != string::npos || pop_pos != string::npos) && s.find("#00000000") == string::npos) { 
		size_t index = s.find("_mem[");
		vector<string> memParams = split (s.substr(index+5, s.find("]", index) - index - 5), ':');
		if (memParams.size() != 3) cout << s;
		string addr = memParams[0];
		string size = memParams[2];
		string newInst;
		if (push_pos != string::npos) { 
			string tmp = s.replace (push_pos, 6, "#mov " + memSizeToPrefix(atoi(size.c_str())) + "[" + addr + "], ");
			size_t index = tmp.find ("[SLICE_INFO]");
			return tmp.replace(index, 12, "[SLICE_INFO] push instruction (rewrite)");
		} 
		if (pop_pos != string::npos) { 
			string tmp = s.replace (pop_pos, 5, "#mov ");
			return tmp.replace (tmp.find("    [SLICE_INFO]"), 16, ", " + memSizeToPrefix(atoi(size.c_str())) + "[" + addr + "]    [SLICE_INFO] pop instruction(rewrite)");
		}
	} else if (s.find ("#j") != string::npos) { //change jump instruction
		size_t index = s.find ("#j");
		size_t spaceIndex = s.find (" ", index);
		string inst = s.substr (index +1, spaceIndex - index - 1);
		string address = s.substr (spaceIndex + 1, s.find (" ", spaceIndex + 1) - spaceIndex - 1);
		//assert (jumpMap.contains(inst))
		if (s.find ("branch_taken 1") != string::npos) {
			//if the original branch is taken, then we jump to error if not taken as before
			string tmp = s.replace (index + 1, inst.length(), jumpMap(inst));
                        if (s.find ("block_index") == string::npos) {
                                spaceIndex = s.find (" ", s.find("#j"));
                                return tmp.replace(spaceIndex + 1, address.length(), "jump_diverge");
                        } else 
                                return tmp;
		} else if (s.find ("branch_taken 0") != string::npos) 
                        if (s.find ("block_index") == string::npos)
			        return s.replace(spaceIndex + 1, address.length(), "jump_diverge");
                        else 
                                return s;
		else if (inst.compare("jecxz") == 0) {
			//return s.replace(spaceIndex + 1, address.length(), "not handled");
                        fprintf (stderr, "[ERROR] jecxz not handled yet.\n");
                        return "";
		} else {
                        if (s.find ("_branch_") == string::npos)
			        cerr << "jump instruction? " + s << endl;
		}
	}
	return s;
}

string replaceReg (string s) {
	size_t index = s.find ("$reg(");
	if (index != string::npos) { 
		//replace reg
		size_t lastIndex = s.find (")", index +1);
		string regIndex = s.substr (index + 4, lastIndex + 1 - index - 4);
		if (regMap.find (regIndex) != regMap.end()) {
			string out = s.replace (index, lastIndex + 1 - index, regMap[regIndex]);
			//println (out)
			return out;
		} else  {
			cerr << "cannot find corresponding reg!!!!!!." << s << endl;
			cerr << s << endl;
                        assert (0);
		}
	} 
	return s;
}

string replaceMem (string s, string instStr) {
	size_t addrIndex = s.find("$addr(");
	if (addrIndex != string::npos) {
		//replace the mem operand in this line
		//copy the original slice code's addressing mode
		if (instStr.find (" ptr " ) == string::npos) {
                    cerr << "error line: " <<s <<endl;
                    assert (0);
                }
		//I haven't handled the case where more than one operand is mem
		assert (instStr.find (" ptr " ) == instStr.rfind(" ptr "));
		assert (instStr.find ("[SLICE]") == 0);
		string inst = split(instStr.substr(0, instStr.find("[SLICE_INFO]")), '#')[2];
		vector<string> operands = split(inst.substr (inst.find(" ") + 1), ',');
		string out;
		//println ("replaceMem: " + instStr + ", " + s + ", " + operands)
		//replace address with base+index registers
		for (string op: operands) {
			//println ("replaceMem: " + op)
			size_t index = op.find("ptr");
			if(index != string::npos) {
				out = s.replace (addrIndex, s.find(")", addrIndex + 1) + 1 - addrIndex, op);
			}
		}
		return out;
	}
	return s;
}

AddrToRestore parseRestoreAddress (string s) {
	size_t index = s.find(":");
	assert (index != string::npos);
	vector<string> strs = split (s.substr(index + 2), ',');
        assert (strs.size() >= 3);
	return AddrToRestore (strs[0], atoi(strs[1].c_str() + 1), atoi(strs[2].c_str() + 1));
}

void println (string s) { 
	cout << s << endl;
}

void printerr (string s) { 
	cerr << s << endl;
}

#define SLICE 0
#ifdef PRINT_DEBUG_INFO
#define SLICE_EXTRA 1
#endif
#define SLICE_RESTORE_ADDRESS 3
#define SLICE_RESTORE_REG 4
#ifdef PRINT_DEBUG_INFO
#define SLICE_VERIFICATION 5
#define SLICE_TAINT 6
#define SLICE_CTRL_FLOW 7
#endif

inline int getLineType (string line) { 
	if (line.compare (0, 7, "[SLICE]") == 0)
		return SLICE;
#ifdef PRINT_DEBUG_INFO
	else if (line.compare (0, 13, "[SLICE_EXTRA]") == 0)
		return SLICE_EXTRA;
	else if (line.compare (0, 20, "[SLICE_VERIFICATION]") == 0)
		return SLICE_VERIFICATION;
	else if (line.compare (0, 13, "[SLICE_TAINT]") == 0)
                return SLICE_TAINT;
        else if (line.compare(0, 17, "[SLICE_CTRL_FLOW]") == 0) 
                return SLICE_CTRL_FLOW;
#endif
	else if (line.compare (0, 23, "[SLICE_RESTORE_ADDRESS]") == 0) 
		return SLICE_RESTORE_ADDRESS;
	else if (line.compare (0, 19, "[SLICE_RESTORE_REG]") == 0)
		return SLICE_RESTORE_REG;
        else if (line.compare (0, 5, "[BUG]") == 0) {
                cerr <<"BUG line: " <<line <<endl;
                return -1;
        } else { 
#ifdef PRINT_DEBUG_INFO
		cerr << "Unrecognized line: " << line <<endl;
#endif
                return -1;
	}
}

int main (int argc, char* argv[]) { 
	if (argc != 2) { 
		cout << "usage: process_slice FILENAME" << endl;
	}
	ifstream in(argv[1], ios::in);
	if (!in.is_open ()) {
		cerr << "cannot open input file" << endl;
	}

	queue<pair<int,string>> buffer; //type and the content of the string
	list<AddrToRestore> restoreAddress;
	list<string> restoreReg;
	int totalRestoreSize = 0;
	string s;
	while (!in.eof()) {
		if (in.fail() || in.bad()) assert (0);
		getline (in, s);
		if (s.empty()) continue;

		//TODO merge two round maybe
		//first round: figure out the type for each line
		// get all mem addresses we need to restore
		// and reorder a little bit
		int type = getLineType (s);
		switch (type) { 
			case SLICE_RESTORE_ADDRESS:  
				{
					AddrToRestore tmp = parseRestoreAddress(s);
					restoreAddress.push_back(tmp);
					totalRestoreSize += tmp.getSize();
					break; 
				}
			case SLICE_RESTORE_REG: 
				{
					size_t index = s.find("$reg(");
					assert (index != string::npos);
					restoreReg.push_back(regMap[s.substr(index+4, s.find (")", index+1)+1 - index - 4)]);
					totalRestoreSize += 4;
					break;
				}
			default:
				buffer.push (make_pair(type, s));
				break;
		}
	}
	if (totalRestoreSize >= 65536) fprintf (stderr, "Total restore size: %d\n", totalRestoreSize);
	assert (totalRestoreSize < 65536); //currently we only allocated 65536 bytes for this restore stack

	//second round
	//write out headers
	//println	(".intel_syntax noprefix")
#if 0
	println (".section	.text");
	println (".globl _start");
	println ("_start:");

	//start
	println ("push ebp");
	println ("call recheck_start");
	println ("pop ebp");
	println ("/*TODO: make sure we follow the calling conventions (preseve eax, edx, ecx when we call recheck-support func)*/");
#endif
	//write out all restore address
	println ("/*first checkpoint necessary addresses and registers*/");
	for (string reg: restoreReg) { 
		println ("push " + reg);
	}
	for (AddrToRestore addrRestore: restoreAddress) 
		addrRestore.printPush();

	// Stack must be aligned for use during slice
	// Adjust for 4 byte return address pushed for call of sections (needed for large slices)
	cout << "sub esp, " << (28-(pushed%16))%16 << endl;

	println ("/*slice begins*/");

	//switch posistion and generate compilable assembly
	//println ("**************************")
	while (!buffer.empty()) {
		auto p = buffer.front();
		string s= p.second;
		//SLICE_ADDRESSING comes first, then SLICE_EXTRA then SLICE
		switch (p.first) { 
#ifdef PRINT_DEBUG_INFO
			case SLICE_EXTRA:
			    println (cleanupExtraline(s));
			    break;
#endif
			case SLICE:
			    println (cleanupSliceLine(s));
			    break;
#ifdef PRINT_DEBUG_INFO
			case SLICE_VERIFICATION:
			    println (cleanupVerificationLine(s));
			    break;
                        case SLICE_CTRL_FLOW:
                            println (cleanupCtrlFlowLine(s));
                            break;
                        case SLICE_TAINT:
                                println ("/*Eliminated " + s + "*/");
                                break;
			default:
				println ("unrecognized: " + s);
				assert (0);
#else
		        default:
			        println (s);
#endif
		}
		buffer.pop();
	}
#if 0
	println ("/* restoring address and registers */");
	cout << "add esp, " << (28-(pushed%16))%16 << endl;

	for (auto addrRestore = restoreAddress.rbegin(); addrRestore!=restoreAddress.rend(); ++addrRestore) {
		addrRestore->printPop();
	}
	for (auto regRetore = restoreReg.rbegin(); regRetore!=restoreReg.rend(); ++regRetore){
		println ("pop " + *regRetore);
	}
	println ("/* slice finishes and return to kernel */");
	println ("mov ebx, 1");
	println ("mov eax, 350");
	println ("int 0x80");

	//control flow divergence
	println ("/* function that handles jump divergence */");
	println ("jump_diverge:");
	println ("push eax");
	println ("push ecx");
	println ("push edx");
	println ("call handle_jump_diverge");
	println ("pop edx");
	println ("pop ecx");
	println ("pop eax");

	//index divergence
	println ("/* function that handles index divergence */");
	println ("index_diverge:");
	println ("push eax");
	println ("push ecx");
	println ("push edx");
	println ("call handle_index_diverge");
	println ("pop edx");
	println ("pop ecx");
	println ("pop eax");
#endif
	return 0;
}
