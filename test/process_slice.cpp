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
	println ("push edx");
	println ("push ecx");
	println ("push eax");

	//index divergence
	println ("/* function that handles index divergence */");
	println ("index_diverge:");
	println ("push eax");
	println ("push ecx");
	println ("push edx");
	println ("call handle_index_diverge");
	println ("push edx");
	println ("push ecx");
	println ("push eax");
#endif

	return 0;
}
