#include <iostream>
#include <string>
#include <fstream>
#include <list>
#include <vector>
#include <assert.h>
#include <queue>
#include <stdio.h>
#include <string.h>

using namespace std;

struct block { 
    int start_line;
    int end_line;
    size_t hash;
    long block_index;
};

static inline long get_block_index (string line, uint32_t &addr) { 
   size_t info_pos = line.find ("[BLOCK_INFO]"); 
   if (info_pos == string::npos) { 
       if (line.find ("[SLICE_VERIFICATION]") == string::npos && line.find("[SLICE_EXTRA]") == string::npos) {
           cerr << "line doesn't have a BLOCK_INFO:" << line <<endl;
       }
       return -1;
   } else { 
       size_t stop = line.find ("*", info_pos);
       string index_str = line.substr (info_pos + 13, stop - info_pos - 13);
       long index;
       sscanf (index_str.c_str(), "%lu,%x", &index, &addr);
       return index;
   }
}

static inline long get_block_index (string line) { 
    uint32_t addr = 0;
    return get_block_index (line, addr);
}

static void inline add_to_block_list (vector<block> &block_list, int start, int end, string block_content, long block_index) { 
    struct block block;
    block.start_line = start;
    block.end_line = end;
    block.block_index = block_index;
    struct hash<string> h;
    block.hash = h(block_content);
    block_list.push_back (block);
    //cout << "block List (" << block.start_line << "," <<block.end_line << ": " << block.hash << ", content: "<< block_content << endl;
}

void get_slice_content (ifstream &in, vector<string> &slice_content, vector<block> &block_list) { 
    string line;
    bool start = false;
    int block_start = 0;
    int block_end = 0;
    int count = 0;
    string block_content = "";
    long last_block_index = -1;
    while (getline (in, line)) {
        ++ count;
        slice_content.push_back (line);
        if (line == "/*slice begins*/") {
            start = true;
            block_start = count + 1;
        }
        if (start) { 
            if (line == "/* restoring address and registers */") {
                add_to_block_list (block_list, block_start, count - 1, block_content, -1);
                break;
            }
            if (line[0] == '/' && line[1] == '*')
                continue;
            long block_index = get_block_index (line);
            if (block_index == -1) { 
                //TODO: I know some lines like SLICE_EXTRA and SLICE_VERIFICATION don't have this index
                block_index = last_block_index;
            }
            //if (line.find ("jump_diverge") != string::npos /*|| line.find ("call ") != string::npos*/) { 
            if (block_index != last_block_index) { 
                add_to_block_list (block_list, block_start, count - 1, block_content, last_block_index);
                last_block_index = block_index;
                block_start = count;
                block_content = "";
            }
        }
    }
    while (getline (in, line)) { 
        slice_content.push_back(line);
    }
}

void init_ctrl_flow_instrument (const char* filename, queue<unsigned long>& block_diverge_list)
{
   FILE* file = fopen (filename, "r");
   char line[256];
   if (file == NULL) {
       fprintf (stderr, "init_ctrl_flow_info: cannot open file /tmp/ctrl_flow_instrument\n");
       return;
   }
   while (fgets (line, 255, file)) {
       unsigned long block_index, block_addr;
       if (strncmp (line, "[CTRL_INFO]", 11)) {
           fprintf (stderr, "init_ctrl_flow_info: cannot parse line %s\n", line);
           continue;
       }
       sscanf (line, "[CTRL_INFO] %lu,%lx", &block_index, &block_addr);
       block_diverge_list.push (block_index);
   }
   fclose (file);
}

int main (int argc, char* argv[]) { 
    string info_filename = "/tmp/ctrl_flow_instrument";
    if (argc != 3) {
        cerr << "usage: finalize_slice_ctrl_flow input_slice output_slice" <<endl;
    }
    ifstream slice_in (argv[1], ios::in);
    ifstream info_in (info_filename, ios::in);
    ofstream slice_out (argv[2], ofstream::out | ofstream::trunc);
    queue<unsigned long> block_diverge_list;
    init_ctrl_flow_instrument (info_filename.c_str(), block_diverge_list);
    if (!slice_in.is_open() || !info_in.is_open()) {
        cerr << "cannot open input files" <<endl;
    }
    if (!slice_out.is_open()) { 
        cerr << "cannot open output file" <<endl;
    }
    vector<string> slice_content;
    vector<block> slice_block;

    get_slice_content (slice_in, slice_content, slice_block);
    int line = 0;
    for (int i = 0; i<slice_block[0].start_line - 1; ++i) {
        slice_out << slice_content[i] << endl;
    }
    for (auto iter = slice_block.begin(); iter != slice_block.end(); ++iter) { 
        if (iter->block_index == block_diverge_list.front()) {
            //change the first line (assume it's a jump)
            string first_line = slice_content[iter->start_line-1];
            size_t pos = first_line.find ("jump_diverge");
            if (pos == string::npos) {
                //this block doesn't begin with jump?
                cerr<< "wrong line:" << first_line <<endl;
                assert (0);
            }
            string label = "block_" + to_string(iter->block_index);
            slice_out << first_line.replace(pos,12,label) << endl;
            for (int i = iter->start_line + 1; i <= iter->end_line; ++i) {
                slice_out << slice_content[i - 1] << endl;
            }
            slice_out << label << ":" << endl;
            block_diverge_list.pop ();
        } else {
            for (int i = iter->start_line; i <= iter->end_line; ++i) {
                slice_out << slice_content[i - 1] << endl;
            }
        }
    }
    for (int i = slice_block[slice_block.size() - 1].end_line; i < slice_content.size(); ++i) {
        slice_out << slice_content[i] << endl;
    }

    slice_in.close();
    info_in.close();
    slice_out.close();
    return 0;
}
