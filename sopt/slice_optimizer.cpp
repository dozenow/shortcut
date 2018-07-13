  #include <iostream>                  // for std::cout
  #include <utility>                   // for std::pair
  #include <algorithm>                 // for std::for_each
  #include <boost/graph/graph_traits.hpp>
  #include <boost/graph/adjacency_list.hpp>
  #include <boost/graph/dijkstra_shortest_paths.hpp>
#include <boost/archive/text_iarchive.hpp>
#include <boost/archive/text_oarchive.hpp>
#include <boost/serialization/map.hpp>
#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>
#include <sstream>
#include <string>
#include <boost/iostreams/device/file.hpp>
#include <boost/iostreams/stream.hpp>
#include <istream>
#include <regex>
#include "slice_optimizer.h"
#include <boost/algorithm/string.hpp>
#include <boost/numeric/ublas/vector.hpp>

using namespace boost;

//#define DEBUG_PRINT
//#define EDGES_PRINT 
#define VAL_EQV

//from taint_full_interface.c.
//the regToNumSize table in slice_optimizer.h is similar and returns -1 for the MostSigByte, or high half, such as AH and returns 1 for the leastSigByte, or low half such as AL.
static inline const char* regName (int reg_num, int reg_size)
  {
      switch (reg_num) {
      case 3:
    switch (reg_size) {
    case 4: return "edi";
    case 2: return "di";
    }
    break;
      case 4:
    switch (reg_size) {
    case 4: return "esi";
    case 2: return "si";
    }
    break;
      case 5:
    switch (reg_size) {
    case 4: return "ebp";
    case 2: return "bp";
    }
    break;
      case 6:
    switch (reg_size) {
    case 4: return "esp";
    case 2: return "sp";
    }
    break;
      case 7:
    switch (reg_size) {
    case 4: return "ebx";
    case 2: return "bx";
    case 1: return "bl";
    case -1: return "bh";
    }
    break;
      case 8:
    switch (reg_size) {
    case 4: return "edx";
    case 2: return "dx";
    case 1: return "dl";
    case -1: return "dh";
    }
    break;
      case 9:
    switch (reg_size) {
    case 4: return "ecx";
    case 2: return "cx";
    case 1: return "cl";
    case -1: return "ch";
    }
    break;
      case 10:
    switch (reg_size) {
    case 4: return "eax";
    case 2: return "ax";
    case 1: return "al";
    case -1: return "ah";
    }
    break;
      case 17:
    switch (reg_size) {
    case 4: return "eflag";
    }
    break;
      case 20:
    switch (reg_size) {
    case 2: return "ds";
    }
    break;
      case 21:
    switch (reg_size) {
    case 2: return "es";
    }
    break;
      case 54:
    switch (reg_size) {
    case 16: return "xmm0";
    }
    break;
      case 55:
    switch (reg_size) {
    case 16: return "xmm1";
    }
    break;
      case 56:
    switch (reg_size) {
    case 16: return "xmm2";
    }
    break;
      case 57:
    switch (reg_size) {
    case 16: return "xmm3";
    }
    break;
      case 58:
    switch (reg_size) {
    case 16: return "xmm4";
    }
    break;
      case 59:
    switch (reg_size) {
    case 16: return "xmm5";
    }
    break;
      case 60:
    switch (reg_size) {
    case 16: return "xmm6";
    }
    break;
      case 61:
    switch (reg_size) {
    case 16: return "xmm7";
    }
    break;
      }
      fprintf (stderr, "regName: unrecognized reg %d size %d\n", reg_num, reg_size);
      assert (0);
      return NULL;
  }

std::pair<int, int> checkForRegs(std::string instOperand){
  std::pair<int, int> regNumSize (NULL,NULL);
  regNumSize.first =(regToNumSize[instOperand]).first;
  regNumSize.second = (regToNumSize[instOperand]).second;

  #ifdef DEBUG_PRINT
    std::cout<< instOperand << "\n";
    std::cout<< regNumSize.first << "\n";
    std::cout<< regNumSize.second << "\n";
  #endif

  return regNumSize;

}

static inline void clear_reg_internal (int reg, int size)
  {
      int i = 0;

      Node* p_Zero = 0;

      for (i = 0; i < size; i++) {
          shadow_reg_table[reg * REG_SIZE + i] = p_Zero;
      }
  }
 
 static inline void set_reg_internal (int reg, int size, Node* author)
  {
      int i = 0;
      int offset = 0;

      if (size == -1){
        size = 1;
        offset = 1;
      }

      for (i = 0; i < size; i++) {
          shadow_reg_table[((reg * REG_SIZE) + i)+offset] = author;
          #ifdef DEBUG_PRINT
            std::cout<< "Setting shadow_reg_table at " << (reg * REG_SIZE + i) << "to " << author->lineNum << "\n";
            //std::cout<< regNumSize.first << "\n";
            //std::cout<< regNumSize.second << "\n";
          #endif
      }
  }

  static inline std::vector<Node*> get_reg_internal (int reg, int size)
  {
      int i = 0;
      std::vector<Node*> authors;
      int offset = 0;

      if (size == -1){
        size = 1;
        offset = 1;
      }

      for (i = 0; i < size; i++) {
          authors.push_back(shadow_reg_table[(reg * REG_SIZE + i)+offset]);
          #ifdef DEBUG_PRINT
            std::cout<< "GETTING shadow_reg_table at " << (reg * REG_SIZE + i) << "which is " << (shadow_reg_table[reg * REG_SIZE + i])->lineNum << "\n";
          #endif
      }
      #ifdef DEBUG_PRINT
        for (auto jt = std::begin(authors); jt != std::end(authors); ++jt){
                      std::cout<<"author is : " << (*jt)->lineNum  << "\n";
                    }
      #endif
      return authors;
  }

// trim from start (in place)
static inline void ltrim(std::string &s) {
    s.erase(s.begin(), std::find_if(s.begin(), s.end(), [](int ch) {
        return !std::isspace(ch);
    }));
}

// trim from end (in place)
static inline void rtrim(std::string &s) {
    s.erase(std::find_if(s.rbegin(), s.rend(), [](int ch) {
        return !std::isspace(ch);
    }).base(), s.end());
}
 

  void clear_reg (int reg, int size)
  {
      clear_reg_internal (reg, size);
  }

  void set_reg (int reg, int size, Node* author)
  {
      set_reg_internal (reg, size, author);
  }

  void set_dst_reg (std::string regName, Node* author)
  {
      std::pair<int, int> dstRegNumSize = checkForRegs(regName);
      set_reg(dstRegNumSize.first, dstRegNumSize.second, author);
  }

  //...

  std::string getStringWithinBrackets(std::string wholeInstructionString){
    std::sregex_iterator end;
    std::string bracketStr;
    //regex selects everything between square brackets
    //"word ptr [0xbfffef74]" IN
    //"[0xbfffef74]" OUT
    std::regex allInBrackets("(?=(\\[)).*");
    auto iterInBrack = std::sregex_iterator(wholeInstructionString.begin(), wholeInstructionString.end(), allInBrackets);
    while (iterInBrack != end) {
      std::smatch match = *iterInBrack;
      bracketStr = match.str();
      #ifdef DEBUG_PRINT
        std::cout << "memAddr:" << bracketStr << "\n";
      #endif
      iterInBrack++;
    }
    return bracketStr;
  }

  u_long hexStrToLong(std::string bracketStr, Node* p_tempNode, Node* p_rootNode){
    std::istringstream hexstr(bracketStr);
    u_long hexValue;
    if (bracketStr.compare("esp") == 0){
      hexValue = 96;
      handle_srcRegMemImm("esp",p_tempNode, p_rootNode);
      #ifdef DEBUG_PRINT
      std::cout<< "hexStrToLong has detected address [esp]! " << bracketStr << ", " << hexValue <<"\n";
      #endif
    }
    else{
      #ifdef DEBUG_PRINT
      std::cout<< "hexStrToLong has contents! " << bracketStr << ", " << hexValue <<"\n";
      #endif
      hexstr >> std::hex >> hexValue;
    }
    
    
    return hexValue;
  }

  int getMemSizeByte(std::string src, std::string bracketStr){
    std::string memSizeStr;
    memSizeStr = src.substr(0, src.find("ptr"));
    #ifdef DEBUG_PRINT
      std::cout << "getMemSize:" << memSizeStr << "\n";
    #endif
    
    ltrim(memSizeStr);
    rtrim(memSizeStr);
    int memSize;

    std::map<std::string, const int>::iterator iter2;
    iter2 = strSizeToByte.find(memSizeStr);
    if (iter2 != strSizeToByte.end()){
      memSize = (*iter2).second;
      #ifdef DEBUG_PRINT
        std::cout<<"srcmemSize:" << memSize << "\n";
      #endif
    }
    return memSize;
  }

  void set_src_mem(int memSizeBytes, u_long hexValue, Node* p_tempNode){
    int i;
    for (i=0; i<memSizeBytes; i++){
      std::map<u_long, Node*>::iterator it;
      it = mapMem.find(hexValue+i);
      //if the key actually exists in our map of [memoryAddress], authorNode
      if (it != mapMem.end()){
        Edge* p_tempInEdge = new Edge();
        Edge* p_tempOutEdge = new Edge();
       
        #ifdef DEBUG_PRINT
          std::cout<<(p_tempNode)->lineNum<< " p_tempNode->lineNum\n";   
          std::cout<<((*it).second)->lineNum<< " authorNode in mapMem\n";
        #endif
        p_tempInEdge->start = (*it).second;
        p_tempInEdge->finish = p_tempNode;
        

        //add correct outEdge from previous register author to self current node 
        p_tempOutEdge->start = (*it).second;
        p_tempOutEdge->finish = p_tempNode;

        p_tempNode->inEdges.push_back(p_tempInEdge);
        ((*it).second)->outEdges.push_back(p_tempOutEdge);
      }
    }
  }


  void set_src_root(Node* p_rootNode, Node* p_tempNode){
    Edge* p_tempInEdge = new Edge();
    Edge* p_tempOutEdge = new Edge();

    #ifdef DEBUG_PRINT
      std::cout<< "CONST SRC DETECTED! set_src_root() \n";
    #endif

    p_tempInEdge->start = p_rootNode;
    p_tempInEdge->finish = p_tempNode;
    p_tempOutEdge->start = p_rootNode;
    p_tempOutEdge->finish = p_tempNode;
    p_rootNode->outEdges.push_back(p_tempOutEdge);
    p_tempNode->inEdges.push_back(p_tempInEdge);
  }

  void set_src_reg(std::pair<int, int> srcRegNumSize, Node* p_tempNode){
  std::vector<Node*> regAuthors = get_reg_internal((srcRegNumSize.first),(srcRegNumSize.second));
  //if srcRegNumSize.first) is not EMPTY then it must be a valid register
  for (auto it = std::begin(regAuthors); it != std::end(regAuthors); ++it){
      //4-23-18
      Edge* p_tempInEdge = new Edge();
      Edge* p_tempOutEdge = new Edge();
      p_tempInEdge->start = (*it);
      p_tempInEdge->finish = p_tempNode;

      //add correct outEdge from previous register author to self current node 
      p_tempOutEdge->start = (*it);
      p_tempOutEdge->finish = p_tempNode;

      p_tempNode->inEdges.push_back(p_tempInEdge);
      (*it)->outEdges.push_back(p_tempOutEdge);

      #ifdef DEBUG_PRINT
        std::cout<< "srcNoding lineNum " << (*it)->lineNum <<  " to " << p_tempNode->lineNum <<"\n";
        std::cout<<"p_tempInEdge->start : " << (*it)->lineNum  << "\n";
        std::cout<<"p_tempInEdge->finish is : " << p_tempNode->lineNum  << "\n";
        for (auto jt = std::begin((*it)->outEdges); jt != std::end((*it)->outEdges); ++jt){
          std::cout<<"outEdges for Node: " << ((*it))->lineNum << " is "  << ((*jt)->start)->lineNum << " to " << ((*jt)->finish)->lineNum  << "\n";
        }
        for (auto jt = std::begin(p_tempNode->inEdges); jt != std::end(p_tempNode->inEdges); ++jt){
          std::cout<<"inEdges for Node: " << " is "  << ((*jt)->start)->lineNum << " to " << ((*jt)->finish)->lineNum  << "\n";
        }
      #endif
    }
  }

  void set_src_regName(std::string regName, Node* p_tempNode){
  std::pair<int, int> srcRegNumSize = checkForRegs(regName);
  std::vector<Node*> regAuthors = get_reg_internal((srcRegNumSize.first),(srcRegNumSize.second));
  //if srcRegNumSize.first) is not EMPTY then it must be a valid register
  for (auto it = std::begin(regAuthors); it != std::end(regAuthors); ++it){
      //4-23-18
      Edge* p_tempInEdge = new Edge();
      Edge* p_tempOutEdge = new Edge();
      p_tempInEdge->start = (*it);
      p_tempInEdge->finish = p_tempNode;

      //add correct outEdge from previous register author to self current node 
      p_tempOutEdge->start = (*it);
      p_tempOutEdge->finish = p_tempNode;

      p_tempNode->inEdges.push_back(p_tempInEdge);
      (*it)->outEdges.push_back(p_tempOutEdge);

      #ifdef DEBUG_PRINT
        std::cout<< "srcNoding lineNum " << (*it)->lineNum <<  " to " << p_tempNode->lineNum <<"\n";
        std::cout<<"p_tempInEdge->start : " << (*it)->lineNum  << "\n";
        std::cout<<"p_tempInEdge->finish is : " << p_tempNode->lineNum  << "\n";
        for (auto jt = std::begin((*it)->outEdges); jt != std::end((*it)->outEdges); ++jt){
          std::cout<<"outEdges for Node: " << ((*it))->lineNum << " is "  << ((*jt)->start)->lineNum << " to " << ((*jt)->finish)->lineNum  << "\n";
        }
        for (auto jt = std::begin(p_tempNode->inEdges); jt != std::end(p_tempNode->inEdges); ++jt){
          std::cout<<"inEdges for Node: " << " is "  << ((*jt)->start)->lineNum << " to " << ((*jt)->finish)->lineNum  << "\n";
        }
      #endif
    }
  }

  void set_dst_mem(int memSizeBytes, u_long hexValue, Node* p_tempNode){
    int i;
    for (i=0; i<memSizeBytes; i++){
                mapMem[(hexValue+i)] = p_tempNode;
              } 
  }

  void set_dst_root(Node* p_rootNode, Node* p_tempNode){
    Edge* p_tempOutEdge = new Edge();

    #ifdef DEBUG_PRINT
      std::cout<< "CONST dst DETECTED! set_dst_root() \n";
    #endif

    p_tempOutEdge->start = p_tempNode;
    p_tempOutEdge->finish = p_rootNode;
    p_tempNode->outEdges.push_back(p_tempOutEdge);
  }

  static inline void set_clear_flags(Node* author, uint32_t set_flags, uint32_t clear_flags) 
{
    if (set_flags != (uint32_t) -1 && clear_flags != (uint32_t) -1) {
  for (int i = 0; i<NUM_FLAGS; ++i) {
      if (set_flags & (1 << i)) {
          eflags_table[i] = author;
      } 
      else if (clear_flags & (1 << i)) {
        //6-5-18 changed 'clearing' flags to be same as setting flags, because instructions that depended on flags that were cleared would break with a segfault when it comes to that 'cmov' sourcing from a flag that was cleared so it has no author. Maybe should change this to set author to p_RootNode.
          eflags_table[i] = author;
        //eflags_table[i] = 0;
      }
       }
    }
}

static inline void set_src_flags(Node* p_tempNode, uint32_t src_flags) 
{

  if (src_flags != (uint32_t) -1) {
    for (int i = 0; i<NUM_FLAGS; ++i) {
      if (src_flags & (1 << i)) {
        Edge* p_tempInEdge = new Edge();
        Edge* p_tempOutEdge = new Edge();
        p_tempInEdge->start = (eflags_table[i]);
        p_tempInEdge->finish = p_tempNode;
        //add correct outEdge from previous register author to self current node 
        p_tempOutEdge->start = (eflags_table[i]);
        p_tempOutEdge->finish = p_tempNode;
        p_tempNode->inEdges.push_back(p_tempInEdge);
        (eflags_table[i])->outEdges.push_back(p_tempOutEdge);
        #ifdef DEBUG_PRINT
        std::cout<<" i is: " << i  << "\n";
        #endif
      } 
    }
  }
}

static inline std::string getMnemonic(std::string wholeInstructionString){
  std::string mnemonic;
  std::string istr;
  std::sregex_iterator end;

  std::regex allPreExtra("^.*(?=(\\/\\*))");
  auto iterPreExtra = std::sregex_iterator(wholeInstructionString.begin(), wholeInstructionString.end(), allPreExtra);
  if (iterPreExtra == end) {
    istr = wholeInstructionString.substr(0, wholeInstructionString.find("\\n"));
  }
  while (iterPreExtra != end) {
    std::smatch match = *iterPreExtra;
    istr = match.str();
    #ifdef DEBUG_PRINT
      std::cout << "regex2:" << match.str() << "\n";
    #endif
    iterPreExtra++;
  } 
  
  //remove the quotes symbol char that leads the instruction string.
  istr = istr.substr(1, istr.size());

  mnemonic = istr.substr(0, istr.find(' '));
  ltrim(mnemonic);
  rtrim(mnemonic);
  #ifdef DEBUG_PRINT
    std::cout<<"istr:"<<istr<<"\n";
  #endif
    return mnemonic;
}

std::vector<std::string> getInstrPieces (std::string wholeInstructionString)
{
  std::string mnemonic;
  std::string istr;
  std::string dst;
  std::string src;
  std::string fourth;

  std::sregex_iterator end;

  std::regex allPreExtra("^.*(?=(\\/\\*))");
  auto iterPreExtra = std::sregex_iterator(wholeInstructionString.begin(), wholeInstructionString.end(), allPreExtra);
  if (iterPreExtra == end) {
    istr = wholeInstructionString.substr(0, wholeInstructionString.find("\\n"));
  }
  while (iterPreExtra != end) {
    std::smatch match = *iterPreExtra;
    istr = match.str();
    #ifdef DEBUG_PRINT
      std::cout << "regex2:" << match.str() << "\n";
    #endif
    iterPreExtra++;
  }

  //remove the quotes symbol char that leads the instruction string.
  istr = istr.substr(1, istr.size());

  mnemonic = istr.substr(0, istr.find(' '));
  ltrim(mnemonic);
  rtrim(mnemonic);

  #ifdef DEBUG_PRINT
    std::cout<<"(getInstrPieces)istr:"<<istr<<"\n";
  #endif

  dst = istr.substr((istr.find(mnemonic)+mnemonic.size()+1), (istr.find(',')-mnemonic.size()-1));

  src = istr.substr((istr.find(',')+1), (istr.size()-2));
  ltrim(src);
  //std::cout<<"dst,src:"<<dst<< ','<<src<<"\n";
  fourth = src.substr((src.find(',')+1), (src.size()-2));
  ltrim(fourth);

  //split this 'src' string one more time on the comma
  //this is for 4 argument (including mnemonic) instructions
  if((src.find(',')) != std::string::npos){
    src = src.substr(0, (src.find(',')));
  }
  
  //trim off pre AND post whitespace from the registerName string
  ltrim(src);
  ltrim(dst);
  ltrim(mnemonic);
  ltrim(fourth);
  rtrim(src);
  rtrim(dst);
  rtrim(mnemonic);
  rtrim(fourth);
  #ifdef DEBUG_PRINT
    std::cout<<"mnemonic Arg: "<<mnemonic<<"\n";
    std::cout<<"dst Arg: "<<dst<<"\n";
    std::cout<<"src Arg: "<<src<<"\n";
    std::cout<<"fourth Arg: "<<fourth<<"\n";
  #endif

  std::vector<std::string> instrPieces;
  instrPieces.push_back(mnemonic);
  instrPieces.push_back(dst);
  instrPieces.push_back(src);
  instrPieces.push_back(fourth);
  return instrPieces;
}

void instrument_div (std::string wholeInstructionString,  uint32_t set_flags, uint32_t clear_flags, Node* p_tempNode, Node* p_rootNode)
{
  
  std::vector<std::string> instrPieces = getInstrPieces(wholeInstructionString);

  std::string mnemonic = instrPieces.at(0);
  std::string dst = instrPieces.at(1);
  std::string dstB = instrPieces.at(1);
  std::string src = instrPieces.at(2);
  //div instruction only has one argument, the src, aka divisor. the dividend is implicit AX, DX:AX, EDX:EAX
  //the div instr stores the result in the AX (AH:AL), DX:AX, or EDX:EAX registers.
  src = instrPieces.at(1);

  std::pair<int, int> srcRegNumSize = checkForRegs(src);
  std::vector<Node*> regAuthors = get_reg_internal((srcRegNumSize.first),(srcRegNumSize.second));

  

    
  
  #ifdef DEBUG_PRINT
    for (auto jt = std::begin(instrPieces); jt != std::end(instrPieces); ++jt){
              std::cout<<"[instrument_div]srcRegNumSize.first, .second is : " << (srcRegNumSize.first) << ", "  << (srcRegNumSize.second) << "\n";
            }
    std::cout<<"mnemonic is: " << mnemonic  << "\n";
    std::cout<<"dst is : " << dst  << "\n";
    std::cout<<"src is : " << src  << "\n";

    for (auto jt = std::begin(regAuthors); jt != std::end(regAuthors); ++jt){
              std::cout<<"regAuthor is : " << (*jt)->lineNum  << "\n";
            }
  #endif

  #ifdef DEBUG_PRINT
    std::cout<< "regAuthors.empty() is " << regAuthors.empty() << "\n";
    std::cout<< "srcRegNumSize.first is " << srcRegNumSize.first << "\n";
  #endif

  //if there is a src register, set the appropriate edges to the previous author of that register
  if(srcRegNumSize.first){
    set_src_reg(srcRegNumSize, p_tempNode);
    //set the dividend register according to divisor register size
    switch (srcRegNumSize.second)
    {
      case 4:
        dst = "edx";
        dstB = "eax";
        break;
      case 2:
        dst = "dx";
        dstB = "ax";
        break;
      case 1:
      case -1:
        dst = "ah";
        dstB = "al";
        break;
    }
  }
  //else must be a const src or memory src  
  else{
    std::string bracketStr;
    std::string memAddrStr;
    bracketStr = getStringWithinBrackets(src);
    
    //take the bracketString of a memory address src, [0xbfffef74]
    //and convert the bracketStr to a u_long hexvalue of the memory address, 3221221236
    if(bracketStr.size() > 0){
      int memSizeBytes = getMemSizeByte(src,bracketStr);
      //remove the brackets from the string
      memAddrStr = bracketStr.substr(1, (bracketStr.size()-2));
      u_long hexValue = hexStrToLong(memAddrStr, p_tempNode, p_rootNode);
      set_src_mem(memSizeBytes, hexValue, p_tempNode);
      switch (memSizeBytes)
      {
        case 4:
          dst = "edx";
          dstB = "eax";
          break;
        case 2:
          dst = "dx";
          dstB = "ax";
          break;
        case 1:
        case -1:
          dst = "ah";
          dstB = "al";
          break;
      }

    }
    //else if (bracketStr.size() < 0) then must be a constant src like "17"
    //so create an OUTedge from the rootNode to the current tempInstruction node;
    //and create an INedge from the rootNode to the current tempInstruction node; 
    else{
      set_src_root(p_rootNode, p_tempNode);
      //6-1-18
      //temp hacky assumption that all constant srcs are 32 bit args
      //the x86 'div' instruction never directly srcs in immediate constant values so this code should never be used.
      dst = "edx";
      dstB = "eax";
    } 
  }

  //...
  std::pair<int, int> dstRegNumSize = checkForRegs(dst);
  set_src_reg(dstRegNumSize, p_tempNode);
  set_clear_flags(p_tempNode, set_flags, clear_flags);

  std::pair<int, int> dstBRegNumSize = checkForRegs(dstB);
  set_src_reg(dstBRegNumSize, p_tempNode);

   //if (dstRegNumSize.first) is not NULL then it must be a valid register
  if(dstRegNumSize.first){
    set_reg((dstRegNumSize.first), (dstRegNumSize.second), p_tempNode);
  }

   //if (dstBRegNumSize.first) is not NULL then it must be a valid register
  if(dstBRegNumSize.first){
    set_reg((dstBRegNumSize.first), (dstBRegNumSize.second), p_tempNode);
  }
}

void handle_srcRegMemImm (std::string src, Node* p_tempNode, Node* p_rootNode){
  #ifdef DEBUG_PRINT
  std::cout<< "(handle_srcRegMemImm) src is : " << src << "\n";
  std::cout<< "srcRegNumSize.first, srcRegNumSize.second is " << srcRegNumSize.first << ", " <<srcRegNumSize.second << "\n";
  #endif
  std::pair<int, int> srcRegNumSize = checkForRegs(src);
  
  #ifdef DEBUG_PRINT
    std::vector<Node*> regAuthors = get_reg_internal((srcRegNumSize.first),(srcRegNumSize.second));
    for (auto jt = std::begin(regAuthors); jt != std::end(regAuthors); ++jt){
              std::cout<<"regAuthor is : " << (*jt)->lineNum  << "\n";
            }
  #endif

  #ifdef DEBUG_PRINT
    std::cout<< "regAuthors.empty() is " << regAuthors.empty() << "\n";
    std::cout<< "srcRegNumSize.first is " << srcRegNumSize.first << "\n";
  #endif

  //if there is a src register, set the appropriate edges to the previous author of that register
  if(srcRegNumSize.first){
    set_src_reg(srcRegNumSize, p_tempNode);
  }
  //else must be a const src or memory src  
  else{
    std::string bracketStr;
    std::string memAddrStr;
    bracketStr = getStringWithinBrackets(src);
    
    //take the bracketString of a memory address src, [0xbfffef74]
    //and convert the bracketStr to a u_long hexvalue of the memory address, 3221221236
    if(bracketStr.size() > 0){
      int memSizeBytes = getMemSizeByte(src,bracketStr);
      //remove the brackets from the string
      memAddrStr = bracketStr.substr(1, (bracketStr.size()-2));
      u_long hexValue = hexStrToLong(memAddrStr, p_tempNode, p_rootNode);
      set_src_mem(memSizeBytes, hexValue, p_tempNode);
    }
    //else if (bracketStr.size() < 0) then must be a constant src like "17"
    //so create an OUTedge from the rootNode to the current tempInstruction node;
    //and create an INedge from the rootNode to the current tempInstruction node; 
    else{
      set_src_root(p_rootNode, p_tempNode);
    } 
  }
}

void handle_dstRegMemImm (std::string dst, Node* p_tempNode, Node* p_rootNode){
  #ifdef DEBUG_PRINT
  std::cout<< "(handle_dstRegMemImm) dst is : " << dst << "\n";
  #endif
  std::pair<int, int> dstRegNumSize = checkForRegs(dst);

   //if (dstRegNumSize.first) is not NULL then it must be a valid register
  if(dstRegNumSize.first){
    set_reg((dstRegNumSize.first), (dstRegNumSize.second), p_tempNode);
  }
  else{
    //else must be a const or memory dst  
    //handle memory dst 
    //1 byte = 8 bits 
    //word = 2 bytes = 16 bits  
    //double word = 4 bytes = 32 bits
    //xmm word = 16 bytes = 144 bits
    std::string bracketStr;
    std::string memAddrStr;
    bracketStr = getStringWithinBrackets(dst);

    //if the dst is a memory range, then set the new author to be current Instruction node 'p_tempNode'
    if(bracketStr.size() > 0){
      int memSizeBytes = getMemSizeByte(dst,bracketStr);
      //remove the brackets from the string
      memAddrStr = bracketStr.substr(1, (bracketStr.size()-2));              
      u_long hexValue = hexStrToLong(memAddrStr, p_tempNode, p_rootNode);
      set_dst_mem(memSizeBytes, hexValue, p_tempNode);

    }
    else{
      //else if (dstRegNumSize.first) is equal to "null" then must be a constant like "17"
      //so create an OUTedge from the rootNode to the current tempInstruction node;
      //and create an INedge from the rootNode to the current tempInstruction node; 
      set_dst_root(p_rootNode, p_tempNode);              
    } 
  }
}

void instrument_onedst_twosrc(std::string wholeInstructionString,  uint32_t set_flags, uint32_t clear_flags, Node* p_tempNode, Node* p_rootNode)
{
  
  std::vector<std::string> instrPieces = getInstrPieces(wholeInstructionString);

  std::string mnemonic = instrPieces.at(0);
  std::string dst = instrPieces.at(1);
  std::string src = instrPieces.at(2);
  std::string srcB = instrPieces.at(3);

  handle_srcRegMemImm(src, p_tempNode, p_rootNode);
  handle_srcRegMemImm(srcB, p_tempNode, p_rootNode);

  set_clear_flags(p_tempNode, set_flags, clear_flags);
  handle_dstRegMemImm(dst, p_tempNode, p_rootNode);
}

void instrument_eflagsdst_twosrc(std::string wholeInstructionString,  uint32_t set_flags, uint32_t clear_flags, Node* p_tempNode, Node* p_rootNode)
{
  
  std::vector<std::string> instrPieces = getInstrPieces(wholeInstructionString);

  std::string mnemonic = instrPieces.at(0);
  //in CMP/TEST instructions the two args are two srcs. The dst is setting the EFLAGS register.
  //so src1 in this case is instrPieces.at(1)
  //and src2 is instrPieces.at(2)
  std::string src = instrPieces.at(1);
  std::string srcB = instrPieces.at(2);

  handle_srcRegMemImm(src, p_tempNode, p_rootNode);
  handle_srcRegMemImm(srcB, p_tempNode, p_rootNode);

  set_clear_flags(p_tempNode, set_flags, clear_flags);
}

void instrument_cmp_or_test (std::string wholeInstructionString,  uint32_t set_flags, uint32_t clear_flags, Node* p_tempNode, Node* p_rootNode)
{
  
  instrument_eflagsdst_twosrc(wholeInstructionString, set_flags, clear_flags, p_tempNode, p_rootNode);
}

void instrument_imul (std::string wholeInstructionString,  uint32_t set_flags, uint32_t clear_flags, Node* p_tempNode, Node* p_rootNode)
{
  
  std::vector<std::string> instrPieces = getInstrPieces(wholeInstructionString);

  //commaCount of 0 is imul instruction with a single arg, is similar to mul instruction
  //commaCount of 1 is imul with two args, dest = dest * src
  //commaCount of 2 is imul with three args, dest = src * immediate
  size_t commaCount = std::count(wholeInstructionString.begin(), wholeInstructionString.end(), ',');
  #ifdef DEBUG_PRINT
  std::cout << "commaCount is: " << commaCount << "\n";
  #endif
  

  switch(commaCount){
    case 0:
      instrument_mul(wholeInstructionString, set_flags, clear_flags, p_tempNode, p_rootNode);
      break;
    case 1:
      instrument_addorsub(wholeInstructionString, set_flags, clear_flags, p_tempNode, p_rootNode);
      break;
    case 2:
      instrument_onedst_twosrc(wholeInstructionString, set_flags, clear_flags, p_tempNode, p_rootNode);
      break;
    default:
    std::cout<< "[ERROR]instrument_imul cant handle this instruction " << wholeInstructionString << "\n";
  }
}

void instrument_mul (std::string wholeInstructionString,  uint32_t set_flags, uint32_t clear_flags, Node* p_tempNode, Node* p_rootNode)
{
  
  std::vector<std::string> instrPieces = getInstrPieces(wholeInstructionString);

  std::string mnemonic = instrPieces.at(0);
  std::string dst = instrPieces.at(1);
  std::string dstB = instrPieces.at(1);
  std::string src = instrPieces.at(2);
  //mul instruction only has one argument, the src. the dst is implicit AL, AX, EAX
  //the mul instr stores the result in the AX (AH:AL), DX:AX, or EDX:EAX registers.
  src = instrPieces.at(1);

  std::pair<int, int> srcRegNumSize = checkForRegs(src);
  std::vector<Node*> regAuthors = get_reg_internal((srcRegNumSize.first),(srcRegNumSize.second));
  
  
  #ifdef DEBUG_PRINT
  for (auto jt = std::begin(instrPieces); jt != std::end(instrPieces); ++jt){
              std::cout<<"[instrument_mul]srcRegNumSize.first, .second is : " << (srcRegNumSize.first) << ", "  << (srcRegNumSize.second) << "\n";
            }

    for (auto jt = std::begin(regAuthors); jt != std::end(regAuthors); ++jt){
              std::cout<<"regAuthor is : " << (*jt)->lineNum  << "\n";
            }
  #endif

  #ifdef DEBUG_PRINT
    std::cout<< "regAuthors.empty() is " << regAuthors.empty() << "\n";
    std::cout<< "srcRegNumSize.first is " << srcRegNumSize.first << "\n";
  #endif

  //if there is a src register, set the appropriate edges to the previous author of that register
  if(srcRegNumSize.first){
    set_src_reg(srcRegNumSize, p_tempNode);
    //set the dst register according to src register size
    switch (srcRegNumSize.second)
    {
      case 4:
        dst = "edx";
        dstB = "eax";
        break;
      case 2:
        dst = "dx";
        dstB = "ax";
        break;
      case 1:
      case -1:
        dst = "ax";
        dstB = "al";
        break;
    }
  }
  //else must be a const src or memory src  
  else{
    std::string bracketStr;
    std::string memAddrStr;
    bracketStr = getStringWithinBrackets(src);
    
    //take the bracketString of a memory address src, [0xbfffef74]
    //and convert the bracketStr to a u_long hexvalue of the memory address, 3221221236
    if(bracketStr.size() > 0){
      int memSizeBytes = getMemSizeByte(src,bracketStr);
      //remove the brackets from the string
      memAddrStr = bracketStr.substr(1, (bracketStr.size()-2));
      u_long hexValue = hexStrToLong(memAddrStr, p_tempNode, p_rootNode);
      set_src_mem(memSizeBytes, hexValue, p_tempNode);
      switch (memSizeBytes)
      {
        case 4:
          dst = "edx";
          dstB = "eax";
          break;
        case 2:
          dst = "dx";
          dstB = "ax";
          break;
        case 1:
        case -1:
          dst = "ax";
          dstB = "al";
          break;
      }

    }
    //else if (bracketStr.size() < 0) then must be a constant src like "17"
    //so create an OUTedge from the rootNode to the current tempInstruction node;
    //and create an INedge from the rootNode to the current tempInstruction node; 
    else{
      set_src_root(p_rootNode, p_tempNode);
      //6-1-18
      //temp hacky assumption that all constant srcs are 32 bit args
      //the x86 'mul' instruction never directly srcs in immediate constant values so this code should never be used.
      dst = "edx";
      dstB = "eax";
    } 
  }

  //...
  set_clear_flags(p_tempNode, set_flags, clear_flags);

  std::pair<int, int> dstRegNumSize = checkForRegs(dst);
  std::pair<int, int> dstBRegNumSize = checkForRegs(dstB);
  set_src_reg(dstBRegNumSize, p_tempNode);


   //if (dstRegNumSize.first) is not NULL then it must be a valid register
  if(dstRegNumSize.first){
    set_reg((dstRegNumSize.first), (dstRegNumSize.second), p_tempNode);
  }

   //if (dstBRegNumSize.first) is not NULL then it must be a valid register
  if(dstBRegNumSize.first){
    set_reg((dstBRegNumSize.first), (dstBRegNumSize.second), p_tempNode);
  }

#ifdef DEBUG_PRINT
  std::cout<<"mnemonic is: " << mnemonic  << "\n";
    std::cout<<"dst is : " << dst  << "\n";
    std::cout<<"dstB is : " << dstB  << "\n";
    std::cout<<"src is : " << src  << "\n";
  #endif

}

void instrument_set (std::string wholeInstructionString,  uint32_t set_flags, uint32_t clear_flags, Node* p_tempNode, Node* p_rootNode)
{
  std::vector<std::string> instrPieces = getInstrPieces(wholeInstructionString);

  std::string mnemonic = instrPieces.at(0);
  std::string dst = instrPieces.at(1);
  handle_dstRegMemImm(dst, p_tempNode, p_rootNode);
}

void instrument_addorsub (std::string wholeInstructionString,  uint32_t set_flags, uint32_t clear_flags, Node* p_tempNode, Node* p_rootNode)
{
  
  std::vector<std::string> instrPieces = getInstrPieces(wholeInstructionString);

  std::string mnemonic = instrPieces.at(0);
  std::string dst = instrPieces.at(1);
  std::string src = instrPieces.at(2);

  std::pair<int, int> srcRegNumSize = checkForRegs(src);
  std::vector<Node*> regAuthors = get_reg_internal((srcRegNumSize.first),(srcRegNumSize.second));

  #ifdef DEBUG_PRINT
    for (auto jt = std::begin(regAuthors); jt != std::end(regAuthors); ++jt){
              std::cout<<"regAuthor is : " << (*jt)->lineNum  << "\n";
            }
  #endif

  #ifdef DEBUG_PRINT
    std::cout<< "regAuthors.empty() is " << regAuthors.empty() << "\n";
    std::cout<< "srcRegNumSize.first is " << srcRegNumSize.first << "\n";
  #endif

  //if there is a src register, set the appropriate edges to the previous author of that register
  if(srcRegNumSize.first){
    set_src_reg(srcRegNumSize, p_tempNode);
  }
  //else must be a const src or memory src  
  else{
    std::string bracketStr;
    std::string memAddrStr;
    bracketStr = getStringWithinBrackets(src);
    
    //take the bracketString of a memory address src, [0xbfffef74]
    //and convert the bracketStr to a u_long hexvalue of the memory address, 3221221236
    if(bracketStr.size() > 0){
      int memSizeBytes = getMemSizeByte(src,bracketStr);
      //remove the brackets from the string
      memAddrStr = bracketStr.substr(1, (bracketStr.size()-2));
      u_long hexValue = hexStrToLong(memAddrStr, p_tempNode, p_rootNode);
      set_src_mem(memSizeBytes, hexValue, p_tempNode);
    }
    //else if (bracketStr.size() < 0) then must be a constant src like "17"
    //so create an OUTedge from the rootNode to the current tempInstruction node;
    //and create an INedge from the rootNode to the current tempInstruction node; 
    else{
      set_src_root(p_rootNode, p_tempNode);
    } 
  }
  //...
  std::pair<int, int> dstRegNumSize = checkForRegs(dst);
  //6-17 Possible Bug! this line "set_src_reg(dstRegNumSize, p_tempNode)" should be moved into the "if(dstRegNumSize.first){" scope below?
  set_src_reg(dstRegNumSize, p_tempNode);
  set_clear_flags(p_tempNode, set_flags, clear_flags);

   //if (dstRegNumSize.first) is not NULL then it must be a valid register
  if(dstRegNumSize.first){
    set_reg((dstRegNumSize.first), (dstRegNumSize.second), p_tempNode);
  }
  else{
    //else must be a const or memory dst  
    //handle memory dst 
    //1 byte = 8 bits 
    //word = 2 bytes = 16 bits  
    //double word = 4 bytes = 32 bits
    //xmm word = 16 bytes = 144 bits
    std::string bracketStr;
    std::string memAddrStr;
    bracketStr = getStringWithinBrackets(dst);

    //if the dst is a memory range, then set the new author to be current Instruction node 'p_tempNode'
    if(bracketStr.size() > 0){
      int memSizeBytes = getMemSizeByte(dst,bracketStr);
      //remove the brackets from the string
      memAddrStr = bracketStr.substr(1, (bracketStr.size()-2));              
      u_long hexValue = hexStrToLong(memAddrStr, p_tempNode, p_rootNode);
      set_src_mem(memSizeBytes, hexValue, p_tempNode);
      set_dst_mem(memSizeBytes, hexValue, p_tempNode);

    }
    else{
      //else if (dstRegNumSize.first) is equal to "null" then must be a constant like "17"
      //so create an OUTedge from the rootNode to the current tempInstruction node;
      //and create an INedge from the rootNode to the current tempInstruction node; 
      set_dst_root(p_rootNode, p_tempNode);              
    } 
  }
}

void instrument_xchg (std::string wholeInstructionString,  uint32_t set_flags, uint32_t clear_flags, Node* p_tempNode, Node* p_rootNode)
{
  
  std::vector<std::string> instrPieces = getInstrPieces(wholeInstructionString);

  std::string mnemonic = instrPieces.at(0);
  std::string dst = instrPieces.at(1);
  std::string src = instrPieces.at(2);

  std::pair<int, int> srcRegNumSize = checkForRegs(src);
  std::vector<Node*> regAuthors = get_reg_internal((srcRegNumSize.first),(srcRegNumSize.second));

  #ifdef DEBUG_PRINT
    for (auto jt = std::begin(regAuthors); jt != std::end(regAuthors); ++jt){
              std::cout<<"regAuthor is : " << (*jt)->lineNum  << "\n";
            }
  #endif

  #ifdef DEBUG_PRINT
    std::cout<< "regAuthors.empty() is " << regAuthors.empty() << "\n";
    std::cout<< "srcRegNumSize.first is " << srcRegNumSize.first << "\n";
  #endif

  //if there is a src register, set the appropriate edges to the previous author of that register
  if(srcRegNumSize.first){
    set_src_reg(srcRegNumSize, p_tempNode);
  }
  //else must be a const src or memory src  
  else{
    std::string bracketStr;
    std::string memAddrStr;
    bracketStr = getStringWithinBrackets(src);
    
    //take the bracketString of a memory address src, [0xbfffef74]
    //and convert the bracketStr to a u_long hexvalue of the memory address, 3221221236
    if(bracketStr.size() > 0){
      int memSizeBytes = getMemSizeByte(src,bracketStr);
      //remove the brackets from the string
      memAddrStr = bracketStr.substr(1, (bracketStr.size()-2));
      u_long hexValue = hexStrToLong(memAddrStr, p_tempNode, p_rootNode);
      set_src_mem(memSizeBytes, hexValue, p_tempNode);
    }
    //else if (bracketStr.size() < 0) then must be a constant src like "17"
    //so create an OUTedge from the rootNode to the current tempInstruction node;
    //and create an INedge from the rootNode to the current tempInstruction node; 
    else{
      set_src_root(p_rootNode, p_tempNode);
    } 
  }
  //...
  std::pair<int, int> dstRegNumSize = checkForRegs(dst);
  set_src_reg(dstRegNumSize, p_tempNode);
  set_clear_flags(p_tempNode, set_flags, clear_flags);

   //if (dstRegNumSize.first) is not NULL then it must be a valid register
  if(dstRegNumSize.first){
    set_reg((dstRegNumSize.first), (dstRegNumSize.second), p_tempNode);
  }
  else{
    //else must be a const or memory dst  
    //handle memory dst 
    //1 byte = 8 bits 
    //word = 2 bytes = 16 bits  
    //double word = 4 bytes = 32 bits
    //xmm word = 16 bytes = 144 bits
    std::string bracketStr;
    std::string memAddrStr;
    bracketStr = getStringWithinBrackets(dst);

    //if the dst is a memory range, then set the new author to be current Instruction node 'p_tempNode'
    if(bracketStr.size() > 0){
      int memSizeBytes = getMemSizeByte(dst,bracketStr);
      //remove the brackets from the string
      memAddrStr = bracketStr.substr(1, (bracketStr.size()-2));              
      u_long hexValue = hexStrToLong(memAddrStr, p_tempNode, p_rootNode);
      set_src_mem(memSizeBytes, hexValue, p_tempNode);
      set_dst_mem(memSizeBytes, hexValue, p_tempNode);

    }
    else{
      //else if (dstRegNumSize.first) is equal to "null" then must be a constant like "17"
      //so create an OUTedge from the rootNode to the current tempInstruction node;
      //and create an INedge from the rootNode to the current tempInstruction node; 
      set_dst_root(p_rootNode, p_tempNode);              
    } 
  }

     //if (srcRegNumSize.first) is not NULL then it must be a valid register
  if(srcRegNumSize.first){
    set_reg((srcRegNumSize.first), (srcRegNumSize.second), p_tempNode);
  }
  else{
    //else must be a const or memory dst  
    //handle memory dst 
    //1 byte = 8 bits 
    //word = 2 bytes = 16 bits  
    //double word = 4 bytes = 32 bits
    //xmm word = 16 bytes = 144 bits
    std::string bracketStr;
    std::string memAddrStr;
    bracketStr = getStringWithinBrackets(dst);

    //if the dst is a memory range, then set the new author to be current Instruction node 'p_tempNode'
    if(bracketStr.size() > 0){
      int memSizeBytes = getMemSizeByte(dst,bracketStr);
      //remove the brackets from the string
      memAddrStr = bracketStr.substr(1, (bracketStr.size()-2));              
      u_long hexValue = hexStrToLong(memAddrStr, p_tempNode, p_rootNode);
      set_dst_mem(memSizeBytes, hexValue, p_tempNode);

    }
    else{
      //else if (srcRegNumSize.first) is equal to "null" then must be a constant like "17"
      //so create an OUTedge from the rootNode to the current tempInstruction node;
      //and create an INedge from the rootNode to the current tempInstruction node; 
      set_dst_root(p_rootNode, p_tempNode);              
    } 
  }
}

void instrument_push (std::string wholeInstructionString,  uint32_t set_flags, uint32_t clear_flags, Node* p_tempNode, Node* p_rootNode)
{
  set_src_regName("esp", p_tempNode);
  std::vector<std::string> instrPieces = getInstrPieces(wholeInstructionString);

  std::string mnemonic = instrPieces.at(0);
  std::string src = instrPieces.at(1);
  
  handle_srcRegMemImm(src, p_tempNode, p_rootNode);
  set_dst_reg("esp", p_tempNode);
  #ifdef DEBUG_PRINT
  std::cout<<"(instrument_push)src is : " << src  << "\n";
  std::cout  << "\n";
  #endif
  
}

void instrument_pcmpistri (std::string wholeInstructionString,  uint32_t set_flags, uint32_t clear_flags, Node* p_tempNode, Node* p_rootNode)
{
  set_clear_flags(p_tempNode, set_flags, clear_flags);
  std::vector<std::string> instrPieces = getInstrPieces(wholeInstructionString);

  std::string mnemonic = instrPieces.at(0);
  std::string src = instrPieces.at(1);
  std::string srcB = instrPieces.at(2);
  
  handle_srcRegMemImm(src, p_tempNode, p_rootNode);
  handle_srcRegMemImm(srcB, p_tempNode, p_rootNode);
  set_dst_reg("ecx", p_tempNode);
  #ifdef DEBUG_PRINT
  std::cout<<"(instrument_pcmpistri)src is : " << src  << "\n";
  std::cout<<"(instrument_pcmpistri)srcB is : " << srcB  << "\n";
  std::cout  << "\n";
  #endif
  
}

void instrument_pop (std::string wholeInstructionString,  uint32_t set_flags, uint32_t clear_flags, Node* p_tempNode, Node* p_rootNode)
{
  set_src_regName("esp", p_tempNode);
  std::vector<std::string> instrPieces = getInstrPieces(wholeInstructionString);

  std::string mnemonic = instrPieces.at(0);
  std::string dst = instrPieces.at(1);
  
  handle_dstRegMemImm(dst, p_tempNode, p_rootNode);
  set_dst_reg("esp", p_tempNode);
  #ifdef DEBUG_PRINT
  std::cout<<"(instrument_pop)dst is : " << dst  << "\n";
  std::cout  << "\n";
  #endif
}

void instrument_neg_not (std::string wholeInstructionString,  uint32_t set_flags, uint32_t clear_flags, Node* p_tempNode, Node* p_rootNode)
{
  set_clear_flags(p_tempNode, set_flags, clear_flags);
  std::vector<std::string> instrPieces = getInstrPieces(wholeInstructionString);

  std::string mnemonic = instrPieces.at(0);
  std::string src = instrPieces.at(1);
  
  handle_srcRegMemImm(src, p_tempNode, p_rootNode);
  handle_dstRegMemImm(src, p_tempNode, p_rootNode);
  #ifdef DEBUG_PRINT
  std::cout<<"(instrument_neg_not)src is : " << src  << "\n";
  std::cout  << "\n";
  #endif
}

void instrument_rep_movsd (std::string wholeInstructionString,  uint32_t set_flags, uint32_t clear_flags, Node* p_tempNode, Node* p_rootNode)
{
  set_src_flags(p_tempNode, DF_FLAG);
  set_src_regName("ecx", p_tempNode);
  
  handle_srcRegMemImm("ds", p_tempNode, p_rootNode);
  handle_srcRegMemImm("esi", p_tempNode, p_rootNode);
  handle_dstRegMemImm("esi", p_tempNode, p_rootNode);
  handle_dstRegMemImm("edi", p_tempNode, p_rootNode);

  #ifdef DEBUG_PRINT
  std::cout<<"(instrument_rep_movsd)src is : " << "ds"  << "\n";
  std::cout  << "\n";
  #endif
}

void instrument_repne_scasb (std::string wholeInstructionString,  uint32_t set_flags, uint32_t clear_flags, Node* p_tempNode, Node* p_rootNode)
{
  set_src_flags(p_tempNode, DF_FLAG|ZF_FLAG);
  set_src_regName("ecx", p_tempNode);
  
  handle_srcRegMemImm("es", p_tempNode, p_rootNode);
  handle_srcRegMemImm("edi", p_tempNode, p_rootNode);
  handle_srcRegMemImm("al", p_tempNode, p_rootNode);
  handle_dstRegMemImm("edi", p_tempNode, p_rootNode);

  set_clear_flags(p_tempNode, set_flags, clear_flags);

  #ifdef DEBUG_PRINT
  std::cout<<"(instrument_repne_scasb)src is : " << "es"  << "\n";
  std::cout  << "\n";
  #endif
}

void instrument_cwde (std::string wholeInstructionString,  uint32_t set_flags, uint32_t clear_flags, Node* p_tempNode, Node* p_rootNode)
{  
  handle_srcRegMemImm("ax", p_tempNode, p_rootNode);
  handle_dstRegMemImm("eax", p_tempNode, p_rootNode);

  #ifdef DEBUG_PRINT
  std::cout<<"(instrument_cwde)src is : " << "ax"  << "\n";
  std::cout  << "\n";
  #endif
}


void instrument_mov (std::string wholeInstructionString,  uint32_t set_flags, uint32_t clear_flags, Node* p_tempNode, Node* p_rootNode)
{
  
  std::vector<std::string> instrPieces = getInstrPieces(wholeInstructionString);

  std::string mnemonic = instrPieces.at(0);
  std::string dst = instrPieces.at(1);
  std::string src = instrPieces.at(2);

  #ifdef DEBUG_PRINT
    std::cout<<"mnemonic is: " << mnemonic  << "\n";
    std::cout<<"dst is : " << dst  << "\n";
    std::cout<<"src is : " << src  << "\n";
  #endif

  set_clear_flags(p_tempNode, set_flags, clear_flags);

  std::pair<int, int> srcRegNumSize = checkForRegs(src);
  std::vector<Node*> regAuthors = get_reg_internal((srcRegNumSize.first),(srcRegNumSize.second));

  #ifdef DEBUG_PRINT
    for (auto jt = std::begin(regAuthors); jt != std::end(regAuthors); ++jt){
              std::cout<<"regAuthor is : " << (*jt)->lineNum  << "\n";
            }
  #endif

  #ifdef DEBUG_PRINT
    std::cout<< "regAuthors.empty() is " << regAuthors.empty() << "\n";
    std::cout<< "srcRegNumSize.first is " << srcRegNumSize.first << "\n";
  #endif

  int memSizeBytes = 0;
  u_long hexValue = 0;

  //if there is a src register, set the appropriate edges to the previous author of that register
  if(srcRegNumSize.first){
    set_src_reg(srcRegNumSize, p_tempNode);
  }
  //else must be a const src or memory src  
  else{
    std::string bracketStr;
    std::string memAddrStr;
    bracketStr = getStringWithinBrackets(src);
    
    //take the bracketString of a memory address src, [0xbfffef74]
    //and convert the bracketStr to a u_long hexvalue of the memory address, 3221221236
    if(bracketStr.size() > 0){
      memSizeBytes = getMemSizeByte(src,bracketStr);
      //remove the brackets from the string
      memAddrStr = bracketStr.substr(1, (bracketStr.size()-2));
      hexValue = hexStrToLong(memAddrStr, p_tempNode, p_rootNode);
      set_src_mem(memSizeBytes, hexValue, p_tempNode);
    }
    //else if (bracketStr.size() < 0) then must be a constant src like "17"
    //so create an OUTedge from the rootNode to the current tempInstruction node;
    //and create an INedge from the rootNode to the current tempInstruction node; 
    else{
      set_src_root(p_rootNode, p_tempNode);
    } 
  }
  //...
  std::pair<int, int> dstRegNumSize = checkForRegs(dst);

   //if (dstRegNumSize.first) is not NULL then it must be a valid register
  if(dstRegNumSize.first){
    #ifdef VAL_EQV
      //if srcMem and dstReg, then get the last author of that memory range and check if the dst Reg already has that same authors. If yes dstReg has the same authors as the memory range, then mark instruction as EXTRA=1" 
       if (memSizeBytes)
       {
         if(hexValue){
           std::vector<Node*> dstRegAuthors = get_reg_internal((dstRegNumSize.first),(dstRegNumSize.second));
           if (dstRegAuthors == mapMemValue[hexValue])
           {
             p_tempNode->extra = 1;
           }
         }
         
       }
     #endif
     //if the instruction node is not extra then set the reg with the p_tempNode as the new author.
     if ((p_tempNode-> extra) == 0){
      set_reg((dstRegNumSize.first), (dstRegNumSize.second), p_tempNode);
     } 
     
     
  }
  else{
    //else must be a const or memory dst  
    //handle memory dst 
    //1 byte = 8 bits 
    //word = 2 bytes = 16 bits  
    //double word = 4 bytes = 32 bits
    //xmm word = 16 bytes = 144 bits
    std::string bracketStr;
    std::string memAddrStr;
    bracketStr = getStringWithinBrackets(dst);

    //if the dst is a memory range, then set the new author to be current Instruction node 'p_tempNode'
    if(bracketStr.size() > 0){
      int memSizeBytes = getMemSizeByte(dst,bracketStr);
      //remove the brackets from the string
      memAddrStr = bracketStr.substr(1, (bracketStr.size()-2));              
      u_long hexValue = hexStrToLong(memAddrStr, p_tempNode, p_rootNode);
     

      if(srcRegNumSize.first){
        #ifdef DEBUG_PRINT
          std::cout<< "(instrument_mov)srcReg and dstMem DETECTED!\n";
        #endif
        #ifdef VAL_EQV
          //if memDst already has the value of srcReg, then dont set the dst_mem author to p_tempNode and mark p_tempNode as extra.
          if (regAuthors == mapMemValue[(hexValue)]){
            p_tempNode->extra = 1;
          }
        #endif
        if(!(regAuthors == mapMemValue[(hexValue)])){
           set_dst_mem(memSizeBytes, hexValue, p_tempNode);
           //if srcReg and dstMem, then get the last author of that source reg and associate it with the memory address dst.
           #ifdef VAL_EQV
             mapMemValue[(hexValue)] = regAuthors;
           #endif
        }
        
      }
    }
    else{
      //else if (dstRegNumSize.first) is equal to "null" then must be a constant like "17"
      //so create an OUTedge from the rootNode to the current tempInstruction node;
      //and create an INedge from the rootNode to the current tempInstruction node; 
      set_dst_root(p_rootNode, p_tempNode);              
    } 
  }
}

int mark_ancestors (Node* p_tempNode){
  if ((p_tempNode->lineNum) == 0){
    return 1;
  }
  #ifdef DEBUG_PRINT
    std::cout<<"(mark_ancestors for node->lineNum: " << (p_tempNode->lineNum) << "\n";
  #endif
  if((p_tempNode-> extra) != 0){
    p_tempNode-> extra = 0;
    for (auto ut = std::begin((p_tempNode->inEdges)); ut != std::end((p_tempNode->inEdges)); ++ut)
    {
      mark_ancestors((*ut)->start);
    }
  }
  
  return 0; 
}

void instrument_jump (Node* p_tempNode, uint32_t src_flags){
  set_src_flags(p_tempNode, src_flags);
  jumps.push_back(p_tempNode);
}

void instrument_call (Node* p_tempNode, uint32_t src_flags){
  calls.push_back(p_tempNode);
}      

void instrument_instruction (std::string mnemonic, Node* p_tempNode, Node* p_rootNode, std::string wholeInstructionString)
{
  InstType instType = mapStringToInstType[mnemonic];
  switch (instType)
  {   
      case InstType::call:
          instrument_call(p_tempNode, 0);
           break;
      case InstType::jle:
      case InstType::jnle:
          instrument_jump(p_tempNode, ZF_FLAG|SF_FLAG|OF_FLAG);
           break;
      case InstType::jl:
      case InstType::jnl:
          instrument_jump(p_tempNode, SF_FLAG|OF_FLAG);
           break;
      case InstType::jz:
      case InstType::jne:
      case InstType::jnz:
          instrument_jump(p_tempNode, ZF_FLAG);
          break;
      case InstType::jns:
      case InstType::js:
          instrument_jump(p_tempNode, SF_FLAG);
          break;
      case InstType::jnbe:
      case InstType::jbe:
          instrument_jump(p_tempNode, CF_FLAG|ZF_FLAG);
           break;
      case InstType::jnb:
      case InstType::jb:
      case InstType::jae:
          instrument_jump(p_tempNode, CF_FLAG);
          break;
      case InstType::cmovbe:
      case InstType::cmovnbe:
          set_src_flags(p_tempNode, CF_FLAG|ZF_FLAG);
          instrument_mov(wholeInstructionString, 0, 0, p_tempNode, p_rootNode);
          break;
      case InstType::cmovz:
      case InstType::cmovnz:
          set_src_flags(p_tempNode, ZF_FLAG);
          instrument_mov(wholeInstructionString, 0, 0, p_tempNode, p_rootNode);
          break;
      case InstType::cmovb:
      case InstType::cmovnb:
          set_src_flags(p_tempNode, CF_FLAG);
          instrument_mov(wholeInstructionString, 0, 0, p_tempNode, p_rootNode);
          break;
      case InstType::cmovs:
      case InstType::cmovns:
          set_src_flags(p_tempNode, SF_FLAG);
          instrument_mov(wholeInstructionString, 0, 0, p_tempNode, p_rootNode);
          break;
      case InstType::cmovnle:
      case InstType::cmovle:
          set_src_flags(p_tempNode, ZF_FLAG|SF_FLAG|OF_FLAG);
          instrument_mov(wholeInstructionString, 0, 0, p_tempNode, p_rootNode);
          break;
      case InstType::cmovl:
      case InstType::cmovnl:
          set_src_flags(p_tempNode, SF_FLAG|OF_FLAG);
          instrument_mov(wholeInstructionString, 0, 0, p_tempNode, p_rootNode);
          break;
      case InstType::xchg:
          instrument_xchg(wholeInstructionString, 0, 0, p_tempNode, p_rootNode);
          break;
      case InstType::xadd:
          instrument_xchg(wholeInstructionString, 0, 0, p_tempNode, p_rootNode);
          instrument_addorsub(wholeInstructionString, SF_FLAG|ZF_FLAG|PF_FLAG|OF_FLAG|CF_FLAG|AF_FLAG, 0, p_tempNode, p_rootNode);
          break;
      //have to add a 'Z' character to these mnemonic enumerator values because 'and' 'or' 'xor' are reserved keywords in C
      case InstType::Zand:
      case InstType::Zor:
      case InstType::Zxor:
          instrument_addorsub(wholeInstructionString, SF_FLAG|ZF_FLAG|PF_FLAG, OF_FLAG|CF_FLAG|AF_FLAG, p_tempNode, p_rootNode);
          break;
      case InstType::pand:
      case InstType::por:
      case InstType::pxor:
          instrument_addorsub(wholeInstructionString, 0, 0, p_tempNode, p_rootNode);
          break;
      case InstType::add:
      case InstType::sub:
      case InstType::adc:
          instrument_addorsub(wholeInstructionString, SF_FLAG|ZF_FLAG|PF_FLAG|OF_FLAG|CF_FLAG|AF_FLAG, 0, p_tempNode, p_rootNode);
          break;
      case InstType::shl:
      case InstType::sar:
      case InstType::sal:
      case InstType::shr:
          instrument_addorsub(wholeInstructionString, CF_FLAG|OF_FLAG|SF_FLAG|ZF_FLAG|PF_FLAG|AF_FLAG, 0, p_tempNode, p_rootNode);
          break;
      case InstType::neg:
          instrument_neg_not(wholeInstructionString, CF_FLAG|OF_FLAG|SF_FLAG|ZF_FLAG|PF_FLAG|AF_FLAG, 0, p_tempNode, p_rootNode);
          break;
      case InstType::Znot:
          instrument_neg_not(wholeInstructionString, 0, 0, p_tempNode, p_rootNode);
          break;
      case InstType::mov:
      case InstType::movzx:
      case InstType::movsx:
      case InstType::movdqu:
      case InstType::pmovmskb:
      case InstType::pcmpeqb:
          instrument_mov(wholeInstructionString, 0, 0, p_tempNode, p_rootNode);
          break;
      case InstType::bsf:
          instrument_mov(wholeInstructionString, SF_FLAG|ZF_FLAG|PF_FLAG|OF_FLAG|CF_FLAG|AF_FLAG, 0, p_tempNode, p_rootNode);
          break;
      case InstType::div:
      case InstType::idiv:
          instrument_div(wholeInstructionString, SF_FLAG|ZF_FLAG|PF_FLAG|OF_FLAG|CF_FLAG|AF_FLAG, 0, p_tempNode, p_rootNode);
          break;
      case InstType::mul:
          instrument_mul(wholeInstructionString, CF_FLAG|OF_FLAG, SF_FLAG|ZF_FLAG|AF_FLAG|PF_FLAG, p_tempNode, p_rootNode);
          break;
      case InstType::imul:
          instrument_imul(wholeInstructionString, CF_FLAG|OF_FLAG, SF_FLAG|ZF_FLAG|AF_FLAG|PF_FLAG, p_tempNode, p_rootNode);
          break;
      case InstType::cmp:
      case InstType::test:
      case InstType::ptest:
          instrument_cmp_or_test(wholeInstructionString, CF_FLAG|OF_FLAG, SF_FLAG|ZF_FLAG|AF_FLAG|PF_FLAG, p_tempNode, p_rootNode);
          break;
      case InstType::setnz:
      case InstType::setz:
          set_src_flags(p_tempNode, ZF_FLAG);
          instrument_set(wholeInstructionString, 0, 0, p_tempNode, p_rootNode);
          break;
      case InstType::sets:
          set_src_flags(p_tempNode, SF_FLAG);
          instrument_set(wholeInstructionString, 0, 0, p_tempNode, p_rootNode);
          break;
      case InstType::setb:
          set_src_flags(p_tempNode, CF_FLAG);
          instrument_set(wholeInstructionString, 0, 0, p_tempNode, p_rootNode);
          break;
      case InstType::pushfd:
          set_src_regName("esp", p_tempNode);
          set_src_flags(p_tempNode, CF_FLAG|PF_FLAG|AF_FLAG|ZF_FLAG|SF_FLAG|OF_FLAG|DF_FLAG);
          set_dst_reg("esp", p_tempNode);
          break;
      case InstType::push:
      case InstType::pushw:
          instrument_push(wholeInstructionString, 0, 0, p_tempNode, p_rootNode);
          break;
      case InstType::popfd:
          set_src_regName("esp", p_tempNode);
          set_clear_flags(p_tempNode, CF_FLAG|PF_FLAG|AF_FLAG|ZF_FLAG|SF_FLAG|OF_FLAG|DF_FLAG, 0);
          set_dst_reg("esp", p_tempNode);
          break;
      case InstType::pop:
          instrument_pop(wholeInstructionString, 0, 0, p_tempNode, p_rootNode);
          break;
      case InstType::pcmpistri:
          instrument_pcmpistri(wholeInstructionString, CF_FLAG|PF_FLAG|AF_FLAG|ZF_FLAG|SF_FLAG|OF_FLAG, 0, p_tempNode, p_rootNode);
          break;
      case InstType::rep:
          instrument_rep_movsd(wholeInstructionString, 0, 0, p_tempNode, p_rootNode);
          break;
      case InstType::repne:
          instrument_repne_scasb(wholeInstructionString, CF_FLAG|PF_FLAG|AF_FLAG|ZF_FLAG|SF_FLAG|OF_FLAG, 0, p_tempNode, p_rootNode);
          break;
      case InstType::cld:
          set_clear_flags(p_tempNode, DF_FLAG, 0);
          break;
      case InstType::cwde:
          instrument_cwde(wholeInstructionString, 0, 0, p_tempNode, p_rootNode);
          break;
      case InstType::fld:
      case InstType::fxch:
      case InstType::fstp:
      case InstType::fild:
      case InstType::fmulp:
      case InstType::fistp:
          (p_tempNode->extra) = 0;
          break;
      case InstType::ret:
          set_src_regName("esp", p_tempNode);
          set_dst_reg("esp", p_tempNode);
          break;
      default:
          std::cout<< "[ERROR1]Unknown InstType mnemonic: " << mnemonic << "\n";
          //std::cout<< "[ERROR]Unknown InstType " << mapInstTypeToString[instType] << "\n";
  }
  //6-22-18 this is bugged. doesnt print error when unknown inst type is encountered.
  if((mapStringToInstType.find(mnemonic)) == mapStringToInstType.end()){
    std::cout<< "[ERROR2]Unknown InstType mnemonic: " << mnemonic << "\n";
  }
  //this is bugged. doesnt print error when unknown inst type is encountered.
  /*
  if(mnemonic == "pmovmskb"){
    std::cout<< "[ERROR3]Unknown InstType mnemonic: " << mnemonic << (p_tempNode->lineNum) <<"\n";
  }
  */
}
  int main(int,char*[])
  {

    //...
    auto t1 = Clock::now();
    
    //std::string filename("JUMPDexslice1.8151.c");
    //std::string filename("8151testslice50000.c");
    std::string filename("gccexslice1.2896.c");
    boost::iostreams::stream<boost::iostreams::file_source>file(filename.c_str());
    std::string line;
    int lineNum = 0;
    instrGraph* p_sliceGraph = new instrGraph();
    std::vector<std::string> instructionPieces;
    std::vector<std::string> tempPieces;
    Node* p_rootNode = new Node();
    Edge* ptempEdge = new Edge();
    p_rootNode->outEdges.push_back(ptempEdge);
    p_rootNode->outEdges[0]->start = p_rootNode;
    p_rootNode->inEdges.push_back(ptempEdge);
    p_rootNode->lineNum = 0;

    set_reg(0,1920,p_rootNode);
    set_clear_flags(p_rootNode, ALL_FLAGS, 0);

    #ifdef DEBUG_PRINT
      for (auto flagIt = std::begin(eflags_table); flagIt != std::end(eflags_table); ++flagIt){
        std::cout<<"eflags REGISTER authors: " << (*flagIt)->lineNum << "\n";
      }
    #endif

    std::cout<<"(main) Started processing exslice.c file: " << "\n";
    auto tb = Clock::now();
    std::cout << "Delta tb-t1: " 
              << (std::chrono::duration_cast<std::chrono::nanoseconds>(tb - t1).count())/1000000000.0
              << " seconds" << std::endl;  

    while (std::getline(file, line)) {
      lineNum++;
      #ifdef DEBUG_PRINT
        std::cout<< lineNum << "\n";
      #endif
      //Start reading actual slice instructions starting at line 5 (because the first 4 lines are padding that always need to be kept)
      if(lineNum >= 5){
        //this last line in exslice1.c is not really a slice instruction. Instead it is the last line of the exslice1.c file, );
        if(!(contains(line, ");"))){
          #ifdef DEBUG_PRINT
            std::cout<<"(main) line: "<<line << "\n";
          #endif
          if ((line.substr(1,2)).compare("b_") == 0)
            {

              line = line.substr(1,line.length());
              line = "\"call " + line;
              #ifdef DEBUG_PRINT
                std::cout<<"(main)3 line: "<<line << "\n";
              #endif
            } 
          #ifdef DEBUG_PRINT
            std::cout<<"(main) line: "<<line << "\n";
          #endif
          std::string mnemonic = getMnemonic(line);
          //need to eventually delete this dynamically allocated memory
          Node* p_tempNode = new Node();
          
          #ifdef DEBUG_PRINT
            //std::cout<< p_tempNode->lineNum << "\n";
            std::cout<< line << "\n";
          #endif
          
          //setting the new instruction nodes' unique lineNum to its corresponding lineNum in the original exslice.c file.
          p_tempNode->lineNum = lineNum;

          instrument_instruction(mnemonic, p_tempNode, p_rootNode, line);

          //add the completed node with dst edges and src edges to the graph
          p_sliceGraph->nodes.push_back(p_tempNode);
        }
      }
    }

    //...
    file.close();
    
    std::cout<<"\n(main) Finished processing exslice.c file: " << "\n";
    auto ta = Clock::now();
    std::cout << "Delta ta-t1: " 
              << std::chrono::duration_cast<std::chrono::nanoseconds>(ta - t1).count()/1000000000.0
              << " seconds" << std::endl;
    

    //get authors and mark them as EXTRA(removeable) or not extra (neccessary for the ouputs we care about)
    //int co = 0;
    for (auto shadowIt = std::begin(shadow_reg_table); shadowIt != std::end(shadow_reg_table); ++shadowIt){
      if (((*shadowIt)->lineNum) != 0){
        outputNodes.insert((*shadowIt));
        //mark_ancestors((*shadowIt));
        //std::cout<<"shadow_reg_table REGISTER authors: " << co << ", "  << (*shadowIt)->lineNum << "\n";
        //co++;
      }
    }

    for (auto flagIt = std::begin(eflags_table); flagIt != std::end(eflags_table); ++flagIt){
      outputNodes.insert((*flagIt));
      //mark_ancestors((*flagIt));
      //std::cout<<"eflags REGISTER authors: " << (*flagIt)->lineNum << "\n";
    }

    for (auto jumpIt = std::begin(jumps); jumpIt != std::end(jumps); ++jumpIt){
      outputNodes.insert((*jumpIt));
      //mark_ancestors((*flagIt));
      //std::cout<<"jump's ancestors marked. jump at line: " << (*flagIt)->lineNum << "\n";
    }

    for (auto callIt = std::begin(calls); callIt != std::end(calls); ++callIt){
      outputNodes.insert((*callIt));
      //mark_ancestors((*flagIt));
      //std::cout<<"calls's ancestors marked. call at line: " << (*flagIt)->lineNum << "\n";
    }


    for (auto const& x : mapMem)
    {
      outputNodes.insert((x.second));
      //mark_ancestors(x.second);
      //std::cout<<"memory's ancestors marked. memory at : " << x.first << " written to by line " <<(x.second)->lineNum<< "\n";
    }


    //bfs marking all ancestors of outputNodes
    std::list <Node *> queue;

    for (auto const& outputN : outputNodes)
    {
      outputN->visited = 1;
      queue.push_back(outputN);

      std::list<Node *>::iterator iterq;
      while(!queue.empty()){
        Node * vNode = queue.front();
        #ifdef DEBUG_PRINT
        std::cout << vNode->lineNum << " visited. \n";
        #endif
        queue.pop_front();

        for (auto edgeIt2 = std::begin((vNode)->inEdges); edgeIt2 != std::end((vNode)->inEdges); ++edgeIt2){
          #ifdef DEBUG_PRINT
          std::cout << vNode->lineNum << " inEdge is " << ((*edgeIt2)->start)->lineNum << "\n";
          #endif
          if(((*edgeIt2)->start)->visited == 0){
            ((*edgeIt2)->start)->visited = 1;
            queue.push_back(((*edgeIt2)->start));
          }
        }
      }
    }


    int allNodeCount = 0;
    int extraNodeCount = 0;
    for (auto const& allNode : (p_sliceGraph->nodes))
    {
      #ifdef DEBUG_PRINT
      std::cout<<"allNode: lineNum, visited " << allNode->lineNum << ", " << allNode->visited << "\n";
      #endif
      if((allNode->visited) == 0){
        extraNodes.push_back(allNode);
        extraNodeCount++;
      }
    } 

    
    for (auto it = std::begin(p_sliceGraph->nodes); it != std::end(p_sliceGraph->nodes); ++it){
      allNodeCount++;
      
      #ifdef DEBUG_PRINT
        std::cout<< ((*it)->lineNum) << " ,extra is: " << ((*it)->extra) <<"\n";
        for (auto ut = std::begin(((*it)->inEdges)); ut != std::end(((*it)->inEdges)); ++ut){
          std::cout <<" inEdges: "<<((*ut)->start)->lineNum << "->" << ((*ut)->finish)->lineNum << " ";
        }
        std::cout<<"\n";
        for (auto kt = std::begin(((*it)->outEdges)); kt != std::end(((*it)->outEdges)); ++kt){
          std::cout<< " outEdges: "<<((*kt)->start)->lineNum << "->" << ((*kt)->finish)->lineNum << " ";
        }
        std::cout<<"\n";
      #endif
    }

    

    #ifdef DEBUG_PRINT
      for (auto const& extras : extraNodes)
      {
        std::cout<<"Extra Node at line : " << extras->lineNum << "\n";
      }
    #endif
   

    std::cout<<"\nOriginal Instruction Count is : " << allNodeCount << "\n";
    std::cout<<"Extra Instruction Count is : " << extraNodeCount << "\n";


    std::cout<<"\n(main) Finished doing backwards-pass over Graph.: " << "\n";
    auto t2 = Clock::now();
    std::cout << "Delta t2-t1: " 
              << std::chrono::duration_cast<std::chrono::nanoseconds>(t2 - t1).count()/1000000000.0
              << " seconds" << std::endl;
    //...
    std::remove("optInfo.txt"); //delete old outfile1, optInfo.txt to make room for new one.
    
    std::ofstream outfile1;
    outfile1.open ("optInfo.txt");

    if (outfile1.is_open()){
      outfile1<<"Original filename is: " << filename << "\n";
      outfile1<<"\nOriginal Instruction Count is : " << allNodeCount << "\n";
      outfile1<<"Extra Instruction Count is : " << extraNodeCount << "\n\n" << "====" << "\n";
      for (auto const& extra1 : extraNodes)
      {
        outfile1<<"Extra Node at line : " << extra1->lineNum << ", node->extra is:" << extra1->extra << "\n";
      }
      outfile1.close();
    }
    else{
        std::cout<< "[ERROR] Unable to open outfile1, optInfo.txt.";
    }

    

    

    //...Delete mem operations here
    delete p_rootNode;
    delete ptempEdge;
    //iterate through each node in the slice Graph
    //for each node, iterate through its inEdges and outEdges and delete each edge pointer
    //then finally delete every node in the slice Graph
    for (auto it = std::begin(p_sliceGraph->nodes); it != std::end(p_sliceGraph->nodes); ++it){
      for (auto edgeIt2 = std::begin((*it)->inEdges); edgeIt2 != std::end((*it)->inEdges); ++edgeIt2){
        delete (*edgeIt2);
      }
      for (auto edgeIt3 = std::begin((*it)->outEdges); edgeIt3 != std::end((*it)->outEdges); ++edgeIt3){
        delete (*edgeIt3);
      }
    }
    for (auto nodeIt = std::begin(p_sliceGraph->nodes); nodeIt != std::end(p_sliceGraph->nodes); ++nodeIt){
      delete (*nodeIt);
    }
    delete p_sliceGraph;

   

    /* 6-25-18 come back to this boost graph lib work

    // create a typedef for the Graph type
    typedef adjacency_list<setS, vecS, bidirectionalS> digraph;

    // Make convenient labels for the vertices
    enum { A, B, C, D, E, N };
    const int num_vertices = N;
    const char* name = "ABCDE";

    // writing out the edges in the graph
    typedef std::pair<int, int> Edge;
    Edge edge_array[] = 
    { Edge(A,B), Edge(A,D), Edge(C,A), Edge(D,C),
      Edge(C,E), Edge(B,D), Edge(D,E) };
    const int num_edges = sizeof(edge_array)/sizeof(edge_array[0]);

    // declare a graph object
    digraph g(num_vertices);

    //...
    add_edge(0,4, g);
    //...

    // add the edges to the graph object
    for (int i = 0; i < num_edges; ++i)
      add_edge(edge_array[i].first, edge_array[i].second, g);
    
    //...

    typedef graph_traits<digraph>::vertex_descriptor Vertex;

    // get the property map for vertex indices
    typedef property_map<digraph, vertex_index_t>::type IndexMap;
    IndexMap index = get(vertex_index, g);

    std::cout << "vertices(g) = ";
    typedef graph_traits<digraph>::vertex_iterator vertex_iter;
    std::pair<vertex_iter, vertex_iter> vp;
    for (vp = vertices(g); vp.first != vp.second; ++vp.first) {
      Vertex v = *vp.first;
      std::cout << index[v] <<  " ";
    }
    std::cout << std::endl;

    // ...
    std::cout << "edges(g) = ";
    graph_traits<digraph>::edge_iterator ei, ei_end;
    for (boost::tie(ei, ei_end) = edges(g); ei != ei_end; ++ei)
        std::cout << "(" << index[source(*ei, g)] 
                  << "," << index[target(*ei, g)] << ") ";
    std::cout << std::endl;

    // ...
     write_graphviz(std::cout, g);

    */

    //...
    return 0;
  }
