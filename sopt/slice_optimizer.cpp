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
          shadow_reg_table[(reg * REG_SIZE + i)+offset] = author;
          #ifdef DEBUG_PRINT
            std::cout<< "Setting shadow_reg_table at " << (reg * REG_SIZE + i) << "to " << author->lineNum << "\n";
            std::cout<< regNumSize.first << "\n";
            std::cout<< regNumSize.second << "\n";
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

  //...
  void taint_reg2reg_offset (int dst_reg_off, int src_reg_off, uint32_t size, uint32_t set_flags, uint32_t clear_flags)
  {
      unsigned i;
     // taint_t* shadow_reg_table = current_thread->shadow_reg_table;
     // taint_t t = 0;
      Node* t = NULL;

      for (i = 0; i < size; i++) {
    //t = merge_taints(shadow_reg_table[dst_reg_off + i], shadow_reg_table[src_reg_off + i]);
    shadow_reg_table[dst_reg_off + i]  = t;
      } 

      //set_clear_flags (&shadow_reg_table[REG_EFLAGS*REG_SIZE], t, set_flags, clear_flags);
  }

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

  u_long hexStrToLong(std::string bracketStr){
    std::istringstream hexstr(bracketStr);
    u_long hexValue;
    hexstr >> std::hex >> hexValue;
    #ifdef DEBUG_PRINT
      std::cout<< "hexStrToLong has contents! " << bracketStr << ", " << hexValue <<"\n";
    #endif
    return hexValue;
  }

  int getMemSizeByte(std::string src, std::string bracketStr){
    std::string memSizeStr;
    memSizeStr = src.substr(0, src.find("ptr"));
    std::cout << "getMemSize:" << memSizeStr << "\n";
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
      std::cout<<"srcmemSize:" << memSize << "\n";
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
    
  int main(int,char*[])
  {

    std::string filename("memRegtestslice.c");
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

    while (std::getline(file, line)) {
      lineNum++;

      //Start reading actual slice instructions starting at line 5 (because the first 4 lines are padding that always need to be kept)
      if(lineNum >= 5){
        //this last line in exslice1.c is not really a slice instruction. Instead it is the last line of the exslice1.c file, );
        if(!(contains(line, ");"))){

          std::string mnemonic;
          std::string istr;
          std::string dst;
          std::string src;

          std::sregex_iterator end;

          std::regex allPreExtra("^.*(?=(\\/\\*))");
          auto iterPreExtra = std::sregex_iterator(line.begin(), line.end(), allPreExtra);
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

          std::cout<<"istr:"<<istr<<"\n";

          dst = istr.substr((istr.find(mnemonic)+mnemonic.size()+1), (istr.find(',')-mnemonic.size()-1));

          src = istr.substr((istr.find(',')+2), (istr.size()-2));

          //trim off pre AND post whitespace from the registerName string
          ltrim(src);
          ltrim(dst);
          ltrim(mnemonic);
          rtrim(src);
          rtrim(dst);
          rtrim(mnemonic);

          std::cout<<"mnemonic Arg: "<<mnemonic<<"\n";
          std::cout<<"dst Arg: "<<dst<<"\n";
          std::cout<<"src Arg: "<<src<<"\n";

          //need to eventually delete this dynamically allocated memory
          Node* p_tempNode = new Node();
          
          #ifdef DEBUG_PRINT
            //std::cout<< p_tempNode->lineNum << "\n";
            std::cout<< line << "\n";
          #endif
          
          //setting the new instruction nodes' unique lineNum to its corresponding lineNum in the original exslice.c file.
          p_tempNode->lineNum = lineNum;

          Edge* p_tempInEdge = new Edge();
          Edge* p_tempOutEdge = new Edge();

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
              u_long hexValue = hexStrToLong(memAddrStr);
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

          //if there is BOTH dstReg, srcReg
          if((srcRegNumSize.first) && (dstRegNumSize.first)){
            #ifdef DEBUG_PRINT
            std::cout << "WOW! srcReg, dstReg detected. " << p_tempNode->lineNum << "\n";
            #endif
            if(addLikeInstr.find(mnemonic) != addLikeInstr.end()){
              #ifdef DEBUG_PRINT
              std::cout << "WOW2! addLikeInstr() found. " << mnemonic << "\n";
              #endif
              //for addLikeInstructions the dst register is also a src Register before the result of the addition is put into the dst register.
              //add dst/src1, src2
              set_src_reg(dstRegNumSize, p_tempNode);
            }
          }

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
              u_long hexValue = hexStrToLong(memAddrStr);
              set_dst_mem(memSizeBytes, hexValue, p_tempNode);

            }
            else{
              //else if (dstRegNumSize.first) is equal to "null" then must be a constant like "17"
              //so create an OUTedge from the rootNode to the current tempInstruction node;
              //and create an INedge from the rootNode to the current tempInstruction node; 
              set_dst_root(p_rootNode, p_tempNode);              
            } 


          }
          //add the completed node with dst edges and src edges to the graph
          p_sliceGraph->nodes.push_back(p_tempNode);
        }
      }
    }

    std::cout<< "now printing all the nodes (identified by their line numbers) in our sliceGraph.\n";
    for (auto it = std::begin(p_sliceGraph->nodes); it != std::end(p_sliceGraph->nodes); ++it){
      std::cout<< ((*it)->lineNum) <<"\n";
      for (auto ut = std::begin(((*it)->inEdges)); ut != std::end(((*it)->inEdges)); ++ut){
        std::cout <<" inEdges: "<<((*ut)->start)->lineNum << "->" << ((*ut)->finish)->lineNum << " ";
      }
      std::cout<<"\n";
      for (auto kt = std::begin(((*it)->outEdges)); kt != std::end(((*it)->outEdges)); ++kt){
        std::cout<< " outEdges: "<<((*kt)->start)->lineNum << "->" << ((*kt)->finish)->lineNum << " ";
      }
      std::cout<<"\n";
    }

    for (auto it = std::begin(mapMem); it != std::end(mapMem); ++it){
      std::cout<<"mapMem [addr],authors: " << (*it).first << ", " << ((*it).second)->lineNum << "\n";
    }

    #ifdef DEBUG_PRINT
    for (auto it = std::begin(cmovToFlags); it != std::end(cmovToFlags); ++it){
      std::cout<<"cmovToFlags [mnemonic],{flags,}: " << (*it).first << ", " ;
      for (auto flagIter = std::begin(((*it).second)); flagIter != std::end(((*it).second)); ++flagIter){
        std::cout << (*flagIter) << ",";
      }
      std::cout << "\n";
    }
    #endif

    #ifdef DEBUG_PRINT
      std::vector<Node*> regAuthors2 = get_reg_internal((8),(4));
            for (auto it = std::begin(regAuthors2); it != std::end(regAuthors2); ++it){
              std::cout<<"edx REGISTER authors: " << (*it)->lineNum << "\n";
            }
    #endif

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

    //...

    // create a typedef for the Graph type
    typedef adjacency_list<vecS, vecS, bidirectionalS> Graph;

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
    Graph g(num_vertices);

    // add the edges to the graph object
    for (int i = 0; i < num_edges; ++i)
      add_edge(edge_array[i].first, edge_array[i].second, g);
    
    //...

    typedef graph_traits<Graph>::vertex_descriptor Vertex;

    // get the property map for vertex indices
    typedef property_map<Graph, vertex_index_t>::type IndexMap;
    IndexMap index = get(vertex_index, g);
/*
    std::cout << "vertices(g) = ";
    typedef graph_traits<Graph>::vertex_iterator vertex_iter;
    std::pair<vertex_iter, vertex_iter> vp;
    for (vp = vertices(g); vp.first != vp.second; ++vp.first) {
      Vertex v = *vp.first;
      std::cout << index[v] <<  " ";
    }
    std::cout << std::endl;

    // ...
    std::cout << "edges(g) = ";
    graph_traits<Graph>::edge_iterator ei, ei_end;
    for (boost::tie(ei, ei_end) = edges(g); ei != ei_end; ++ei)
        std::cout << "(" << index[source(*ei, g)] 
                  << "," << index[target(*ei, g)] << ") ";
    std::cout << std::endl;
    */
    // ...
    return 0;
  }