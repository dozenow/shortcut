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
#include "slice_optimizer.h"
#include <boost/algorithm/string.hpp>

using namespace boost;

//#define DEBUG_PRINT

//from taint_full_interface.c
static inline const char* regName (uint32_t reg_num, uint32_t reg_size)
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

std::string checkForRegs(std::string instOperand){
  bool found = false;
  std::string reg = "error";

  std::string chk = "edx";
  found = (contains(instOperand, chk));
  if(found)
      {
          return(chk);
      }

  chk = "dx";
  found = (contains(instOperand, chk));
  if(found)
      {
          return(chk);
      }

  chk = "ecx";
  found = (contains(instOperand, chk));
  if(found)
      {
          return(chk);
      }

  chk = "edi";
  found = (contains(instOperand, chk));
  if(found)
      {
          return(chk);
      }

    return reg;

}
  
  
  int main(int,char*[])
  {

    std::string filename("testslice.c");
    boost::iostreams::stream<boost::iostreams::file_source>file(filename.c_str());
    std::string line;
    int lineNum = 0;
    instrGraph sliceGraph;
    instrGraph* p_sliceGraph = &sliceGraph;
    std::vector<std::string> instructionPieces;
    std::vector<std::string> tempPieces;
    std::string mnemonic;
    std::string dst;
    std::string src;
    Node* p_rootNode = new Node();
    Edge* ptempEdge = new Edge();
    p_rootNode->outEdges.push_back(ptempEdge);
    p_rootNode->outEdges[0]->start = p_rootNode;
    p_rootNode->inEdges.push_back(ptempEdge);

    p_rootNode->lineNum = 0;
    
    tregister* edx = new tregister();
    tregister* dx = new tregister();
    tregister* ecx = new tregister();
    tregister* edi = new tregister();
    

    edx->regNum = 8;
    edx->size = 4;
    edx->author = p_rootNode;

    dx->regNum = 8;
    dx->size = 2;
    dx->author = p_rootNode;

    ecx->regNum = 9;
    ecx->size = 4;
    ecx->author = p_rootNode;
    
    edi->regNum = 3;
    edi->size = 4;
    edi->author = p_rootNode;

    while (std::getline(file, line)) {
      lineNum++;

      //Start reading actual slice instructions starting at line 5 (because the first 4 lines are padding that always need to be kept)
      if(lineNum >= 5){
        //this last line in exslice1.c is not really a slice instruction. Instead it is the last line of the exslice1.c file, );
        if(!(contains(line, ");"))){

          boost::split(tempPieces, line, boost::is_any_of(" "), token_compress_on);
          mnemonic = tempPieces[0];
          //erase the first char of the mnemonic string to remove the extra quote symbol at the start of the mnemonic string.
          mnemonic.erase(0,1);

          boost::split(tempPieces, line, boost::is_any_of(mnemonic), token_compress_on);
          #ifdef DEBUG_PRINT
            for (auto it = std::begin(tempPieces); it != std::end(tempPieces); ++it){
                std::cout<<(*it)<<"\n";
            }
            std::cout<<tempPieces[1]<<"\n";
          #endif
          
          
          boost::split(tempPieces, tempPieces[1], boost::is_any_of(","), token_compress_on);
          

          #ifdef DEBUG_PRINT
            for (auto it = std::begin(tempPieces); it != std::end(tempPieces); ++it){
                std::cout<<(*it)<<"\n";
            }
            std::cout<<tempPieces[0]<<"\n";
          #endif
          dst = tempPieces[0];
          
          boost::split(tempPieces, tempPieces[1], boost::is_any_of("/"), token_compress_on);
          #ifdef DEBUG_PRINT
            for (auto it = std::begin(tempPieces); it != std::end(tempPieces); ++it){
                std::cout<<(*it)<<"\n";
            }
            std::cout<<tempPieces[0]<<"\n";
          #endif
          
          src = tempPieces[0];


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

         

          std::string tempSrc = checkForRegs(src);
          //if tempSrc is not "error" then it must be a valid register
          if (tempSrc != "error"){
            if(tempSrc == "edx"){
              //create a new IN edge for the new instruction node.
              //The IN edge starts at the last Node to set edx register and finishes at the current new instruction node self.
              
              p_tempInEdge->start = edx->author;
              p_tempInEdge->finish = p_tempNode;
              edx->author->outEdges.push_back(p_tempOutEdge);
              edx->author->outEdges.back()->start = edx->author;
              edx->author->outEdges.back()->finish = p_tempNode;
              }
            if(tempSrc == "dx"){
              //create a new IN edge for the new instruction node.
              //The IN edge starts at the last Node to set dx register and finishes at the current new instruction node self.
              
              p_tempInEdge->start = dx->author;
              p_tempInEdge->finish = p_tempNode;
              dx->author->outEdges.push_back(p_tempOutEdge);
              dx->author->outEdges.back()->start = dx->author;
              dx->author->outEdges.back()->finish = p_tempNode;
              }
            if(tempSrc == "ecx"){
              //create a new IN edge for the new instruction node.
              //The IN edge starts at the last Node to set ecx register and finishes at the current new instruction node self.
              #ifdef DEBUG_PRINT
                std::cout<< "setting (prevAuthor of ecx)->outEdges[0]->finish = self current new node.";
              #endif
              std::cout<< "setting (prevAuthor of ecx)" << ecx->author->lineNum <<"->outEdges[0]->finish = self current new node. " << p_tempNode->lineNum<<"\n";
              
              p_tempInEdge->start = ecx->author;
              p_tempInEdge->finish = p_tempNode;
              ecx->author->outEdges.push_back(p_tempOutEdge);
              ecx->author->outEdges.back()->start = ecx->author;
              ecx->author->outEdges.back()->finish = p_tempNode;
              }
            if(tempSrc == "edi"){
              //create a new IN edge for the new instruction node.
              //The IN edge starts at the last Node to set edi register and finishes at the current new instruction node self.
              
              p_tempInEdge->start = edi->author;
              p_tempInEdge->finish = p_tempNode;
              edi->author->outEdges.push_back(p_tempOutEdge);
              edi->author->outEdges.back()->start = edi->author;
              edi->author->outEdges.back()->finish = p_tempNode;
              }
          }
          //else if tempSrc is equal to "error" then must be a constant like "17"
          else{
            //so create an edge from the rootNode to the current instruction node;
            
            p_tempInEdge->start = p_rootNode;
            p_tempInEdge->finish = p_tempNode;
            p_rootNode->outEdges[0]->finish = p_tempNode;
          }

          std::string tempDst = checkForRegs(dst);
          //if tempDst is not "error" then it must be a valid register
          if (tempDst != "error"){
            if(tempDst == "edx"){
              #ifdef DEBUG_PRINT
                std::cout<< "setting edx with a new author: " << p_tempNode->lineNum << "\n";
              #endif
              //modify the edx tregister object to have self current instruction node as the new author.
              edx->author = p_tempNode;
              }
            if(tempDst == "dx"){
              #ifdef DEBUG_PRINT
                std::cout<< "setting dx with a new author: " << p_tempNode->lineNum << "\n";
              #endif
              dx->author = p_tempNode;
              }
            if(tempDst == "ecx"){
              #ifdef DEBUG_PRINT
                std::cout<< "setting ecx with a new author: " << p_tempNode->lineNum << "\n";
              #endif
              ecx->author = p_tempNode;
              }
            if(tempDst == "edi"){
              #ifdef DEBUG_PRINT
                std::cout<< "setting edi with a new author: " << p_tempNode->lineNum << "\n";
              #endif
              edi->author = p_tempNode;
              }
          }
          //else if tempDst is equal to "error" then must be a constant like "17"
          else{
            //so create an edge from the rootNode to the current instruction node;
            
            p_tempOutEdge->start = p_tempNode;p_rootNode;
            p_tempOutEdge->finish = p_rootNode;
          }


          //add the IN OUT tempEdges to the current node
          p_tempNode->inEdges.push_back(p_tempInEdge);
          //p_tempNode->outEdges.push_back(p_tempOutEdge);

          #ifdef DEBUG_PRINT
            std::cout<< p_tempNode->lineNum << "\n";
            std::cout<< p_tempNode << "\n";
          #endif

          p_sliceGraph->nodes.push_back(p_tempNode);
        }
      }
    }

    //remove the last 'node' in the nodes vector of sliceGraph, because this last node is not really an instruction node. Instead it is the last line of the exslice1.c file, );
    //p_sliceGraph->nodes.pop_back();

    std::cout<< "now printing all the nodes (identified by their line numbers) in our sliceGraph.\n";
    for (auto it = std::begin(p_sliceGraph->nodes); it != std::end(p_sliceGraph->nodes); ++it){
      std::cout<<((*it)->lineNum) << "\n";
      for (auto ut = std::begin(((*it)->inEdges)); ut != std::end(((*it)->inEdges)); ++ut){
        std::cout<< "inEdges: "<<((*ut)->start)->lineNum << "->" << ((*ut)->finish)->lineNum << " ";
      }
      std::cout<<"\n";
      for (auto kt = std::begin(((*it)->outEdges)); kt != std::end(((*it)->outEdges)); ++kt){
        std::cout<< "outEdges: "<<((*kt)->start)->lineNum << "->" << ((*kt)->finish)->lineNum << " ";
      }
      std::cout<<"\n";
    }

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
    // ...
    return 0;
  }