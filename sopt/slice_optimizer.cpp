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


bool checkForRegs(std::string instOperand){
  bool found = false;
  found = (contains(instOperand, "edx"));
  if(found)
    {
        std::cout << "edx is there" << "\n";
    }

    return found;

}
  
  
  int main(int,char*[])
  {

    std::string filename("cleanedtestslice.c");
    boost::iostreams::stream<boost::iostreams::file_source>file(filename.c_str());
    std::string line;
    int lineNum = 0;
    instrGraph sliceGraph;
    instrGraph* p_sliceGraph = &sliceGraph;
    std::vector<std::string> instructionPieces;
    
    tregister* edx = new tregister();
    tregister* ecx = new tregister();



    
    while (std::getline(file, line)) {
      lineNum++;

      //Start reading actual slice instructions starting at line 5 (because the first 4 lines are padding that always need to be kept)
      if(lineNum >= 5){
        //this last line in exslice1.c is not really a slice instruction. Instead it is the last line of the exslice1.c file, );
        if(!(contains(line, ");"))){

          boost::split(instructionPieces, line, boost::is_any_of(",/"), token_compress_on);
          #ifdef DEBUG_PRINT
            for (auto it = std::begin(instructionPieces); it != std::end(instructionPieces); ++it){
              std::cout<<(*it)<<"\n";
            }
          #endif

          std::cout<< line << "\n";
          std::cout<<"dest Arg: "<<instructionPieces[1]<<"\n";
          std::cout<<"src Arg: "<<instructionPieces[2]<<"\n";
          

          //need to eventually delete this dynamically allocated memory
          Node* p_tempNode = new Node();
          
          #ifdef DEBUG_PRINT
            //std::cout<< p_tempNode->lineNum << "\n";
            std::cout<< line << "\n";
          #endif
          
          
          p_tempNode->lineNum = lineNum;

          #ifdef DEBUG_PRINT
            std::cout<< p_tempNode->lineNum << "\n";
            std::cout<< p_tempNode << "\n";
          #endif

          int checkRegs = checkForRegs(line);

          #ifdef DEBUG_PRINT
            std::cout<< "checkRegs value is: " << checkRegs << "\n";
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
    }

    //...
    /*
    std::ifstream infile("testslice.c");

    std::string line;
    while (std::getline(infile, line))
    {
      std::istringstream iss(line);
      int a, b;

      std::cout << line << '\n';
      //if (!(iss >> a >> b)) { break; } // error

      // process pair (a,b)
    }

    */
    //...
    /*
    std::string file_path = "testslice.c";

    filesystem::ifstream file(file_path);
    std::string str;
    std::vector<std::string> filenames;
    while(getline(file, str)){
      filenames.push_back(str);
    }

    for (auto it = std::begin (filenames); it != std::end (filenames); ++it) {
      //it->doSomething ();
      std::cout << it;
    }
    */
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