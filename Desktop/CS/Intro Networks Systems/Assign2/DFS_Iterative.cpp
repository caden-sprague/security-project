#include <iostream>
#include <fstream>
#include <stack>
#include "AdjList.h"

using namespace std;

AdjList *createAdjList(string file, int &V, int &E){
    ifstream fin;
    fin.open(file);
    if(!fin){
        cout << "Input file not found! Please ensure you have the required file in the correct location\n";
        exit(EXIT_FAILURE);
    }
    fin >> V >> E;
	
    AdjList *list = new AdjList[V];
    for(int i = 0; i < E; i++){
        int src, dest;
        fin >> src >> dest;
        list[src].AddNode(dest);
    }
	
    return list;
}

void DFS_iter(AdjList *list, int startID, bool *isVisited){
	// TODO
}

int main(int argc, char *argv[]){
	
    int vertexSize, edgeCount;
    
	if(argc < 2){
		fprintf(stderr, "ERROR: Must include edge list file as command line argument\n"); 
		exit(-1);
	}
    string file = argv[1];
    
	AdjList *adjList = createAdjList(file, vertexSize, edgeCount);
    
	bool *isVisited = new bool[vertexSize];
    for(int i = 0; i < vertexSize; i++){
        isVisited[i] = false;
    }
	
    DFS_iter(adjList, 0, isVisited);
	
    return 0;
}