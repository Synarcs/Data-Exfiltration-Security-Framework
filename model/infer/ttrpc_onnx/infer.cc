#include <boost/thread/thread.hpp>
#include <iostream>
#include <memory.h>

using namespace std;

class OnnxRequestProcessingHandler {
    public:
        OnnxRequestProcessingHandler() {

        }

        ~OnnxRequestProcessingHandler() {

        }
};

int main() {
    unique_ptr<OnnxRequestProcessingHandler> handler = make_unique<OnnxRequestProcessingHandler>();
    cout << "checking the loaded libboost modules " << endl;
}