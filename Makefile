CXX = g++
CXXFLAGS = -std=c++17 -Wall -O2
LIBS = -lpthread
TARGET = scanner
SRC = new_syn_scan.cpp

$(TARGET): $(SRC)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(SRC) $(LIBS)

clean:
	rm -f $(TARGET)
