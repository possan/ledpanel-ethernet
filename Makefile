all: plasma

ledpanel.o: ledpanel.cpp ledpanel.h
	g++ -c -o ledpanel.o ledpanel.cpp

plasma: ledpanel.o plasma.cpp
	g++ -o plasma plasma.cpp ledpanel.o
