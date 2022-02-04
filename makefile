LDLIBS += -lpcap

all: deauth-attack

deauth-attack: deauth-attack.cpp

clean:
	rm -f deauth-attack *.o
