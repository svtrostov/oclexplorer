LIBS=-lcrypto -lm
CFLAGS=-ggdb -O0 -Wall
OBJS=oclexplorer.o oclengine.o utils.o
PROGS=oclexplorer

PLATFORM=$(shell uname -s)
ifeq ($(PLATFORM),Darwin)
OPENCL_LIBS=-framework OpenCL
else
OPENCL_LIBS=-lOpenCL
endif


most: oclexplorer

all: $(PROGS)

oclexplorer: oclexplorer.o oclengine.o utils.o
	$(CC) $^ -o $@ $(CFLAGS) $(LIBS) $(OPENCL_LIBS)
	rm -f $(OBJS)

clean:
	rm -f $(OBJS) $(PROGS) $(TESTS)
