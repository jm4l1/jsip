CC=g++
CPPFLAGS= -std=c++17 -stdlib=libc++ -g
SRCDIR := src
BUILDDIR := build
TARGET := test

SRCEXT := cpp
SOURCES := $(shell find $(SRCDIR) -type f -name "*.$(SRCEXT)")
OBJECTS := $(patsubst $(SRCDIR)/%,$(BUILDDIR)/%,$(SOURCES:.$(SRCEXT)=.o))

INC := -I ../include

$(TARGET) : test.o $(OBJECTS)
	$(CC) $(CPPFLAGS) test.o $(OBJECTS) -o bin/test
# sockets.o:src/sockets.cpp
# 	$(CC) $(CPPFLAGS) -c  $(INC) $< -o $(BUILDDIR)/$@
$(BUILDDIR)/%.o: $(SRCDIR)/%.$(SRCEXT)
	$(CC) $(CPPFLAGS) -c $(INC) $< -o $@
test.o : test.cpp
	$(CC) $(CPPFLAGS) -c  $(INC) $< -o $@ 
clean:
	@echo " Cleaning..."; 
	@echo " $(RM) -r test.o $(BUILDDIR)/*.o $(TARGET)"; $(RM) -r test.o $(BUILDDIR)/*.o $(TARGET) && $(RM) -r $(OBJECTS)

