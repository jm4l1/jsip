CC=g++
CPPFLAGS= -std=c++17 -stdlib=libc++ -g
SRCDIR := src
BUILDDIR := build
TESTDIR := tests
TARGET := main

SRCEXT := cpp
SOURCES := $(shell find $(SRCDIR) -type f -name "*.$(SRCEXT)")
OBJECTS := $(patsubst $(SRCDIR)/%,$(BUILDDIR)/%,$(SOURCES:.$(SRCEXT)=.o))

TESTSOURCES := $(shell find $(TESTDIR) -type f -name "*.$(SRCEXT)")
TESTNAMES := $(patsubst $(TESTSOURCES)/%,%,$(TESTSOURCES:.$(SRCEXT)=))
TESTOBJECTS := $(patsubst $(TESTDIR)/%,$(TESTDIR)/%,$(TESTSOURCES:.$(SRCEXT)=.o))

INC := -I ../include


$(TARGET) : $(TARGET).o $(OBJECTS)
	$(CC) $(CPPFLAGS) $(TARGET).o $(OBJECTS) -o bin/$@
$(BUILDDIR)/%.o: $(SRCDIR)/%.$(SRCEXT)
	$(CC) $(CPPFLAGS) -c $(INC) $< -o $@
$(TARGET).o : $(TARGET).cpp
	$(CC) $(CPPFLAGS) -c  $(INC) $< -o $@ 
	
#=== test recipes
tests : $(TESTNAMES)
	@echo "Building tests $(TESTNAMES)"
$(TESTNAMES) : $(TESTOBJECTS) $(OBJECTS)
	$(CC) $(CPPFLAGS) -Wall $^ -o $@	
$(TESTDIR)/%.o: $(TESTDIR)/%.$(SRCEXT)
	$(CC) $(CPPFLAGS) -Wall -c $(INC) $(TESTDIR) $< -o $@

clean:
	@echo " Cleaning..."; 
	@echo " $(RM) -f $(TARGET).o $(BUILDDIR)/*.o bin/$(TARGET)"; $(RM) -f $(TARGET).o $(BUILDDIR)/*.o bin/$(TARGET) && $(RM) -f $(OBJECTS)
cleantest:
	$(RM) -f $(TESTOBJECTS) $(TESTNAMES)
