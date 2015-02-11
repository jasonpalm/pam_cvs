# The MIT License (MIT)
# 
# Copyright (c) 2015 Jason Palm
# 
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
# 
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

CFLAGS_32 = -std=gnu99 -DLDAP_DEPRECATED -Wall -g 
CFLAGS_64 = -std=gnu99 -DLDAP_DEPRECATED -Wall -g -m64

PAM_DIR_32 = /lib/security/
PAM_DIR_64 = /lib64/security/

ARCH              = $(shell getconf LONG_BIT)
PAM_DIR           = $(PAM_DIR_$(ARCH))
override CFLAGS  += $(CFLAGS_$(ARCH))

all: pam

pam: pam_cvs.c
	gcc $(CFLAGS) -fPIC -c pam_cvs.c
	gcc $(CFLAGS) -shared -o pam_cvs.so pam_cvs.o -lpam -lldap

install: pam
	install -v -oroot -groot -m0755 pam_cvs.so $(PAM_DIR)

clean:
	rm -f *.o *.so 

