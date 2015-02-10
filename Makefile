ARCH := $(shell getconf LONG_BIT)

CFLAGS_32 = -std=gnu99 -DLDAP_DEPRECATED -Wall -g 
CFLAGS_64 = -std=gnu99 -DLDAP_DEPRECATED -Wall -g -m64

PAM_DIR_32 = /lib/security/
PAM_DIR_64 = /lib64/security/

CFLAGS  = $(CFLAGS_$(ARCH))
PAM_DIR = $(PAM_DIR_$(ARCH))

all: pam

pam: pam_cvs.c
	gcc $(CFLAGS) -fPIC -c pam_cvs.c
	gcc $(CFLAGS) -shared -o pam_cvs.so pam_cvs.o -lpam -lldap

install: pam
	install -v -oroot -groot -m0755 pam_cvs.so $(PAM_DIR)

clean:
	rm -f *.o *.so 

