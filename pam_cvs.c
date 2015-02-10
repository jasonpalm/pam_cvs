/*******************************************************************************
 * Copyright (c) 2015 Jason Palm
 * See LICENSE file for licensing.
 */

#define PAM_SM_ACCOUNT
#define PAM_SM_AUTH
#define PAM_SM_SESSION

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <ldap.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <syslog.h>

#define MODULE_SO_NAME "pam_module.so"
#define EFFECTIVE_USER_MODULE_DATA_NAME "cvs_effective_user"
#define IND "  "

void log_call(pam_handle_t *pamh, const char *func_name, int argc, const char **argv);
void log_pam_item(pam_handle_t *pamh, char *item_name, int item_type);
void show_usage();

/*******************************************************************************
 * Called when the .so is loaded.
 *
 * Opens syslog.
 *
 */
void __attribute__ ((constructor)) so_loaded(void)
{
 	openlog("pam_tims_cvs", LOG_CONS | LOG_PID, LOG_AUTHPRIV);
}

/*******************************************************************************
 * Called when the .so is unloaded.
 *
 * Closes syslog.
 *
 */
void __attribute__ ((destructor)) so_unloaded(void)
{
	closelog();
}

void log_call(pam_handle_t *pamh, const char *func_name, int argc, const char **argv)
{
	syslog(LOG_NOTICE, "Calling %s()", func_name);
	syslog(LOG_NOTICE, IND "%d arguments passed:", argc);
	for(int i=0; i < argc; i++)
	{
		syslog(LOG_NOTICE, IND IND "%s", argv[i]);
	}

	// Log PAM environment variables
	char **env = pam_getenvlist(pamh);
	if(env && *env)
	{
		syslog(LOG_NOTICE, IND "PAM environment variables:");
		for(char **p = env; *p; p++)
		{
			syslog(LOG_NOTICE, IND IND "%s", *p);
		}	
	}
	else 
	{
		syslog(LOG_NOTICE, IND "No PAM environment variables set." );
	}

	// Log item values
	syslog(LOG_NOTICE, IND "PAM item values:");
	log_pam_item(pamh, "PAM_SERVICE     ", PAM_SERVICE);
	log_pam_item(pamh, "PAM_USER        ", PAM_USER);
	log_pam_item(pamh, "PAM_USER_PROMPT ", PAM_USER_PROMPT);
	log_pam_item(pamh, "PAM_TTY         ", PAM_TTY);
	log_pam_item(pamh, "PAM_RUSER       ", PAM_RUSER);
	log_pam_item(pamh, "PAM_RHOST       ", PAM_RHOST);
	log_pam_item(pamh, "PAM_AUTHTOK     ", PAM_AUTHTOK);
	log_pam_item(pamh, "PAM_OLDAUTHTOK  ", PAM_OLDAUTHTOK);
}

void log_pam_item(pam_handle_t *pamh, char *item_name, int item_type)
{
	char *value;
	int retval;

	retval = pam_get_item(pamh, item_type, (const void**) &value);
	
	if(retval == PAM_SUCCESS)
	{
		syslog(LOG_NOTICE, IND IND "%s: %s", item_name, value);
	}
	else 
	{
		syslog(LOG_NOTICE, "Failed to read value of PAM item %s: %s", item_name,
			pam_strerror(pamh, retval));
	}
}

void show_usage()
{
	syslog(LOG_ERR, "Usage: %s cvs_user ldap_host ldap_port", MODULE_SO_NAME);
    syslog(LOG_ERR, "(Ignore any message below saying \"user has no password\","
        " which comes from CVS and is innacurate).");
	fprintf(stderr, "Error message sent to syslog (AUTHPRIV)\n");
}	

int cvs_get_password(pam_handle_t *pamh, char **password)
{
	int retval;

	struct pam_conv     *conv;
	struct pam_message  *mesg;
	struct pam_response *resp;

	// Initialze the password to NULL so we know not to free it if the function fails.
	*password = NULL;

	// Get the PAM conversation function. 
    retval = pam_get_item(pamh, PAM_CONV, (const void **) &conv); 
	if(retval != PAM_SUCCESS)
	{
		syslog(LOG_ERR, "Failed to get PAM conversation function: %s", pam_strerror(pamh, retval));
		return retval;
	}

	// Allocate a request message
    mesg = malloc(sizeof(struct pam_message));
	if(!mesg)
	{
		syslog(LOG_ERR, "Failed allocating memory for struct pam_message: %s", strerror(errno));
		return PAM_AUTHINFO_UNAVAIL;
	}

	// Initialize the request message
    memset(mesg, 0, sizeof(struct pam_message));
    mesg->msg_style = PAM_PROMPT_ECHO_OFF;

	// Ask for the password
    retval = conv->conv(1, (const struct pam_message **) &mesg, &resp, conv->appdata_ptr); 
    free(mesg);
    if(retval != PAM_SUCCESS)
    {
        syslog(LOG_NOTICE, "PAM conversation function failed: %s", pam_strerror(pamh, retval));
        return retval; 
    }

    *password = strdup(resp[0].resp);

	// The response contains the password, so we wipe it before freeing it.
	memset(resp, 0, sizeof(struct pam_response));
	free(resp);

	return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	int   retval;

	const char *cvs_user;
	const char *ldap_host;
	int         ldap_port;
	LDAP       *ldap;

	char *username;
	char *password;

	// log_call(pamh, "pam_sm_authenticate", argc, argv);

	if(argc != 3)
	{
		show_usage();
		return PAM_AUTHINFO_UNAVAIL;
	}

	cvs_user  = argv[0];
	ldap_host = argv[1];
	sscanf(argv[2], "%d", &ldap_port);

	if(ldap_port < 0 || ldap_port > 65535)
	{
		show_usage();
		return PAM_AUTHINFO_UNAVAIL;
	}

	// syslog(LOG_NOTICE, "Using effective user %s and LDAP %s:%d", cvs_user, ldap_host, ldap_port);

	retval = pam_set_data(pamh, EFFECTIVE_USER_MODULE_DATA_NAME, (void *) cvs_user, NULL);
	if(retval != PAM_SUCCESS)
	{
		syslog(LOG_ERR, "Failed to store effective user in module internal data: %s", 
			pam_strerror(pamh, retval));
		return retval;
	}

	retval = pam_get_item(pamh, PAM_USER, (const void **) &username);
	if(retval != PAM_SUCCESS)
	{
		syslog(LOG_ERR, "Failed to get PAM_USER: %s", pam_strerror(pamh, retval));
		return retval;
	}

	retval = cvs_get_password(pamh, &password);
	if(retval != PAM_SUCCESS)
	{
		syslog(LOG_ERR, "Failed getting password from cvs: %s", pam_strerror(pamh, retval));
		syslog(LOG_ERR, "Check error messages above for details");
		return retval;
	}

	ldap = ldap_init(ldap_host, ldap_port);
	if(!ldap)
	{	
		syslog(LOG_ERR, "ldap_init(\"%s\", %d) failed.", ldap_host, ldap_port);
		return PAM_AUTHINFO_UNAVAIL;
	} 
	
    retval = ldap_simple_bind_s(ldap, username, password);
	if(retval != LDAP_SUCCESS)
	{
    	syslog(LOG_ERR, "Failed to authenticate user %s with LDAP at %s:%d : %s",
        	username, ldap_host, ldap_port, ldap_err2string(retval));
        syslog(LOG_ERR, "(Ignore any message below saying \"user has no password\","
            " which comes from CVS and is innacurate).");
	
		return PAM_AUTH_ERR;
	}

	syslog(LOG_NOTICE, "Authenticated %s with LDAP.", username);

	return PAM_SUCCESS;
}	 


PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	// log_call(pamh, "pam_sm_setcred", argc, argv);
	return PAM_SUCCESS;
}


PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	// log_call(pamh, "pam_sm_acct_mgmt", argc, argv);
	return PAM_SUCCESS;
}


PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	int   retval;
	char *effective_user;

	// log_call(pamh, "pam_sm_open_session", argc, argv);

	// set the effective user to use when accessing the repository
	retval = pam_get_data(pamh, EFFECTIVE_USER_MODULE_DATA_NAME, (const void **) &effective_user);
	if(retval == PAM_SUCCESS)
	{
		pam_set_item(pamh, PAM_USER, effective_user);
	}
	return retval;
}


PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	// log_call(pamh, "pam_sm_close_session", argc, argv);
	return PAM_SUCCESS;
}

