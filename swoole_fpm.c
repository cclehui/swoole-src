/*
 +----------------------------------------------------------------------+
 | Swoole                                                               |
 +----------------------------------------------------------------------+
 | Copyright (c) 2012-2015 The Swoole Group                             |
 +----------------------------------------------------------------------+
 |     |
 +----------------------------------------------------------------------+
 | Author: chenlehui  <763414242@qq.com>                        |
 +----------------------------------------------------------------------+
 */

#include "php_swoole.h"
#include "swoole_fpm.h"
#include "php_variables.h"
#include "zend_globals_macros.h"

zend_class_entry swoole_fpm_server_ce;
zend_class_entry *swoole_fpm_server_class_entry_ptr;

static PHP_METHOD(swoole_fpm_server, run);

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_fpm_server_run, 0, 0, 2)
ZEND_END_ARG_INFO()


const zend_function_entry swoole_fpm_server_methods[] =
{
    PHP_ME(swoole_fpm_server, run,         arginfo_swoole_fpm_server_run, ZEND_ACC_PUBLIC|ZEND_ACC_STATIC)
    PHP_FE_END
};


void swoole_fpm_server_init(int module_number TSRMLS_DC)
{
    SWOOLE_INIT_CLASS_ENTRY(swoole_fpm_server_ce, "swoole_fpm_server", "Swoole\\Fpm\\Server", swoole_fpm_server_methods);
    //swoole_fpm_server_class_entry_ptr = sw_zend_register_internal_class_ex(&swoole_fpm_server_ce, swoole_server_class_entry_ptr, "swoole_server" TSRMLS_CC);
    swoole_fpm_server_class_entry_ptr = zend_register_internal_class(&swoole_fpm_server_ce TSRMLS_CC);
    SWOOLE_CLASS_ALIAS(swoole_fpm_server, "Swoole\\Fpm\\Server");

}


//参考自 php_request_startup()
int swoole_request_startup() 
{
	int retval = SUCCESS;
	zend_try {
		PG(in_error_log) = 0;
		PG(during_request_startup) = 1;

		php_output_activate();

		/* initialize global variables */
		PG(modules_activated) = 0;
		PG(header_is_being_sent) = 0;
		PG(connection_status) = PHP_CONNECTION_NORMAL;
		PG(in_user_include) = 0;

		zend_activate();
		//sapi_activate();

		if (PG(max_input_time) == -1) {
			zend_set_timeout(EG(timeout_seconds), 1);
		} else {
			zend_set_timeout(PG(max_input_time), 1);
		}

		if (PG(output_handler) && PG(output_handler)[0]) {
			zval oh;

			ZVAL_STRING(&oh, PG(output_handler));
			php_output_start_user(&oh, 0, PHP_OUTPUT_HANDLER_STDFLAGS);
			zval_ptr_dtor(&oh);
		} else if (PG(output_buffering)) {
			php_output_start_user(NULL, PG(output_buffering) > 1 ? PG(output_buffering) : 0, PHP_OUTPUT_HANDLER_STDFLAGS);
		} else if (PG(implicit_flush)) {
			php_output_set_implicit_flush(1);
		}

		/* We turn this off in php_execute_script() */
		/* PG(during_request_startup) = 0; */

		php_hash_environment();
		zend_activate_modules();
		PG(modules_activated)=1;
	} zend_catch {
		retval = FAILURE;
	} zend_end_try();

    return retval;
}

ZEND_API void swoole_zend_deactivate(void) /* {{{ */
{
	/* we're no longer executing anything */
	EG(current_execute_data) = NULL;

	zend_try {
		//shutdown_scanner();
	} zend_end_try();

	/* shutdown_executor() takes care of its own bailout handling */
	//shutdown_executor();
	swoole_shutdown_executor();


	zend_try {
		//zend_ini_deactivate();
	} zend_end_try();

	zend_try {
		//shutdown_compiler();
	} zend_end_try();

	zend_destroy_rsrc_list(&EG(regular_list));

}
/* }}} */

//请求结束
//参考自 php_request_shutdown()
void swoole_request_shutdown()
{
	zend_bool report_memleaks;

	report_memleaks = PG(report_memleaks);

	/* EG(current_execute_data) points into nirvana and therefore cannot be safely accessed
	 * inside zend_executor callback functions.
	 */
	EG(current_execute_data) = NULL;


	php_deactivate_ticks();

	swoole_zend_deactivate();
    return;

	/* 1. Call all possible shutdown functions registered with register_shutdown_function() */
	if (PG(modules_activated)) zend_try {
		php_call_shutdown_functions();
	} zend_end_try();

	/* 2. Call all possible __destruct() functions */
	zend_try {
		zend_call_destructors();
	} zend_end_try();

	/* 3. Flush all output buffers */
	zend_try {
		//zend_bool send_buffer = SG(request_info).headers_only ? 0 : 1;
		zend_bool send_buffer = 1;

		if (CG(unclean_shutdown) && PG(last_error_type) == E_ERROR &&
			(size_t)PG(memory_limit) < zend_memory_usage(1)
		) {
			send_buffer = 0;
		}

		if (!send_buffer) {
			php_output_discard_all();
		} else {
			php_output_end_all();
		}
	} zend_end_try();

	/* 4. Reset max_execution_time (no longer executing php code after response sent) */
	zend_try {
		zend_unset_timeout();
	} zend_end_try();

	/* 5. Call all extensions RSHUTDOWN functions */
	if (PG(modules_activated)) {
		zend_deactivate_modules();
	}

	/* 6. Shutdown output layer (send the set HTTP headers, cleanup output handlers, etc.) */
	zend_try {
		php_output_deactivate();
	} zend_end_try();

	/* 7. Free shutdown functions */
	if (PG(modules_activated)) {
		php_free_shutdown_functions();
	}

	/* 8. Destroy super-globals */
	zend_try {
		int i;

		for (i=0; i<NUM_TRACK_VARS; i++) {
			zval_ptr_dtor(&PG(http_globals)[i]);
		}
	} zend_end_try();

	/* 9. free request-bound globals */
	php_free_request_globals();

	/* 10. Shutdown scanner/executor/compiler and restore ini entries */
	//zend_deactivate();
	swoole_zend_deactivate();

	/* 11. Call all extensions post-RSHUTDOWN functions */
	zend_try {
		zend_post_deactivate_modules();
	} zend_end_try();

	/* 13. free virtual CWD memory */
	virtual_cwd_deactivate();

	/* 14. Destroy stream hashes */
	zend_try {
		php_shutdown_stream_hashes();
	} zend_end_try();

	/* 15. Free Willy (here be crashes) */
	zend_interned_strings_restore();
	zend_try {
		shutdown_memory_manager(CG(unclean_shutdown) || !report_memleaks, 0);
	} zend_end_try();

	/* 16. Reset max_execution_time */
	zend_try {
		zend_unset_timeout();
	} zend_end_try();
}

static PHP_METHOD(swoole_fpm_server, run)
{
    php_printf("execute_file, 11111111111\n");

    if (UNEXPECTED(swoole_request_startup() == FAILURE)) {
        RETURN_FALSE;
    }

    zend_file_handle file_handle;

    char *filename = "/var/www/my_index.php";

    if (zend_stream_open(filename, &file_handle) == FAILURE) {
        php_printf("execute_file, eeeeeeeeeeee\n");
    }

    php_printf("execute_file, 6666, %s, %s\n", file_handle.filename, ZSTR_VAL(file_handle.opened_path));

    php_execute_script(&file_handle);

    swoole_request_shutdown();

    php_printf("execute_file, 99999999999\n");

    RETURN_TRUE;
}

