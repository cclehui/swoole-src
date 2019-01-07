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
#include "swoole_php_runner.h"
#include "php_variables.h"
#include "zend_globals_macros.h"
#include "Zend/zend_language_scanner.h"

zend_class_entry swoole_php_runner_ce;
zend_class_entry *swoole_php_runner_class_entry_ptr;

static PHP_METHOD(swoole_php_runner, run);

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_php_runner_run, 0, 0, 2)
ZEND_END_ARG_INFO()


const zend_function_entry swoole_php_runner_methods[] =
{
    PHP_ME(swoole_php_runner, run,         arginfo_swoole_php_runner_run, ZEND_ACC_PUBLIC|ZEND_ACC_STATIC)
    PHP_FE_END
};


void swoole_php_runner_init(int module_number TSRMLS_DC)
{
    SWOOLE_INIT_CLASS_ENTRY(swoole_php_runner_ce, "swoole_php_runner", "Swoole\\Php\\Runner", swoole_php_runner_methods);
    //swoole_php_runner_class_entry_ptr = sw_zend_register_internal_class_ex(&swoole_php_runner_ce, swoole_server_class_entry_ptr, "swoole_server" TSRMLS_CC);
    swoole_php_runner_class_entry_ptr = zend_register_internal_class(&swoole_php_runner_ce TSRMLS_CC);
    SWOOLE_CLASS_ALIAS(swoole_php_runner, "Swoole\\Fpm\\Server");

}

static size_t sapi_cli_ub_write(const char *str, size_t str_length) /* {{{ */
{
    zval send_data;
    //SW_ZVAL_STRING(&send_data, "sssssssssssssssdddddddddddddddd", 1); 
    SW_ZVAL_STRINGL(&send_data, str, str_length, 1); 


    server_receive_context *receive_context = (server_receive_context *)SG(server_context);
    zval *zserv = receive_context->zserv;

    zval send_retval;
    zval function_name;
    ZVAL_STRING(&function_name, "send");

    zval params[2];
    params[0] = *(receive_context->zfd);
    params[1] = send_data;

    //调用 swoole_server->send() 方法 输出 output
    class_call_user_method(&send_retval, swoole_server_class_entry_ptr, zserv, function_name, 2, params);

    //swNotice("sapi_cli_ub_write, ooooooooooo , %s", str);

    /*
    if (output_buffer == NULL) {
        output_buffer = zend_string_init(str, str_length, 0);

    } else {
        size_t old_length = ZSTR_LEN(output_buffer);
        output_buffer = zend_string_realloc(output_buffer, old_length + str_length, 0);
        memcpy(ZSTR_VAL(output_buffer) + old_length, str, str_length);
    }
    */

    return str_length;
}

static void sapi_cli_flush(void *server_context) /* {{{ */
{
    if (output_buffer != NULL) {
        zend_string_free(output_buffer);
    }
}

static void sapi_cli_log_message(char *message, int syslog_type_int) /* {{{ */
{
    swWarn("sapi_cli_log_message, %s\n", message);
}


//执行php程序
static PHP_METHOD(swoole_php_runner, run)
{

    zval *zserv;
    zval *zfd;
    zval *zfrom_id;
    zend_string *zdata;
    

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "zzzS", &zserv, &zfd, &zfrom_id, &zdata) == FAILURE) {
        goto out;
    }

    if (!zserv) {
        swWarn("serv object is null");
        goto out;
    }

    //sapi 的output输出处理赋值
    sapi_module.ub_write = sapi_cli_ub_write;
    sapi_module.flush = sapi_cli_flush;
    sapi_module.log_message = sapi_cli_log_message;

    server_receive_context receive_context; 
    receive_context.zserv = zserv;
    receive_context.zfd = zfd;
    receive_context.zfrom_id = zfrom_id;
    receive_context.zdata = zdata;

    SG(server_context) = (void *)&receive_context;

    if (UNEXPECTED(swoole_php_request_startup() == FAILURE)) {
        goto out;
    }

    //swoole_php_fatal_error(E_ERROR, "EEEEEEEEEEEEEEEEEEE");

    zend_file_handle file_handle;

    char *filename = "/var/www/swoole/my_index.php";

    if (zend_stream_open(filename, &file_handle) == FAILURE) {
        swTrace("execute_file, eeeeeeeeeeee");
    }


    int status = 0;

    //zend_first_try 
    /*
    zend_try {
        status = 8888;
        php_execute_script(&file_handle);

    } zend_catch {
        status = 1001;
    } zend_end_try();
    */

    php_execute_script(&file_handle);
    swNotice("execute_file, 6666, %s\n", file_handle.filename);

    swoole_php_request_shutdown();

    swNotice("execute_file, 99999999999, %d\n", status);

    //swNotice("php_output start, -----\n%s, -----end -----\n", ZSTR_VAL(output_buffer));

out:
    SG(server_context) = NULL;
    RETURN_TRUE;
}

/*****************************************************/

//调用对象中方法
// zval function_name;
// ZVAL_STRING(&function_name,"set");
static zval * class_call_user_method(zval *retval, zend_class_entry *obj_ce, 
        zval *obj, zval function_name,  uint32_t params_count, zval params[]){ 

    zend_fcall_info fci;  

    fci.size = sizeof(fci);  
    fci.function_name = function_name;   
    fci.retval = retval;  
    fci.params = params;  
    fci.object =  obj ? Z_OBJ_P(obj) : NULL;;
    fci.param_count = params_count;  
    fci.no_separation = 1;  

    int result;
    result = zend_call_function(&fci, NULL TSRMLS_CC);         //函数调用结束。  

    if (result == FAILURE) {
        swoole_php_fatal_error(E_ERROR, "function call failed. Error: %s", sw_error);
    }

    return retval;
}

/* {{{ php_free_request_globals
 */
static void php_free_request_globals(void)
{
	if (PG(last_error_message)) {
		free(PG(last_error_message));
		PG(last_error_message) = NULL;
	}
	if (PG(last_error_file)) {
		free(PG(last_error_file));
		PG(last_error_file) = NULL;
	}
	if (PG(php_sys_temp_dir)) {
		efree(PG(php_sys_temp_dir));
		PG(php_sys_temp_dir) = NULL;
	}
}
/* }}} */

void php_deactivate_ticks(void)
{
	zend_llist_clean(&PG(tick_functions));
}

void php_shutdown_stream_hashes(void)
{
	if (FG(stream_wrappers)) {
		zend_hash_destroy(FG(stream_wrappers));
		efree(FG(stream_wrappers));
		FG(stream_wrappers) = NULL;
	}

	if (FG(stream_filters)) {
		zend_hash_destroy(FG(stream_filters));
		efree(FG(stream_filters));
		FG(stream_filters) = NULL;
	}

    if (FG(wrapper_errors)) {
		zend_hash_destroy(FG(wrapper_errors));
		efree(FG(wrapper_errors));
		FG(wrapper_errors) = NULL;
    }
}

static void zend_extension_deactivator(zend_extension *extension) /* {{{ */
{
	if (extension->deactivate) {
		extension->deactivate();
	}
}
/* }}} */

static void zend_unclean_zval_ptr_dtor(zval *zv) /* {{{ */
{
	if (Z_TYPE_P(zv) == IS_INDIRECT) {
		zv = Z_INDIRECT_P(zv);
	}
	i_zval_ptr_dtor(zv ZEND_FILE_LINE_CC);
}
/* }}} */

static int clean_non_persistent_function(zval *zv) /* {{{ */
{
	zend_function *function = Z_PTR_P(zv);
	return (function->type == ZEND_INTERNAL_FUNCTION) ? ZEND_HASH_APPLY_STOP : ZEND_HASH_APPLY_REMOVE;
}
/* }}} */

ZEND_API int clean_non_persistent_function_full(zval *zv) /* {{{ */
{
	zend_function *function = Z_PTR_P(zv);
	return (function->type == ZEND_INTERNAL_FUNCTION) ? ZEND_HASH_APPLY_KEEP : ZEND_HASH_APPLY_REMOVE;
}
/* }}} */

static int clean_non_persistent_class(zval *zv) /* {{{ */
{
	zend_class_entry *ce = Z_PTR_P(zv);
	return (ce->type == ZEND_INTERNAL_CLASS) ? ZEND_HASH_APPLY_STOP : ZEND_HASH_APPLY_REMOVE;
}
/* }}} */

ZEND_API int clean_non_persistent_class_full(zval *zv) /* {{{ */
{
	zend_class_entry *ce = Z_PTR_P(zv);
	return (ce->type == ZEND_INTERNAL_CLASS) ? ZEND_HASH_APPLY_KEEP : ZEND_HASH_APPLY_REMOVE;
}
/* }}} */

static int clean_non_persistent_constant(zval *zv)
{
	zend_constant *c = Z_PTR_P(zv);
	return (c->flags & CONST_PERSISTENT) ? ZEND_HASH_APPLY_STOP : ZEND_HASH_APPLY_REMOVE;
}


static int clean_non_persistent_constant_full(zval *zv)
{
	zend_constant *c = Z_PTR_P(zv);
	return (c->flags & CONST_PERSISTENT) ? 0 : 1;
}

void clean_non_persistent_constants(void)
{
	if (EG(full_tables_cleanup)) {
		zend_hash_apply(EG(zend_constants), clean_non_persistent_constant_full);
	} else {
		zend_hash_reverse_apply(EG(zend_constants), clean_non_persistent_constant);
	}
}

static int zend_close_rsrc(zval *zv)
{
	zend_resource *res = Z_PTR_P(zv);

	if (res->type >= 0) {
		zend_resource_dtor(res);
	}
	return ZEND_HASH_APPLY_KEEP;
}

void zend_close_rsrc_list(HashTable *ht)
{
	zend_hash_reverse_apply(ht, zend_close_rsrc);
}

void zend_destroy_rsrc_list(HashTable *ht)
{
	zend_hash_graceful_reverse_destroy(ht);
}

void swoole_shutdown_executor(void) /* {{{ */
{
	zend_function *func;
	zend_class_entry *ce;

	zend_try {

		zend_llist_apply(&zend_extensions, (llist_apply_func_t) zend_extension_deactivator);

		if (CG(unclean_shutdown)) {
			EG(symbol_table).pDestructor = zend_unclean_zval_ptr_dtor;
		}
		zend_hash_graceful_reverse_destroy(&EG(symbol_table));
	} zend_end_try();
	EG(valid_symbol_table) = 0;

	zend_try {
		zval *zeh;
		/* remove error handlers before destroying classes and functions,
		 * so that if handler used some class, crash would not happen */
		if (Z_TYPE(EG(user_error_handler)) != IS_UNDEF) {
			zeh = &EG(user_error_handler);
			zval_ptr_dtor(zeh);
			ZVAL_UNDEF(&EG(user_error_handler));
		}

		if (Z_TYPE(EG(user_exception_handler)) != IS_UNDEF) {
			zeh = &EG(user_exception_handler);
			zval_ptr_dtor(zeh);
			ZVAL_UNDEF(&EG(user_exception_handler));
		}

		zend_stack_clean(&EG(user_error_handlers_error_reporting), NULL, 1);
		zend_stack_clean(&EG(user_error_handlers), (void (*)(void *))ZVAL_PTR_DTOR, 1);
		zend_stack_clean(&EG(user_exception_handlers), (void (*)(void *))ZVAL_PTR_DTOR, 1);
	} zend_end_try();


	zend_try {
		/* Cleanup static data for functions and arrays.
		 * We need a separate cleanup stage because of the following problem:
		 * Suppose we destroy class X, which destroys the class's function table,
		 * and in the function table we have function foo() that has static $bar.
		 * Now if an object of class X is assigned to $bar, its destructor will be
		 * called and will fail since X's function table is in mid-destruction.
		 * So we want first of all to clean up all data and then move to tables destruction.
		 * Note that only run-time accessed data need to be cleaned up, pre-defined data can
		 * not contain objects and thus are not probelmatic */
		if (EG(full_tables_cleanup)) {
			ZEND_HASH_FOREACH_PTR(EG(function_table), func) {
				if (func->type == ZEND_USER_FUNCTION) {
					zend_cleanup_op_array_data((zend_op_array *) func);
				}
			} ZEND_HASH_FOREACH_END();
			ZEND_HASH_REVERSE_FOREACH_PTR(EG(class_table), ce) {
				if (ce->type == ZEND_USER_CLASS) {
					zend_cleanup_user_class_data(ce);
				} else {
					zend_cleanup_internal_class_data(ce);
				}
			} ZEND_HASH_FOREACH_END();
		} else {
			ZEND_HASH_REVERSE_FOREACH_PTR(EG(function_table), func) {
				if (func->type != ZEND_USER_FUNCTION) {
					break;
				}
				zend_cleanup_op_array_data((zend_op_array *) func);
			} ZEND_HASH_FOREACH_END();
			ZEND_HASH_REVERSE_FOREACH_PTR(EG(class_table), ce) {
				if (ce->type != ZEND_USER_CLASS) {
					break;
				}
				zend_cleanup_user_class_data(ce);
			} ZEND_HASH_FOREACH_END();
			zend_cleanup_internal_classes();
		}
	} zend_end_try();


	zend_try {
		zend_llist_destroy(&CG(open_files));
	} zend_end_try();

	zend_try {
		clean_non_persistent_constants();
    } zend_end_try();

	zend_try {
		zend_close_rsrc_list(&EG(regular_list));
	} zend_end_try();

#if ZEND_DEBUG
	if (GC_G(gc_enabled) && !CG(unclean_shutdown)) {
		gc_collect_cycles();
	}
#endif

	zend_try {
		zend_objects_store_free_object_storage(&EG(objects_store));

        //这个去掉  swoole 在用
		//zend_vm_stack_destroy();

		/* Destroy all op arrays */
		if (EG(full_tables_cleanup)) {
			zend_hash_reverse_apply(EG(function_table), clean_non_persistent_function_full);
			zend_hash_reverse_apply(EG(class_table), clean_non_persistent_class_full);
		} else {
			zend_hash_reverse_apply(EG(function_table), clean_non_persistent_function);
			zend_hash_reverse_apply(EG(class_table), clean_non_persistent_class);
		}

		while (EG(symtable_cache_ptr)>=EG(symtable_cache)) {
			zend_hash_destroy(*EG(symtable_cache_ptr));
			FREE_HASHTABLE(*EG(symtable_cache_ptr));
			EG(symtable_cache_ptr)--;
		}
	} zend_end_try();

	zend_try {
#if 0&&ZEND_DEBUG
	signal(SIGSEGV, original_sigsegv_handler);
#endif

		zend_hash_destroy(&EG(included_files));

		zend_stack_destroy(&EG(user_error_handlers_error_reporting));
		zend_stack_destroy(&EG(user_error_handlers));
		zend_stack_destroy(&EG(user_exception_handlers));
		zend_objects_store_destroy(&EG(objects_store));
		if (EG(in_autoload)) {
			zend_hash_destroy(EG(in_autoload));
			FREE_HASHTABLE(EG(in_autoload));
		}
	} zend_end_try();

	zend_shutdown_fpu();

#if ZEND_DEBUG
	if (EG(ht_iterators_used) && !CG(unclean_shutdown)) {
		zend_error(E_WARNING, "Leaked %" PRIu32 " hashtable iterators", EG(ht_iterators_used));
	}
#endif

	EG(ht_iterators_used) = 0;
	if (EG(ht_iterators) != EG(ht_iterators_slots)) {
		efree(EG(ht_iterators));
	}

	EG(active) = 0;
}

static void heredoc_label_dtor(zend_heredoc_label *heredoc_label) {
    efree(heredoc_label->label);
}

#define SCNG    LANG_SCNG
void shutdown_scanner(void)
{
	CG(parse_error) = 0;
	RESET_DOC_COMMENT();
	zend_stack_destroy(&SCNG(state_stack));
	zend_ptr_stack_clean(&SCNG(heredoc_label_stack), (void (*)(void *)) &heredoc_label_dtor, 1);
	zend_ptr_stack_destroy(&SCNG(heredoc_label_stack));
	SCNG(on_event) = NULL;
}
#undef SCNG

void shutdown_compiler(void) /* {{{ */
{
	zend_stack_destroy(&CG(loop_var_stack));
	zend_stack_destroy(&CG(delayed_oplines_stack));
	zend_hash_destroy(&CG(filenames_table));
	zend_hash_destroy(&CG(const_filenames));
	zend_arena_destroy(CG(arena));
}


//参考  zend_deactivate()
ZEND_API void swoole_zend_deactivate(void) /* {{{ */
{
	/* we're no longer executing anything */
	EG(current_execute_data) = NULL;

	zend_try {
		shutdown_scanner();
	} zend_end_try();

	/* shutdown_executor() takes care of its own bailout handling */
	//shutdown_executor();
	swoole_shutdown_executor();


	zend_try {
		zend_ini_deactivate();
	} zend_end_try();

	zend_try {
		shutdown_compiler();
	} zend_end_try();

	zend_destroy_rsrc_list(&EG(regular_list));

}
/* }}} */




//请求开始前的初始化操作
//参考 php_request_startup
static int swoole_php_request_startup() {

    if (output_buffer != NULL) {
        zend_string_free(output_buffer);
    }

    //sapi 的output输出处理赋值
    //sapi_module.ub_write = sapi_cli_ub_write;
    //sapi_module.flush = sapi_cli_flush;
    //sapi_module.log_message = sapi_cli_log_message;

    //SG(request_info) = NULL;
    SG(sapi_headers).http_response_code = 200; 

    if (FAILURE == php_request_startup()) {
        return FAILURE;
    }    

    PG(during_request_startup) = 0; 

    return SUCCESS;
}

//请求结束后的清理操作
//参考 php_request_shutdown
static int swoole_php_request_shutdown() {
	zend_bool report_memleaks;

	report_memleaks = PG(report_memleaks);

	/* EG(current_execute_data) points into nirvana and therefore cannot be safely accessed
	 * inside zend_executor callback functions.
	 */
	EG(current_execute_data) = NULL;

	php_deactivate_ticks();

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
		zend_bool send_buffer = SG(request_info).headers_only ? 0 : 1;

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
    //修改 部分zend_deactivate()的功能
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
        //去掉这个 swoole有用到
		//shutdown_memory_manager(CG(unclean_shutdown) || !report_memleaks, 0);
	} zend_end_try();

	/* 16. Reset max_execution_time */
	zend_try {
		zend_unset_timeout();
	} zend_end_try();

    return SUCCESS;
}

