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

#ifndef SWOOLE_FPM_H_
#define SWOOLE_FPM_H_

#include "ext/standard/file.h"
#include "zend_extensions.h"
#include "Zend/zend_list.h"

extern zend_class_entry swoole_fpm_server_ce;
extern zend_class_entry *swoole_fpm_server_class_entry_ptr;

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

    php_printf("ssssssssssss, 222222222222222\n");

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


    php_printf("ssssssssssss, 33333333333\n");

	zend_try {
		//zend_llist_destroy(&CG(open_files));
	} zend_end_try();

	zend_try {
		clean_non_persistent_constants();
    } zend_end_try();

    php_printf("ssssssssssss, 444444444444444444\n");
	zend_try {
		zend_close_rsrc_list(&EG(regular_list));
	} zend_end_try();

#if ZEND_DEBUG
	if (GC_G(gc_enabled) && !CG(unclean_shutdown)) {
		gc_collect_cycles();
	}
#endif
    php_printf("ssssssssssss, 5555555555555555\n");

	zend_try {
		//zend_objects_store_free_object_storage(&EG(objects_store));

		zend_vm_stack_destroy();

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

    php_printf("ssssssssssss, 66666666666666\n");

    //return;

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

#endif /* SWOOLE_FPM_H_ */
