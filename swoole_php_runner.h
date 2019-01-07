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
#include "php_variables.h"
#include "zend_globals_macros.h"
#include "Zend/zend_language_scanner.h"

extern sapi_module_struct sapi_module;

extern zend_class_entry swoole_php_runner_ce;
extern zend_class_entry *swoole_php_runner_class_entry_ptr;

static int swoole_php_request_startup();
static int swoole_php_request_shutdown();
static zval * class_call_user_method(zval *retval, zend_class_entry *obj_ce, 
        zval *obj, zval function_name,  uint32_t params_count, zval params[]); 

//全局输出变量  cclehui_test
zend_string *output_buffer;


typedef struct _server_receive_context {
    zval *zserv; // object of swoole_server
    zval *zfd;
    zval *zfrom_id;
    zend_string *zdata;
} server_receive_context;


/*****************************************************/



#endif /* SWOOLE_FPM_H_ */
